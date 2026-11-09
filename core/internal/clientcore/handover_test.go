package clientcore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/elevated"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// This process is an ordinary real Host, not a fake UAC/token fixture. It tests
// the production persistence/Serve/unique-writer primitive without any OS route.
func TestC50HandoverChild(t *testing.T) {
	if os.Getenv("KAT_C50_HANDOVER_CHILD") != "1" {
		return
	}
	h, e := Open(os.Getenv("KAT_C50_HANDOVER_WORKSPACE"))
	if e != nil {
		os.Exit(11)
	}
	e = h.Serve(context.Background(), os.Stdin, os.Stdout)
	ce := h.Close()
	if e != nil || ce != nil {
		os.Exit(12)
	}
	os.Exit(0)
}
func TestC50HandoverActualProcessSingleWriter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	dir := t.TempDir()
	h, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	port := func() int {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	hp, sp := port(), port()
	for hp == sp {
		sp = port()
	}
	text, _ := json.Marshal(map[string]any{"schema_version": 1, "client": Client{Mode: "rule", HTTPPort: hp, SOCKSPort: sp, ProbeURL: "http://127.0.0.1:1/probe"}, "kernel": map[string]any{"groups": []any{map[string]any{"name": "pick", "type": "select", "members": []string{"direct", "reject"}, "selected": "direct"}}, "routing": map[string]any{"final": "pick"}}})
	if _, de := h.Apply(string(text) + "\n"); de != nil {
		h.Close()
		t.Fatal(de)
	}
	source := h.path
	h.history.TotalUp = 1800
	h.history.TotalDown = 4200
	h.history.dirty = true
	if e = h.Close(); e != nil {
		t.Fatal(e)
	}
	selections := []byte(`{"version":1,"groups":{"pick":{"selected":"reject","config_default":"direct"}}}`)
	if e = os.WriteFile(filepath.Join(dir, "runtime.select.json"), selections, 0600); e != nil {
		t.Fatal(e)
	}
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestC50HandoverChild$")
	cmd.Env = append(os.Environ(), "KAT_C50_HANDOVER_CHILD=1", "KAT_C50_HANDOVER_WORKSPACE="+dir)
	input, e := cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	output, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		input.Close()
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	reader := bufio.NewReader(output)
	call := func(method string) map[string]json.RawMessage {
		t.Helper()
		b, _ := json.Marshal(map[string]any{"id": "h1", "method": method, "params": map[string]any{}})
		if _, e = input.Write(append(b, '\n')); e != nil {
			t.Fatal(e)
		}
		line, e := reader.ReadBytes('\n')
		if e != nil {
			t.Fatal(e)
		}
		var r map[string]json.RawMessage
		if e = json.Unmarshal(line, &r); e != nil {
			t.Fatal(e)
		}
		return r
	}
	for _, method := range []string{"hello", "core.start", "status"} {
		if r := call(method); string(r["ok"]) != "true" {
			t.Fatalf("%s failed: %s", method, r["error"])
		}
	}
	before, e := os.ReadFile(source)
	if e != nil {
		t.Fatal(e)
	}
	// Waiting/cancel-before-commit has sent no mutation and has no second writer.
	if second, e := Open(dir); e == nil {
		second.Close()
		t.Fatal("waiting old writer lock stolen")
	}
	if r := call("status"); string(r["ok"]) != "true" {
		t.Fatal("old core changed before handover")
	}
	reply := call("host.prepare-update")
	if string(reply["ok"]) != "true" {
		t.Fatalf("prepare failed: %s", reply["error"])
	}
	var ack struct {
		Prepared   bool                `json:"prepared"`
		Checkpoint elevated.Checkpoint `json:"checkpoint"`
	}
	if json.Unmarshal(reply["result"], &ack) != nil || !ack.Prepared || !ack.Checkpoint.Valid() {
		t.Fatal("no real persistence ACK")
	}
	if second, e := OpenHandover(dir, ack.Checkpoint); e == nil {
		second.Close()
		t.Fatal("ACK is not exact exit: second writer admitted")
	}
	input.Close()
	if e = cmd.Wait(); e != nil {
		t.Fatalf("old exact process did not exit zero: %v", e)
	}
	after, _ := os.ReadFile(source)
	if !bytes.Equal(before, after) {
		t.Fatal("accepted source mutated across old drain")
	}
	bad := ack.Checkpoint
	bad.HistorySHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if second, e := OpenHandover(dir, bad); e == nil {
		second.Close()
		t.Fatal("mismatched checkpoint admitted")
	}
	next, e := OpenHandover(dir, ack.Checkpoint)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	if next.history.TotalUp != 1800 || next.history.TotalDown != 4200 {
		t.Fatal("cumulative history reset or duplicated")
	}
	if second, e := OpenHandover(dir, ack.Checkpoint); e == nil {
		second.Close()
		t.Fatal("two new writers admitted")
	}
	if _, de := next.Start(); de != nil {
		t.Fatal(de)
	}
	next.mu.Lock()
	next.sampleLocked(time.Now())
	next.mu.Unlock()
	if next.history.TotalUp != 1800 || next.history.TotalDown != 4200 {
		t.Fatal("loaded counters counted twice")
	}
	if _, de := next.Stop(); de != nil {
		t.Fatal(de)
	}
	b, e := os.ReadFile(filepath.Join(dir, "runtime.select.json"))
	if e != nil {
		t.Fatal(e)
	}
	var choice struct {
		Groups map[string]struct {
			Selected string `json:"selected"`
		} `json:"groups"`
	}
	if json.Unmarshal(b, &choice) != nil || choice.Groups["pick"].Selected != "reject" {
		t.Fatal("runtime choice reset")
	}
	t.Log("actual old process ACK+exit0; lock held through ACK; one new writer; source, persisted choice and cumulative history retained; zero routes/token mocks")
}
