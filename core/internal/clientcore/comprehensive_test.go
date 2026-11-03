package clientcore

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// A production Serve request must not silently replace an accepted point/round
// budget with a shorter transport deadline. This is deliberately not mocked:
// it crosses the historical 35s ceiling over a real loopback HTTP request.
func TestIPCConfiguredBudgetPast35Seconds(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(36 * time.Second):
			w.WriteHeader(http.StatusNoContent)
		case <-r.Context().Done():
		}
	}))
	defer target.Close()
	h := newHost(t)
	text := settingsText(t, fixture(t, map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}}), map[string]any{"probe_timeout": "40s", "probe_round_timeout": "45s"})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	defer inW.Close()
	defer outR.Close()
	done := make(chan error, 1)
	go func() { e := h.Serve(context.Background(), inR, outW); outW.Close(); done <- e }()
	b, _ := json.Marshal(map[string]any{"id": "configured-budget", "method": "probe.node", "params": map[string]any{"name": "direct", "url": target.URL}})
	fmt.Fprintln(inW, string(b))
	s := bufio.NewScanner(outR)
	if !s.Scan() {
		t.Fatal("no response")
	}
	var r struct {
		OK     bool `json:"ok"`
		Result struct {
			ProbeMS *float64 `json:"probe_ms"`
			Error   string   `json:"error"`
		} `json:"result"`
	}
	if json.Unmarshal(s.Bytes(), &r) != nil {
		t.Fatal("invalid frame")
	}
	inW.Close()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if !r.OK || r.Result.ProbeMS == nil || r.Result.Error != "" {
		t.Fatal("accepted 40s probe/45s round was truncated before 36s HTTP response")
	}
}

// A successful projection must remain valid strict JSON, with no float64
// round-trip. Arbitrary bytes exercise depth/tags/alias/duplicate boundaries.
func FuzzYAMLProjection(f *testing.F) {
	for _, s := range []string{"a: 9007199254740993", "a: &x [*x]", "a: 1\na: 2", "a: 1e9999", "a: [null,true,\"x\"]", "a: .NaN", "!!map {a: 1}"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64<<10 {
			t.Skip()
		}
		projected, e := yamlJSON(b)
		if e == nil && uniqueJSON(projected) != nil {
			t.Fatal("successful YAML projection is not bounded strict JSON")
		}
	})
}

func TestComprehensiveRepeatedTransactionsKeepOldStreamAndRelease(t *testing.T) {
	baselineG := runtime.NumGoroutine()
	baselineFD := diagnosticFDs()
	echo, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	h := newHost(t)
	text := fixture(t, map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	c, e := net.Dial("tcp4", portAddress(h.doc.client.HTTPPort))
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(20 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echo.Addr(), echo.Addr())
	r := bufio.NewReader(c)
	line, e := r.ReadString('\n')
	if e != nil || !strings.Contains(line, "200") {
		t.Fatal("CONNECT")
	}
	r.ReadString('\n')
	statusCtx, statusCancel := context.WithCancel(context.Background())
	statusDone := make(chan struct{})
	go func() {
		defer close(statusDone)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-statusCtx.Done():
				return
			case <-tick.C:
				h.Status()
			}
		}
	}()
	for i := 0; i < 60; i++ {
		f := []DocumentFormat{FormatJSON, FormatYAML, FormatYML}[i%3]
		draft := text
		if f != FormatJSON {
			draft = yamlFixture(h.doc.client.HTTPPort, h.doc.client.SOCKSPort) + fmt.Sprintf("# retained comment revision %d\n", i)
		}
		if _, e := h.Apply(draft, f); e != nil {
			t.Fatal("transaction", i, e)
		}
		if i%5 == 0 {
			if _, e := h.Apply("{", f); e == nil {
				t.Fatal("invalid candidate accepted")
			}
			if _, e := h.Reload(); e != nil {
				t.Fatal("reload", e)
			}
		}
		payload := fmt.Sprintf("retained-generation-%d", i)
		if _, e := io.WriteString(c, payload); e != nil {
			t.Fatal("old flow write", e)
		}
		b := make([]byte, len(payload))
		if _, e := io.ReadFull(r, b); e != nil || string(b) != payload {
			t.Fatal("old flow changed across format reload")
		}
		disk, e := os.ReadFile(h.path)
		if e != nil || string(disk) != draft {
			t.Fatal("accepted original changed")
		}
		left, _ := filepath.Glob(filepath.Join(h.workspace, ".kat-*"))
		if len(left) != 0 {
			t.Fatal("successful transaction leaked recovery material")
		}
	}
	statusCancel()
	<-statusDone
	c.Close()
	for i := 0; i < 12; i++ {
		if _, e := h.Stop(); e != nil {
			t.Fatal("clean stop", e)
		}
		if _, e := h.Start(); e != nil {
			t.Fatal("repeat start", e)
		}
	}
	if e := h.Close(); e != nil {
		t.Fatal(e)
	}
	echo.Close()
	<-echoDone
	deadline := time.Now().Add(3 * time.Second)
	var afterG, afterFD int
	for {
		runtime.GC()
		afterG = runtime.NumGoroutine()
		afterFD = diagnosticFDs()
		if afterG <= baselineG+8 && (baselineFD < 0 || afterFD <= baselineFD+4) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("resources did not settle: goroutines %d->%d fd %d->%d", baselineG, afterG, baselineFD, afterFD)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("60 conversions + 12 failed candidates/reloads + 12 restart cycles; old CONNECT stream retained; goroutines %d->%d fd %d->%d", baselineG, afterG, baselineFD, afterFD)
}
func diagnosticFDs() int {
	e, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(e)
}

func TestCanceledRequestCannotPublishDocument(t *testing.T) {
	h := newHost(t)
	before := h.doc.text
	draft := fixture(t, map[string]any{"dns": map[string]any{"server": "system"}})
	params, _ := json.Marshal(map[string]any{"text": draft})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := h.Request(ctx, "document.apply", params)
	disk, err := os.ReadFile(h.path)
	if e == nil || err != nil || string(disk) != before || h.doc.text != before {
		t.Fatal("already canceled request published a new accepted document")
	}
}
