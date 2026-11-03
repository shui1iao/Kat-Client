package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type process struct {
	cmd   *exec.Cmd
	in    io.WriteCloser
	lines chan []byte
	err   bytes.Buffer
	done  chan error
	once  sync.Once
}

func runCore(t *testing.T, exe string) *process {
	t.Helper()
	p := &process{cmd: exec.Command(exe, "--workspace", t.TempDir()), lines: make(chan []byte, 32), done: make(chan error, 1)}
	var e error
	p.in, e = p.cmd.StdinPipe()
	if e != nil {
		t.Fatal(e)
	}
	out, e := p.cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	p.cmd.Stderr = &p.err
	if e = p.cmd.Start(); e != nil {
		t.Fatal(e)
	}
	go func() {
		s := bufio.NewScanner(out)
		s.Buffer(make([]byte, 64<<10), (2<<20)+2)
		for s.Scan() {
			p.lines <- append([]byte(nil), s.Bytes()...)
		}
		close(p.lines)
	}()
	go func() { p.done <- p.cmd.Wait() }()
	t.Cleanup(func() {
		p.in.Close()
		select {
		case <-p.done:
		case <-time.After(8 * time.Second):
			t.Error("sidecar did not exit after EOF; no broad kill attempted")
		}
	})
	return p
}
func (p *process) send(t *testing.T, id, method string, params any) {
	t.Helper()
	b, e := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.in.Write(append(b, '\n')); e != nil {
		t.Fatal(e)
	}
}
func (p *process) read(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	select {
	case b, ok := <-p.lines:
		if !ok {
			t.Fatal("protocol closed")
		}
		var r map[string]json.RawMessage
		if json.Unmarshal(b, &r) != nil {
			t.Fatal("stdout contained non-protocol output")
		}
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("IPC timeout")
	}
	return nil
}
func (p *process) call(t *testing.T, id, method string, params any) map[string]json.RawMessage {
	t.Helper()
	p.send(t, id, method, params)
	r := p.read(t)
	var got string
	json.Unmarshal(r["id"], &got)
	if got != id {
		t.Fatal("id not exact")
	}
	return r
}
func ok(t *testing.T, r map[string]json.RawMessage) json.RawMessage {
	t.Helper()
	if string(r["ok"]) != "true" {
		t.Fatalf("IPC method failed: %s", r["error"])
	}
	return r["result"]
}
func unusedPort(t *testing.T) int {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func TestRealProcessIPCFramesMethodsEOF(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux subprocess evidence")
	}
	dir := t.TempDir()
	exe := filepath.Join(dir, "kat-client-core")
	build := exec.Command("go", "build", "-p", "2", "-o", exe, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOMAXPROCS=2")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, b)
	}
	t.Run("methods-and-errors", func(t *testing.T) {
		p := runCore(t, exe)
		ok(t, p.call(t, "精确-id-🟦", "hello", map[string]any{}))
		doc := ok(t, p.call(t, "doc", "document.get", map[string]any{}))
		if !bytes.Contains(doc, []byte(`"running":false`)) {
			t.Fatal("default not stopped")
		}
		bad := p.call(t, "bad", "document.validate", map[string]any{"text": "{"})
		if string(bad["ok"]) != "false" {
			t.Fatal("invalid document accepted")
		}
		bad = p.call(t, "unknown", "does.not.exist", map[string]any{})
		if string(bad["ok"]) != "false" {
			t.Fatal("unknown method")
		}
		hp, sp := portPair(t)
		text := fmt.Sprintf(`{"schema_version":1,"client":{"mode":"rule","global_group":"","probe_url":"http://127.0.0.1:1/","http_port":%d,"socks_port":%d},"kernel":{"dns":{"server":"system"},"security":{"allow_loopback":true}}}`, hp, sp)
		ok(t, p.call(t, "validate", "document.validate", map[string]any{"text": text}))
		ok(t, p.call(t, "apply", "document.apply", map[string]any{"text": text}))
		st := ok(t, p.call(t, "start", "core.start", map[string]any{}))
		if !bytes.Contains(st, []byte(`"ready":true`)) {
			t.Fatal("protocol not ready")
		}
		ok(t, p.call(t, "reload", "core.reload", map[string]any{}))
		ok(t, p.call(t, "status", "status", map[string]any{}))
		ok(t, p.call(t, "import", "import.parse", map[string]any{"text": "socks5://synthetic:private-test-only@127.0.0.1:12345#test\nunknown://x"}))
		ok(t, p.call(t, "get-egress", "network.egress.get", map[string]any{}))
		bad = p.call(t, "set-egress", "network.egress.set", map[string]any{"enabled": true, "ipv4_if_index": 1, "ipv6_if_index": nil, "bootstrap_dns": []string{"192.0.2.53"}})
		if string(bad["ok"]) != "false" {
			t.Fatal("Linux egress mutation")
		}
		ok(t, p.call(t, "stop", "core.stop", map[string]any{}))
		// Multiple complete frames in one write; responses may arrive out of order.
		fmt.Fprint(p.in, "{\"id\":\"one\",\"method\":\"hello\"}\n{\"id\":\"two\",\"method\":\"status\"}\n")
		ids := map[string]bool{}
		for range 2 {
			r := p.read(t)
			var id string
			json.Unmarshal(r["id"], &id)
			ids[id] = true
		}
		if !ids["one"] || !ids["two"] {
			t.Fatal("frame boundaries")
		}
		if _, e := p.in.Write([]byte("{broken\n")); e != nil {
			t.Fatal(e)
		}
		if string(p.read(t)["ok"]) != "false" {
			t.Fatal("bad frame no error")
		}
	})
	t.Run("slow-probe-and-eof", func(t *testing.T) {
		began := make(chan struct{}, 1)
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { began <- struct{}{}; <-r.Context().Done() }))
		defer target.Close()
		p := runCore(t, exe)
		hp, sp := portPair(t)
		text := fmt.Sprintf(`{"schema_version":1,"client":{"mode":"rule","probe_url":%q,"http_port":%d,"socks_port":%d},"kernel":{"dns":{"server":"system"},"security":{"allow_loopback":true}}}`, target.URL, hp, sp)
		ok(t, p.call(t, "save", "document.apply", map[string]any{"text": text}))
		ok(t, p.call(t, "start", "core.start", map[string]any{}))
		p.send(t, "slow", "probe.node", map[string]any{"name": "direct"})
		select {
		case <-began:
		case <-time.After(time.Second):
			t.Fatal("probe not real HTTP")
		}
		begin := time.Now()
		ok(t, p.call(t, "status", "status", map[string]any{}))
		if time.Since(begin) > 500*time.Millisecond {
			t.Fatal("status blocked by probe")
		}
		p.in.Close()
		r := p.read(t)
		if string(r["id"]) != `"slow"` {
			t.Fatal("EOF lost probe correlation")
		}
		select {
		case e := <-p.done:
			if e != nil {
				t.Fatal("EOF abnormal exit")
			}
			p.done <- nil
		case <-time.After(3 * time.Second):
			t.Fatal("EOF leaked worker")
		}
		if p.err.Len() != 0 {
			t.Fatal("unexpected diagnostic output")
		}
	})
	t.Run("frame-limit", func(t *testing.T) {
		p := runCore(t, exe)
		frame := `{"id":"limit","method":"hello","padding":"` + strings.Repeat("x", 2<<20) + `"}` + "\n"
		_, _ = io.WriteString(p.in, frame)
		r := p.read(t)
		if string(r["ok"]) != "false" || !bytes.Contains(r["error"], []byte("frame_too_large")) {
			t.Fatal("oversized frame accepted")
		}
	})
}

func portPair(t *testing.T) (int, int) {
	a, b := unusedPort(t), unusedPort(t)
	for a == b {
		b = unusedPort(t)
	}
	return a, b
}
