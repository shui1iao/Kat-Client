package clientcore

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/outbound"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLogsRingBoundaries(t *testing.T) {
	var r logRing
	if s := r.read(0, 200); len(s.Entries) != 0 || s.NextSeq != 0 || s.Dropped != 0 {
		t.Fatal("empty ring invented history")
	}
	for range logCapacity + 17 {
		r.record(kernel.ClientLogEvent{Time: time.Now(), Level: "info", Event: "reload_ok"})
	}
	s := r.read(0, 500)
	if len(s.Entries) != 500 || s.Entries[0].Seq != 18 || s.NextSeq != 517 || s.Dropped != 17 {
		t.Fatal("overflow/cursor mismatch")
	}
	after := s.NextSeq
	count := len(s.Entries)
	for {
		s = r.read(after, 500)
		if len(s.Entries) == 0 {
			break
		}
		if s.Entries[0].Seq != after+1 {
			t.Fatal("cursor duplicate/gap")
		}
		count += len(s.Entries)
		after = s.NextSeq
	}
	if count != logCapacity || after != logCapacity+17 || s.NextSeq != after {
		t.Fatal("pagination failed")
	}
	if s = r.read(maxLogSeq, 1); len(s.Entries) != 1 || s.Entries[0].Seq != 18 || s.NextSeq != 18 || s.Dropped != 17 {
		t.Fatal("future cursor changed")
	}
	for _, e := range []kernel.ClientLogEvent{{Level: "trace", Event: "reload_ok"}, {Level: "info", Event: strings.Repeat("x", 65)}, {Level: "error", Event: "failure", Code: strings.Repeat("x", 65)}} {
		r.record(e)
	}
	if r.read(0, 1).Dropped != 17 {
		t.Fatal("invalid record entered ring")
	}
	// Mutating a reply cannot alter the retained ring.
	s = r.read(0, 1)
	s.Entries[0].Event = "changed"
	if r.read(0, 1).Entries[0].Event != "reload_ok" {
		t.Fatal("reply aliases ring")
	}
}

func TestLogsParamsAndConcurrency(t *testing.T) {
	h := newHost(t)
	for _, raw := range []string{`{"after":-1}`, `{"after":1.5}`, `{"after":null}`, `{"after":"1"}`, `{"after":9007199254740992}`, `{"limit":0}`, `{"limit":501}`, `{"limit":null}`, `{"limit":1.5}`, `{"limit":"1"}`, `{"unknown":true}`, `{"limit":1,"limit":2}`, `[]`, `null`} {
		if _, e := h.Request(context.Background(), "logs.get", json.RawMessage(raw)); e == nil || e.Code != "invalid_params" {
			t.Fatal("invalid log params accepted")
		}
	}
	if _, e := h.Request(context.Background(), "logs.other", nil); e == nil || e.Code != "unknown_method" {
		t.Fatal("unknown method accepted")
	}
	for _, raw := range []string{`{}`, `{"after":0,"limit":1}`, `{"limit":500}`, `{"after":9007199254740991}`} {
		if _, e := h.Request(context.Background(), "logs.get", json.RawMessage(raw)); e != nil {
			t.Fatal(e)
		}
	}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 1500 {
				h.logs.record(kernel.ClientLogEvent{Time: time.Now(), Level: "warn", Event: "failure", Code: "connect_failed"})
				r, e := h.Request(context.Background(), "logs.get", nil)
				if e != nil || len(r.(LogsReply).Entries) > 200 {
					t.Error("concurrent read/default limit failed")
				}
			}
		}()
	}
	wg.Wait()
	if s := h.logs.read(0, 500); s.Dropped != 1000 || len(s.Entries) != 500 {
		t.Fatal("concurrent ring exceeded bound")
	}
}

func TestLogsRealRuntimePrivacyAndRaw(t *testing.T) {
	h := newHost(t)
	// Test-only secrets in the saved config, never user credentials.
	marker := "sensitive-fixture-only"
	logPath := filepath.Join(h.workspace, "fixture-secret-log")
	base := map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}, "log": map[string]any{"level": "debug", "file": logPath, "format": "json", "access": true}, "outbounds": []any{map[string]any{"name": marker, "type": "socks5", "server": "127.0.0.1", "port": 1, "username": "fixture-user", "password": marker}}, "providers": []any{map[string]any{"name": "fixture-provider", "type": "http", "url": "http://fixture-user:" + marker + "@127.0.0.1:1/private?token=" + marker, "headers": map[string]string{"Authorization": "Bearer " + marker}, "path": filepath.Join(h.workspace, "fixture-provider-cache"), "interval": "1h"}}}
	text := fixture(t, base)
	if _, e := applyLegacyFixture(h, text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	isolated := newHost(t)
	if r, e := isolated.Request(context.Background(), "logs.get", nil); e != nil || len(r.(LogsReply).Entries) != 0 {
		t.Fatal("independent workspace inherited logs")
	}
	if _, e := h.Reload(); e != nil {
		t.Fatal(e)
	}
	// Generate a genuine warn reload_failed with a private path in the failed
	// underlying error, and check that its free-form reason never reaches IPC.
	busy, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer busy.Close()
	var root map[string]any
	json.Unmarshal([]byte(text), &root)
	root["client"].(map[string]any)["socks_port"] = busy.Addr().(*net.TCPAddr).Port
	bad, _ := json.Marshal(root)
	if _, e := applyLegacyFixture(h, string(bad)); e == nil {
		t.Fatal("actual bind failure missing")
	}
	if got, e := os.ReadFile(h.path); e != nil || string(got) != text {
		t.Fatal("raw log/config fields not preserved")
	}
	if _, e := os.Stat(logPath); !os.IsNotExist(e) {
		t.Fatal("raw log.file was opened")
	}
	result, e2 := h.Request(context.Background(), "logs.get", json.RawMessage(`{"limit":500}`))
	if e2 != nil {
		t.Fatal(e2)
	}
	reply := result.(LogsReply)
	seen := map[string]bool{}
	for _, e := range reply.Entries {
		seen[e.Event] = true
		b, _ := json.Marshal(e)
		if len(b) > 512 {
			t.Fatal("unbounded log entry")
		}
		var m map[string]any
		json.Unmarshal(b, &m)
		for k := range m {
			if k != "seq" && k != "time" && k != "level" && k != "event" && k != "code" && k != "meta" {
				t.Fatal("extra unsafe entry field")
			}
		}
	}
	if !seen["reload_ok"] || !seen["reload_failed"] || !seen["config_generation_released"] {
		t.Fatal("actual runtime logs missing")
	}
	b, _ := json.Marshal(reply)
	for _, secret := range []string{marker, "fixture-user", "127.0.0.1", "Authorization", "Bearer", "/private", "token=", h.workspace, "fixture-provider"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("sensitive fixture escaped into logs")
		}
	}
	if _, e := h.Stop(); e != nil {
		t.Fatal(e)
	}
	// Actual debug retirement may add an event during stop, but reads and
	// idempotent stopped operations must not fabricate lifecycle/history.
	stopped := h.logs.read(0, 500)
	h.Stop()
	if s := h.logs.read(0, 500); fmt.Sprint(s) != fmt.Sprint(stopped) {
		t.Fatal("stopped action invented a log")
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Reload(); e != nil {
		t.Fatal(e)
	}
	next := h.logs.read(stopped.NextSeq, 500)
	if len(next.Entries) == 0 || next.Entries[0].Seq <= stopped.NextSeq {
		t.Fatal("core restart reset log sequence")
	}
}

func TestLogsDefaultLevelProjection(t *testing.T) {
	for _, level := range []string{"", "debug", "info", "warn", "error"} {
		k := map[string]any{"dns": map[string]any{"server": "system"}}
		if level != "" {
			k["log"] = map[string]any{"level": level}
		}
		d, e := parseDocument(fixture(t, k), t.TempDir())
		if e != nil {
			t.Fatal(e)
		}
		want := level
		if want == "" {
			want = "info"
		}
		if d.config.Log.Level != want || d.config.Log.Access || d.config.Log.File != "" {
			t.Fatal("configured/default level not projected safely")
		}
	}
}

func TestRuntimeConfigBufferLimits(t *testing.T) {
	var h Host
	for _, tc := range []struct {
		name      string
		inSize    int
		inPool    int
		wantSize  int
		wantPool  int
		wantBytes int
	}{
		{"default_16k_128_upgraded_to_64k_64", 16384, 128, 65536, 64, 4 << 20},
		{"default_size_custom_pool_preserves_32k", 16384, 32, 32768, 32, 1 << 20},
		{"custom_size_default_pool_preserved", 8192, 128, 8192, 128, 1 << 20},
		{"custom_size_and_pool_preserved", 4096, 16, 4096, 16, 64 << 10},
		{"explicit_32k_128_preserved", 32768, 128, 32768, 128, 4 << 20},
		{"explicit_64k_128_preserved", 65536, 128, 65536, 128, 8 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c kernel.Config
			c.Limits.BufferSize = tc.inSize
			c.Limits.PoolBuffers = tc.inPool
			got := h.runtimeConfig(c)
			if got.Limits.BufferSize != tc.wantSize || got.Limits.PoolBuffers != tc.wantPool {
				t.Fatalf("runtimeConfig(%d, %d) = (%d, %d), want (%d, %d)",
					tc.inSize, tc.inPool, got.Limits.BufferSize, got.Limits.PoolBuffers, tc.wantSize, tc.wantPool)
			}
			if gotBytes := got.Limits.BufferSize * got.Limits.PoolBuffers; gotBytes != tc.wantBytes {
				t.Fatalf("retained budget = %d, want %d", gotBytes, tc.wantBytes)
			}
		})
	}
}

func TestC50LogsTransportLabelsAndBufferedReader(t *testing.T) {
	for _, tc := range []struct {
		name, protocol string
		kind           TransportKind
		legacy         bool
	}{
		{"legacy_stdio", "stdio", TransportStdio, true},
		{"explicit_zero_stdio", "stdio", TransportKind(0), false},
		{"named_pipe", "named_pipe", TransportNamedPipe, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Host{}
			h.logs.record(kernel.ClientLogEvent{Time: time.Now(), Level: "info", Event: "reload_ok"})
			inR, inW := io.Pipe()
			reader := bufio.NewReader(inR)
			defer inR.Close()
			defer inW.Close()
			prefilled := make(chan error, 1)
			go func() {
				_, err := io.WriteString(inW, "activated\n{\"id\":\"h41\",\"method\":\"logs.get\",\"params\":{\"after\":0,\"limit\":500}}\n")
				prefilled <- err
			}()
			if line, err := reader.ReadString('\n'); err != nil || line != "activated\n" {
				t.Fatalf("activation prefix: %q %v", line, err)
			}
			if err := <-prefilled; err != nil {
				t.Fatal(err)
			}
			if reader.Buffered() == 0 {
				t.Fatal("fixture did not retain post-activation buffered bytes")
			}
			out := &c50GateWriter{entered: make(chan struct{}), release: make(chan struct{}), frames: make(chan []byte, 1)}
			var once sync.Once
			unblock := func() { once.Do(func() { close(out.release) }) }
			defer unblock()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if tc.legacy {
					done <- h.Serve(ctx, reader, out)
				} else {
					done <- h.ServeTransport(ctx, reader, out, tc.kind)
				}
			}()
			select {
			case <-out.entered:
			case <-time.After(time.Second):
				t.Fatal("buffered request never reached output")
			}
			// A short controlled output wait exercises the existing >=250ms phase point;
			// this is not the previous >3s experiment or a native Windows pipe harness.
			time.Sleep(275 * time.Millisecond)
			unblock()
			select {
			case frame := <-out.frames:
				var reply struct {
					ID     string    `json:"id"`
					OK     bool      `json:"ok"`
					Result LogsReply `json:"result"`
				}
				if err := json.Unmarshal(frame, &reply); err != nil {
					t.Fatal(err)
				}
				if reply.ID != "h41" || !reply.OK || len(reply.Result.Entries) == 0 || reply.Result.Entries[0].Event != "reload_ok" {
					t.Fatalf("original ID/content changed: %s", frame)
				}
			case <-time.After(time.Second):
				t.Fatal("response not returned")
			}
			inW.Close()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("Serve did not join workers")
			}
			stages := map[string]bool{}
			for _, entry := range h.logs.read(0, 500).Entries {
				d := entry.Runtime
				if d == nil {
					continue
				}
				if !d.Valid() || d.Protocol != tc.protocol || d.RequestID == nil || *d.RequestID != 41 {
					t.Fatalf("inconsistent/invalid transport observation: %#v", d)
				}
				if d.Action == "request_end" {
					if d.Stage != "ipc_response" || d.ElapsedMS == nil || *d.ElapsedMS < 250 {
						t.Fatalf("slow phase point changed: %#v", d)
					}
					stages["slow_phase"] = true
				} else {
					stages[d.Stage] = true
				}
			}
			if !stages["ipc_read"] || !stages["ipc_response"] || !stages["slow_phase"] {
				t.Fatalf("missing transport observations: %v", stages)
			}
			t.Logf("%s: buffered request, original ID/content, ordinary and slow-phase labels agree", tc.protocol)
		})
	}
}

type c50TransportUnusedIO struct{ reads, writes, closes int }

func (rw *c50TransportUnusedIO) Read([]byte) (int, error)    { rw.reads++; return 0, io.EOF }
func (rw *c50TransportUnusedIO) Write(p []byte) (int, error) { rw.writes++; return len(p), nil }
func (rw *c50TransportUnusedIO) Close() error                { rw.closes++; return nil }

func TestC50LogsTransportRejectsInvalidNativeKind(t *testing.T) {
	for _, kind := range []TransportKind{2, 255} {
		h := &Host{}
		rw := &c50TransportUnusedIO{}
		err := h.ServeTransport(context.Background(), rw, rw, kind)
		if err == nil || err.Error() != "invalid IPC transport kind" {
			t.Fatalf("kind %d did not fail closed: %v", kind, err)
		}
		if rw.reads != 0 || rw.writes != 0 || rw.closes != 0 || len(h.logs.read(0, 500).Entries) != 0 {
			t.Fatalf("invalid kind touched IO/logs: %#v", rw)
		}
	}
	if _, err := decodeRequest([]byte(`{"id":"h1","method":"hello","protocol":"named_pipe"}`)); err == nil {
		t.Fatal("business JSON selected a native protocol")
	}
}

func TestC50LogsTransportGoProtocolWhitelist(t *testing.T) {
	for _, p := range []string{"stdio", "service_pipe", "named_pipe"} {
		if !(outbound.Diagnostic{Stage: "ipc_read", Category: "ok", Protocol: p}).Valid() {
			t.Fatalf("valid protocol rejected: %s", p)
		}
	}
	for _, p := range []string{"namedpipe", "named_pipe target", "named_pipe\nstdio"} {
		if (outbound.Diagnostic{Stage: "ipc_read", Category: "ok", Protocol: p}).Valid() {
			t.Fatalf("free protocol accepted: %q", p)
		}
	}
}

func TestC50LogsFullRingIndependentOfHostLock(t *testing.T) {
	h := &Host{}
	for range logCapacity + 17 {
		h.logs.record(kernel.ClientLogEvent{Time: time.Now(), Level: "info", Event: "reload_ok"})
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	done := make(chan LogsReply, 1)
	started := time.Now()
	go func() {
		v, e := h.Request(context.Background(), "logs.get", json.RawMessage(`{"after":0,"limit":500}`))
		if e != nil {
			done <- LogsReply{}
			return
		}
		done <- v.(LogsReply)
	}()
	select {
	case r := <-done:
		if len(r.Entries) != 500 || r.Entries[0].Seq != 18 || r.NextSeq != 517 || r.Dropped != 17 {
			t.Fatalf("cursor/content/budget changed: %#v", r)
		}
		t.Logf("full 2000-entry ring, Host.mu held: logs.get copied 500 in %s", time.Since(started))
	case <-time.After(time.Second):
		t.Fatal("logs.get blocked on unrelated Host mutex")
	}
}

type c50GateWriter struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
	frames  chan []byte
	err     error
}

func (w *c50GateWriter) Write(b []byte) (int, error) {
	w.once.Do(func() { close(w.entered); <-w.release })
	if w.err != nil {
		return 0, w.err
	}
	w.frames <- append([]byte(nil), b...)
	return len(b), nil
}

func TestC50LogsReplyWaitsForOutputNotHostLock(t *testing.T) {
	h := &Host{}
	h.logs.record(kernel.ClientLogEvent{Time: time.Now(), Level: "info", Event: "reload_ok"})
	inR, inW := io.Pipe()
	out := &c50GateWriter{entered: make(chan struct{}), release: make(chan struct{}), frames: make(chan []byte, 4)}
	var release sync.Once
	unblock := func() { release.Do(func() { close(out.release) }) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer inW.Close()
	defer unblock()
	done := make(chan error, 1)
	go func() { done <- h.Serve(ctx, inR, out) }()
	if _, e := io.WriteString(inW, "{\"id\":\"h1\",\"method\":\"hello\"}\n"); e != nil {
		t.Fatal(e)
	}
	select {
	case <-out.entered:
	case <-time.After(time.Second):
		t.Fatal("first response did not reach controlled output")
	}
	started := time.Now()
	if _, e := io.WriteString(inW, "{\"id\":\"h2\",\"method\":\"logs.get\",\"params\":{\"after\":0,\"limit\":500}}\n"); e != nil {
		t.Fatal(e)
	}
	h.mu.Lock()
	time.Sleep(3050 * time.Millisecond)
	if len(out.frames) != 0 {
		h.mu.Unlock()
		t.Fatal("output crossed the held write barrier")
	}
	unblock()
	for i := 0; i < 2; i++ {
		select {
		case b := <-out.frames:
			var r Response
			if e := json.Unmarshal(b, &r); e != nil {
				h.mu.Unlock()
				t.Fatal(e)
			}
			if !r.OK || (i == 0 && r.ID != "h1") || (i == 1 && r.ID != "h2") {
				h.mu.Unlock()
				t.Fatalf("correlation/order changed: %s", b)
			}
			if r.ID == "h2" {
				var wire struct {
					Result LogsReply `json:"result"`
				}
				if e := json.Unmarshal(b, &wire); e != nil {
					h.mu.Unlock()
					t.Fatal(e)
				}
				if len(wire.Result.Entries) == 0 || wire.Result.Entries[0].Event != "reload_ok" {
					h.mu.Unlock()
					t.Fatal("original log result was lost")
				}
			}
		case <-time.After(time.Second):
			h.mu.Unlock()
			t.Fatal("reply did not recover after output release")
		}
	}
	h.mu.Unlock()
	inW.Close()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve leaked a worker")
	}
	c50AssertLogPhase(t, h, "ipc_write", 2, "ok")
	t.Logf("controlled stdout block reproduced >3s logs.get reply wait: %s; original ID/result recovered", time.Since(started))
}

func c50AssertLogPhase(t *testing.T, h *Host, stage string, id uint64, category string) {
	t.Helper()
	var found int
	for _, e := range h.logs.read(0, 500).Entries {
		d := e.Runtime
		if d == nil || d.Action != "request_end" {
			continue
		}
		if !d.Valid() || d.Stage != stage || d.RequestID == nil || *d.RequestID != id || d.ElapsedMS == nil || *d.ElapsedMS < 250 || d.Category != category {
			t.Fatalf("wrong completed slow phase: %#v", d)
		}
		found++
		t.Logf("request h%d: %s/%s elapsed=%dms", id, d.Stage, d.Category, *d.ElapsedMS)
	}
	if found != 1 {
		t.Fatalf("wanted exactly one slow phase, got %d", found)
	}
}

func TestC50LogsMeasureHandlerVersusActualWrite(t *testing.T) {
	for _, tc := range []struct {
		name, stage, category  string
		ringLock, writeFailure bool
	}{
		{"log_ring_wait", "ipc_request", "ok", true, false},
		{"stdout_wait", "ipc_response", "ok", false, false},
		{"stdout_failure", "ipc_response", "write_failed", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &Host{}
			inR, inW := io.Pipe()
			out := &c50GateWriter{entered: make(chan struct{}), release: make(chan struct{}), frames: make(chan []byte, 2)}
			if tc.writeFailure {
				out.err = io.ErrClosedPipe
			}
			var once sync.Once
			unblock := func() { once.Do(func() { close(out.release) }) }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			defer inW.Close()
			defer unblock()
			done := make(chan error, 1)
			go func() { done <- h.Serve(ctx, inR, out) }()
			if tc.ringLock {
				h.logs.mu.Lock()
				unblock()
			}
			if _, e := io.WriteString(inW, "{\"id\":\"h7\",\"method\":\"logs.get\",\"params\":{\"limit\":500}}\n"); e != nil {
				if tc.ringLock {
					h.logs.mu.Unlock()
				}
				t.Fatal(e)
			}
			if tc.ringLock {
				time.Sleep(350 * time.Millisecond)
				h.logs.mu.Unlock()
			} else {
				select {
				case <-out.entered:
				case <-time.After(time.Second):
					t.Fatal("logs.get did not reach output")
				}
				time.Sleep(350 * time.Millisecond)
				unblock()
			}
			if !tc.writeFailure {
				select {
				case b := <-out.frames:
					var r Response
					if e := json.Unmarshal(b, &r); e != nil || r.ID != "h7" || !r.OK {
						t.Fatalf("original reply changed: %s (%v)", b, e)
					}
				case <-time.After(time.Second):
					t.Fatal("response did not complete")
				}
			}
			inW.Close()
			select {
			case e := <-done:
				if (e != nil) != tc.writeFailure {
					t.Fatalf("real transport error changed: %v", e)
				}
			case <-time.After(time.Second):
				t.Fatal("Serve did not join worker")
			}
			c50AssertLogPhase(t, h, tc.stage, 7, tc.category)
		})
	}
}

func TestC50LogsSlowPhaseBoundAndClassification(t *testing.T) {
	for _, tc := range []struct {
		stage  string
		timing ipcLogTiming
	}{
		{"ipc_admission", ipcLogTiming{admission: 300 * time.Millisecond}},
		{"ipc_request", ipcLogTiming{handler: 300 * time.Millisecond}},
		{"ipc_parse", ipcLogTiming{encode: 300 * time.Millisecond}},
		{"ipc_write", ipcLogTiming{writeWait: 300 * time.Millisecond}},
		{"ipc_response", ipcLogTiming{write: 300 * time.Millisecond}},
	} {
		t.Run(tc.stage, func(t *testing.T) {
			h := &Host{}
			h.recordSlowIPCLogs("h9", ipcLogTiming{handler: time.Millisecond}, 1, TransportStdio)
			if s := h.logs.read(0, 500); len(s.Entries) != 0 {
				t.Fatal("fast phase amplified logs")
			}
			for range 100 {
				h.recordSlowIPCLogs("h9", tc.timing, 1, TransportStdio)
			}
			c50AssertLogPhase(t, h, tc.stage, 9, "ok")
			if s := h.logs.read(0, 500); len(s.Entries) != 1 || s.NextSeq != 1 {
				t.Fatal("existing rate gate bypassed")
			}
		})
	}
}

func TestC50LogsDedicatedAdmissionUnderFullSlots(t *testing.T) {
	h := &Host{}
	h.logs.record(kernel.ClientLogEvent{Time: time.Now(), Level: "info", Event: "reload_ok"})
	h.mu.Lock()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	defer outR.Close()
	defer inW.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		e := h.ServeTransport(ctx, inR, outW, TransportNamedPipe)
		outW.Close()
		done <- e
	}()
	replies := make(chan Response, 32)
	go func() {
		d := json.NewDecoder(outR)
		for {
			var r Response
			if d.Decode(&r) != nil {
				close(replies)
				return
			}
			replies <- r
		}
	}()
	for i := 0; i < 16; i++ {
		b, _ := json.Marshal(map[string]any{"id": "s" + string(rune('a'+i)), "method": "status"})
		if _, e := inW.Write(append(b, '\n')); e != nil {
			h.mu.Unlock()
			t.Fatal(e)
		}
	}
	if _, e := io.WriteString(inW, "{\"id\":\"overflow\",\"method\":\"hello\"}\n"); e != nil {
		h.mu.Unlock()
		t.Fatal(e)
	}
	select {
	case r := <-replies:
		if r.ID != "overflow" || r.OK || r.Error == nil || r.Error.Code != "busy" {
			h.mu.Unlock()
			t.Fatalf("expected 17th general request to be busy, got %#v", r)
		}
	case <-time.After(time.Second):
		h.mu.Unlock()
		t.Fatal("overflow reply timed out")
	}
	started := time.Now()
	if _, e := io.WriteString(inW, "{\"id\":\"h88\",\"method\":\"logs.get\",\"params\":{\"after\":0,\"limit\":500}}\n"); e != nil {
		h.mu.Unlock()
		t.Fatal(e)
	}
	select {
	case r := <-replies:
		if r.ID != "h88" || !r.OK {
			h.mu.Unlock()
			t.Fatalf("logs.get blocked or failed while general slots full: %#v", r)
		}
		if elapsed := time.Since(started); elapsed >= ipcLogSlowPhase {
			h.mu.Unlock()
			t.Fatalf("logs.get admission/reply exceeded slow threshold: %s", elapsed)
		}
	case <-time.After(time.Second):
		h.mu.Unlock()
		t.Fatal("logs.get timed out behind 16 blocked general requests")
	}
	h.mu.Unlock()
	inW.Close()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeTransport did not drain")
	}
}

func TestRound2KernelLogsCapacityCursorAndParams(t *testing.T) {
	h := &Host{}
	for i := 0; i < 2010; i++ {
		h.kernelLogs.record(kernel.KernelLogEvent{Time: time.Now(), Level: "info", Message: "safe token=HIDDEN"})
	}
	h.kernelLogs.record(kernel.KernelLogEvent{Time: time.Now(), Level: "error", Message: "original failure"})
	r := h.kernelLogs.read(0, 500, "error")
	if len(r.Entries) != 1 || r.NextSeq != 2011 || r.Dropped != 11 {
		t.Fatal(r)
	}
	r = h.kernelLogs.read(0, 500, "")
	if len(r.Entries) != 500 || r.Entries[0].Seq != 12 || strings.Contains(r.Entries[0].Message, "HIDDEN") {
		t.Fatal(r)
	}
	for _, raw := range []string{`{"after":-1}`, `{"limit":501}`, `{"level":"bogus"}`, `{"extra":true}`} {
		if _, e := h.Request(context.Background(), "logs.kernel", json.RawMessage(raw)); e == nil {
			t.Fatal("accepted", raw)
		}
	}
	if _, e := h.Request(context.Background(), "logs.kernel", json.RawMessage(`{"after":0,"limit":500,"level":"info"}`)); e != nil {
		t.Fatal(e)
	}
}
