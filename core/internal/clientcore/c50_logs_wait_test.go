package clientcore

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/kernel"
)

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
