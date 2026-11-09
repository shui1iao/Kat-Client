package clientcore

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/outbound"
)

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
