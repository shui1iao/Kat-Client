package clientcore

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/kernel"
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
	if s = r.read(maxLogSeq, 1); len(s.Entries) != 0 || s.NextSeq != maxLogSeq || s.Dropped != 17 {
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
			if k != "seq" && k != "time" && k != "level" && k != "event" && k != "code" {
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
