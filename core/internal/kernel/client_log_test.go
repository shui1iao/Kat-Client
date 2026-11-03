package kernel

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestClientLogFilterAndLevels(t *testing.T) {
	// Deliberately synthetic sensitive markers: never real user material.
	secret := "fixture-password-token"
	for _, threshold := range []logLevel{levelDebug, levelInfo, levelWarn, levelError} {
		var got []ClientLogEvent
		l, e := newClientLogger(&LogOptions{Level: threshold.String(), File: filepath.Join(t.TempDir(), "must-not-open"), Access: true}, func(e ClientLogEvent) { got = append(got, e) })
		if e != nil || l.file != nil || l.access.Load() {
			t.Fatal("client sink opened original destination")
		}
		for _, lv := range []logLevel{levelDebug, levelInfo, levelWarn, levelError} {
			_ = l.emit(lv, []byte("kat event=failure reason=connect_failed password="+secret+" url=https://name:pass@fixture.invalid/path?q=token header=Authorization path=/private/fixture\n"))
		}
		if len(got) != int(levelError-threshold+1) {
			t.Fatal("actual level gate not respected")
		}
		for _, e := range got {
			if e.Event != "failure" || e.Code != "connect_failed" {
				t.Fatal("fixed facts not retained")
			}
			b, _ := json.Marshal(e)
			if bytes.Contains(b, []byte(secret)) || len(b) > 512 {
				t.Fatal("unsafe/unbounded event")
			}
		}
		n := len(got)
		for _, line := range []string{"arbitrary " + secret, "kat event=access password=" + secret, "kat event=" + secret, "kat event=reload_ok " + strings.Repeat(secret, 500)} {
			_ = l.emit(levelError, []byte(line))
		}
		if len(got) != n {
			t.Fatal("unknown/access/free/oversized line accepted")
		}
		_ = l.emit(levelError, []byte("kat event=reload_failed reason=https://fixture.invalid/?secret="+secret+"\n"))
		if got[len(got)-1].Code != "" {
			t.Fatal("free-form reload error copied")
		}
		l.shutdown()
		_ = l.emit(levelError, []byte("kat event=reload_ok\n"))
		if len(got) != n+1 {
			t.Fatal("closed sink accepted write")
		}
	}
	// Client sink never changes another logger's behavior or destination.
	normal, _ := newLogger(&LogOptions{Level: "debug"})
	defer normal.shutdown()
	var raw bytes.Buffer
	normal.write = func(b []byte) error { _, e := raw.Write(b); return e }
	_ = normal.emit(levelInfo, []byte("original raw message\n"))
	if raw.String() != "original raw message\n" {
		t.Fatal("ordinary logger changed")
	}
}

func TestClientLogRealRuntimeReload(t *testing.T) {
	var mu sync.Mutex
	var entries []ClientLogEvent
	sink := func(e ClientLogEvent) { mu.Lock(); entries = append(entries, e); mu.Unlock() }
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.SetClientLogSink(sink)
	dir := t.TempDir()
	c.Log = &LogOptions{Level: "info", File: filepath.Join(dir, "not-created.log"), Access: true}
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	for _, level := range []string{"debug", "info", "warn", "error", "info"} {
		c.Log = &LogOptions{Level: level, Format: "json", File: filepath.Join(dir, level+"-not-created.log"), Access: true}
		if _, e := s.ApplyConfig(c); e != nil {
			t.Fatal(e)
		}
		if s.log.getLevel().String() != level || s.log.access.Load() || s.log.file != nil {
			t.Fatal("runtime level/private sink not retained across reload")
		}
		mu.Lock()
		entries = nil
		mu.Unlock()
		// Real successful generation install/release, not injected log records.
		if _, e := s.ApplyConfig(c); e != nil {
			t.Fatal(e)
		}
		busy, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		bad := c
		bad.Inbounds = append([]Inbound(nil), c.Inbounds...)
		bad.Inbounds[0].Listen = busy.Addr().String()
		if _, e = s.ApplyConfig(bad); e == nil {
			t.Fatal("expected actual bind failure")
		}
		busy.Close()
		mu.Lock()
		copyEvents := append([]ClientLogEvent(nil), entries...)
		mu.Unlock()
		present := map[string]bool{}
		for _, e := range copyEvents {
			present[e.Event] = true
			if e.Time.IsZero() {
				t.Fatal("no event timestamp")
			}
		}
		if present["reload_ok"] != (level == "info" || level == "debug") {
			t.Fatal("info gate not applied to real reload")
		}
		if present["config_generation_released"] != (level == "debug") {
			t.Fatal("debug gate not applied to actual retirement")
		}
		if present["reload_failed"] != (level != "error") {
			t.Fatal("warn gate not applied to real bind failure")
		}
	}
	if files, _ := os.ReadDir(dir); len(files) != 0 {
		t.Fatal("client opened arbitrary configured log.file")
	}
	// Logger is shared across generations, not globally. A second instance
	// cannot deliver events into this callback.
	mu.Lock()
	n := len(entries)
	mu.Unlock()
	other := socksCfg("127.0.0.1:0")
	other.DNS = &DNSOptions{Server: "system"}
	other.Log = &LogOptions{Level: "error"}
	o, e := Start(other)
	if e != nil {
		t.Fatal(e)
	}
	o.Close(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if len(entries) != n {
		t.Fatal("cross-instance log leak")
	}
}
