package clientcore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/elevated"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestStage5UpdateShutdownSyncsSourceAndHistoryAndPreservesAllUserData(t *testing.T) {
	dir := t.TempDir()
	h, err := Open(dir)
	if err != nil {
		t.Fatal(err)
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
	docText := `{
  "schema_version": 1,
  "client": {
    "mode": "rule",
    "global_group": "auto-group",
    "probe_url": "http://127.0.0.1:1/probe",
    "http_port": ` + strconv.Itoa(hp) + `,
    "socks_port": ` + strconv.Itoa(sp) + `,
    "ipv6": true,
    "close_on_switch": false,
    "sniff": {"enabled": true, "override_destination": false, "tcp_ports": "80,443"}
  },
  "kernel": {
    "dns": {"server": "system"},
    "security": {"allow_loopback": true},
    "outbounds": [
      {"name": "node-a", "type": "socks5", "server": "127.0.0.1", "port": 1080},
      {"name": "node-b", "type": "socks5", "server": "127.0.0.1", "port": 1081}
    ],
    "groups": [
      {"name": "pick", "type": "select", "members": ["node-a", "node-b", "direct"], "selected": "node-a"},
      {"name": "auto-group", "type": "smart", "lazy": true, "fixed": "node-b", "priority": {"node-a": 1.2, "node-b": 0.8}, "smart": {"scope": "site"}, "probe": {"url": "http://127.0.0.1:1/probe", "timeout": "1s", "interval": "1h"}, "members": ["node-a", "node-b"]}
    ],
    "routing": {
      "rules": [
        {"domain_suffix": "example.com", "outbound": "pick"},
        {"ip_cidr": "10.0.0.0/8", "action": "direct"}
      ],
      "final": "auto-group"
    }
  }
}` + "\n"
	if _, de := h.Apply(docText); de != nil {
		h.Close()
		t.Fatal(de)
	}
	// Simulate cumulative traffic checkpoint from c49 / previous session.
	now := time.Now()
	h.mu.Lock()
	h.history.add(now, 12500, 34800)
	if saveErr := h.saveHistory(); saveErr != nil {
		h.mu.Unlock()
		h.Close()
		t.Fatal(saveErr)
	}
	h.mu.Unlock()

	// Write runtime selection state to verify runtime choices survive upgrade/handover.
	selBytes := []byte(`{"version":1,"groups":{"pick":{"selected":"direct","config_default":"node-a"}}}`)
	if err := os.WriteFile(filepath.Join(dir, "runtime.select.json"), selBytes, 0600); err != nil {
		h.Close()
		t.Fatal(err)
	}

	// Drive Host over TransportNamedPipe to verify named-pipe strict update shutdown & resume.
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	serveDone := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		serveDone <- h.ServeTransport(ctx, c2sR, s2cW, TransportNamedPipe)
	}()
	reader := bufio.NewReader(s2cR)
	rpc := func(id, method string) map[string]json.RawMessage {
		t.Helper()
		req, _ := json.Marshal(map[string]any{"id": id, "method": method, "params": map[string]any{}})
		if _, err := c2sW.Write(append(req, byte(10))); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadBytes(byte(10))
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]json.RawMessage
		if err := json.Unmarshal(line, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	if r := rpc("1", "core.start"); string(r["ok"]) != "true" {
		t.Fatalf("core.start failed: %s", r["error"])
	}
	// First prepare-update, then verify normal requests are paused, then resume-update.
	prep1 := rpc("2", "host.prepare-update")
	if string(prep1["ok"]) != "true" {
		t.Fatalf("prepare-update 1 failed: %s", prep1["error"])
	}
	paused := rpc("3", "status")
	if string(paused["ok"]) != "false" {
		t.Fatal("status should be paused while updatePrepared")
	}
	resumed := rpc("4", "host.resume-update")
	if string(resumed["ok"]) != "true" {
		t.Fatalf("resume-update failed: %s", resumed["error"])
	}
	if r := rpc("5", "status"); string(r["ok"]) != "true" {
		t.Fatalf("status after resume failed: %s", r["error"])
	}

	// Add more traffic before final update shutdown.
	h.mu.Lock()
	h.history.add(now, 2500, 5200)
	h.mu.Unlock()

	prep2 := rpc("6", "host.prepare-update")
	if string(prep2["ok"]) != "true" {
		t.Fatalf("prepare-update 2 failed: %s", prep2["error"])
	}
	var ack struct {
		Prepared     bool                `json:"prepared"`
		SourceSaved  bool                `json:"source_saved"`
		HistorySaved bool                `json:"history_saved"`
		Checkpoint   elevated.Checkpoint `json:"checkpoint"`
	}
	if err := json.Unmarshal(prep2["result"], &ack); err != nil || !ack.Prepared || !ack.SourceSaved || !ack.HistorySaved || !ack.Checkpoint.Valid() {
		t.Fatalf("invalid prepare-update ACK: %+v err=%v", ack, err)
	}
	// Close pipe input (simulating Write::Close after persistence ACK) and wait for ServeTransport + Close.
	_ = c2sW.Close()
	if err := <-serveDone; err != nil {
		t.Fatalf("ServeTransport error on clean EOF: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Host.Close failed: %v", err)
	}

	// OpenHandover with committed checkpoint must succeed and preserve all user data and cumulative totals.
	next, err := OpenHandover(dir, ack.Checkpoint)
	if err != nil {
		t.Fatalf("OpenHandover failed: %v", err)
	}
	defer next.Close()

	if next.doc.text != docText {
		t.Fatal("accepted user document changed across handover")
	}
	if !next.doc.client.IPv6 || next.doc.client.HTTPPort != hp || next.doc.client.SOCKSPort != sp {
		t.Fatalf("client preferences lost: %+v", next.doc.client)
	}
	if len(next.doc.config.Groups) != 2 || len(next.doc.config.Outbounds) != 2 || len(next.doc.config.Routing.Rules) != 2 {
		t.Fatal("groups, outbounds or rules lost")
	}
	if next.history.TotalUp != 15000 || next.history.TotalDown != 40000 {
		t.Fatalf("traffic totals mismatch: got (%d, %d), want (15000, 40000)", next.history.TotalUp, next.history.TotalDown)
	}
	// Starting the new server and sampling must NOT double-count previously committed totals,
	// and new traffic must add on top of the committed checkpoint.
	if _, de := next.Start(); de != nil {
		t.Fatal(de)
	}
	next.mu.Lock()
	next.sampleLocked(now)
	if next.history.TotalUp != 15000 || next.history.TotalDown != 40000 {
		next.mu.Unlock()
		t.Fatalf("totals double-counted after Start+sample: (%d, %d)", next.history.TotalUp, next.history.TotalDown)
	}
	next.history.add(now, 500, 1200)
	if next.history.TotalUp != 15500 || next.history.TotalDown != 41200 {
		next.mu.Unlock()
		t.Fatalf("incremental traffic after checkpoint wrong: (%d, %d)", next.history.TotalUp, next.history.TotalDown)
	}
	next.mu.Unlock()
	if _, de := next.Stop(); de != nil {
		t.Fatal(de)
	}
	afterSel, err := os.ReadFile(filepath.Join(dir, "runtime.select.json"))
	if err != nil || !bytes.Contains(afterSel, []byte(`"selected": "direct"`)) {
		t.Fatalf("runtime selection not preserved: %s err=%v", afterSel, err)
	}
}
