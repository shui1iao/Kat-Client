package kernel

import (
	"context"

	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func reloadPort(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

func reloadLimits() Limits {
	return Limits{Connections: 32, Handshakes: 16, Dials: 8, UDPAssociations: 8, UDPQueue: 4, UDPTargets: 4, PoolBuffers: 4, HandshakeTimeout: Duration(time.Second), DialTimeout: Duration(time.Second), DrainTimeout: Duration(2 * time.Second), UDPIdle: Duration(time.Second)}
}

func socksCfg(listens ...string) Config {
	c := Config{UDPBindIPv4: "127.0.0.1", UDPBindIPv6: "::1", Limits: reloadLimits(), Security: &SecurityOptions{AllowLoopback: true}}
	for _, l := range listens {
		c.Inbounds = append(c.Inbounds, Inbound{Protocol: "socks5", Listen: l})
	}
	return c
}

// socksTo opens a no-auth SOCKS5 CONNECT on listen to a; ok=false when the
// inbound refused the connection or the no-auth method.

func echoOnce(c net.Conn, msg string) bool {
	if writeAll(c, []byte(msg)) != nil {
		return false
	}
	b, e := readN(c, len(msg))
	return e == nil && string(b) == msg
}

func startReloadable(t *testing.T, c Config, next *Config) *Server {
	t.Helper()
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	s.SetConfigLoader(func() (Config, error) { return *next, nil })
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Close(ctx)
	})
	return s
}

func selectCfg(statsFile, def string, members ...string) Config {
	c := socksCfg("127.0.0.1:0")
	c.Groups = []GroupConfig{{Name: "h", Type: "select", Members: []string{"direct"}}, {Name: "g", Type: "select", Members: members, Selected: def}}
	c.Stats = &StatsOptions{File: statsFile}
	return c
}

func currentOf(t *testing.T, s *Server, name string) (string, string) {
	t.Helper()
	for _, g := range s.SelectGroups() {
		if g.Name == name {
			return g.Current, g.Source
		}
	}
	t.Fatalf("group %s missing", name)
	return "", ""
}

func TestSelectPersistenceMatrix(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "x.stats.json")
	restart := func(s *Server, c Config, next *Config) *Server {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.Close(ctx)
		return startReloadable(t, c, next)
	}
	base := selectCfg(file, "", "direct", "reject", "h")
	next := base
	s := startReloadable(t, base, &next)
	if cur, src := currentOf(t, s, "g"); cur != "direct" || src != "config" {
		t.Fatal(cur, src)
	}
	// Running switch, unknown member refused.
	if e := s.Select("g", "h"); e != nil {
		t.Fatal(e)
	}
	var se *SelectError
	if e := s.Select("g", "nope"); !errors.As(e, &se) || se.Code != "unknown_member" {
		t.Fatal(e)
	}
	if e := s.Select("zz", "h"); !errors.As(e, &se) || se.Code != "unknown_group" {
		t.Fatal(e)
	}
	if b, e := os.ReadFile(filepath.Join(dir, "x.select.json")); e != nil || !strings.Contains(string(b), `"selected": "h"`) {
		t.Fatalf("state file %s %v", b, e)
	}
	// Kept by reload and by restart.
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if cur, src := currentOf(t, s, "g"); cur != "h" || src != "runtime" {
		t.Fatal("reload", cur, src)
	}
	s = restart(s, base, &next)
	if cur, _ := currentOf(t, s, "g"); cur != "h" {
		t.Fatal("restart", cur)
	}
	// Configured default changed (reload): the configuration wins.
	next = selectCfg(file, "reject", "direct", "reject", "h")
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if cur, src := currentOf(t, s, "g"); cur != "reject" || src != "config" {
		t.Fatal("default changed by reload", cur, src)
	}
	// Configured default changed between runs (restart).
	if e := s.Select("g", "h"); e != nil {
		t.Fatal(e)
	}
	changed := selectCfg(file, "direct", "direct", "reject", "h")
	next = changed
	s = restart(s, changed, &next)
	if cur, src := currentOf(t, s, "g"); cur != "direct" || src != "config" {
		t.Fatal("default changed by restart", cur, src)
	}
	// Member removed.
	if e := s.Select("g", "h"); e != nil {
		t.Fatal(e)
	}
	next = selectCfg(file, "direct", "direct", "reject")
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if cur, src := currentOf(t, s, "g"); cur != "direct" || src != "config" {
		t.Fatal("member removed", cur, src)
	}
	// Corrupt state file: warning, configured value.
	if e := s.Select("g", "reject"); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	_ = s.Close(ctx)
	cancel()
	if e := os.WriteFile(filepath.Join(dir, "x.select.json"), []byte("{broken"), 0o600); e != nil {
		t.Fatal(e)
	}
	s = startReloadable(t, next, &next)
	if cur, src := currentOf(t, s, "g"); cur != "direct" || src != "config" {
		t.Fatal("corrupt state", cur, src)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "x.select.json.corrupt-*")); len(m) != 1 {
		t.Fatal("corrupt state file not kept aside", m)
	}
}

// An AnyTLS session (pooled by clients, effectively unbounded lifetime) must
// not pin the generation that accepted it: only its open streams do.

// A finished SS UDP association drops its generation reference and its
// socket's association count: superseded generations are released and the
// UDP socket of a removed inbound closes with its last association.

// Used by both portable provider persistence and Linux socket budget tests.
func closeNow(t *testing.T, s *Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = s.Close(ctx)
}
