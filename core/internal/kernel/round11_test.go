package kernel

import (
	"bufio"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// Real controllable SOCKS peers, not injected latency records. Each serves HEAD
// keep-alive twice (unified delay), so both engines see identical HTTP paths.
type r11Peer struct {
	delay atomic.Int64
	down  atomic.Bool
	ln    net.Listener
}

func r11Node(t *testing.T, d int) *r11Peer {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := &r11Peer{ln: ln}
	p.delay.Store(int64(d))
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p
}
func (p *r11Peer) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	r := bufio.NewReader(c)
	var h [2]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return
	}
	if _, e := io.CopyN(io.Discard, r, int64(h[1])); e != nil {
		return
	}
	if p.down.Load() {
		return
	}
	c.Write([]byte{5, 0})
	var req [4]byte
	if _, e := io.ReadFull(r, req[:]); e != nil {
		return
	}
	n := 0
	switch req[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		b, e := r.ReadByte()
		if e != nil {
			return
		}
		n = int(b)
	default:
		return
	}
	if _, e := io.CopyN(io.Discard, r, int64(n+2)); e != nil {
		return
	}
	c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
	for {
		q, e := http.ReadRequest(r)
		if e != nil {
			return
		}
		q.Body.Close()
		if p.down.Load() {
			return
		}
		time.Sleep(time.Duration(p.delay.Load()) * time.Millisecond)
		if p.down.Load() {
			return
		}
		if _, e = io.WriteString(c, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"); e != nil {
			return
		}
	}
}
func r11Port(t *testing.T) int {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// SPEC4 deliberately no longer has mihomo's single-low-sample / zero-
// tolerance selection semantics. Keep real controlled peers for health and
// startup regression; mathematical dwell is tested with a fake clock in group.
func TestR11ControlledStableGroups(t *testing.T) {
	a, b := r11Node(t, 20), r11Node(t, 50)
	lazy := false
	cfg := socksCfg("127.0.0.1:0")
	cfg.SetClientUnifiedDelay(true)
	for i, p := range []*r11Peer{a, b} {
		cfg.Outbounds = append(cfg.Outbounds, OutboundConfig{Name: []string{"A", "B"}[i], Type: "socks5", Server: "127.0.0.1", Port: uint16(p.ln.Addr().(*net.TCPAddr).Port)})
	}
	for _, v := range []struct{ name, kind string }{{"U", "url-test"}, {"F", "fallback"}} {
		cfg.Groups = append(cfg.Groups, GroupConfig{Name: v.name, Type: v.kind, Members: []string{"A", "B"}, Lazy: &lazy, Probe: &group.ProbeOptions{URL: "http://bench.invalid/204", Interval: outbound.Duration(time.Second), Timeout: outbound.Duration(200 * time.Millisecond)}})
	}
	s := groupsStart(t, cfg)
	current := func(name string) string {
		for _, g := range s.GroupSnapshots() {
			if g.Name == name {
				return g.Current
			}
		}
		return ""
	}
	await := func(name, want string, limit time.Duration) {
		t.Helper()
		deadline := time.Now().Add(limit)
		for current(name) != want {
			if time.Now().After(deadline) {
				t.Fatalf("%s=%s want %s", name, current(name), want)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	time.Sleep(300 * time.Millisecond)
	await("U", "A", time.Second)
	await("F", "A", time.Second)
	a.down.Store(true)
	await("U", "B", 3*time.Second)
	await("F", "B", 3*time.Second)
	a.down.Store(false)
	a.delay.Store(1)
	time.Sleep(1500 * time.Millisecond)
	if current("F") != "B" {
		t.Fatal("single recovery switched fallback")
	}
	await("F", "A", 12*time.Second)
	if current("U") != "B" {
		t.Fatal("recovery bypassed url-test min dwell")
	}
}
