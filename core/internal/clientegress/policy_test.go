package clientegress

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
)

func fixtureOptions() Options {
	v4, v6 := uint32(4), uint32(6)
	l4, l6 := uint64(14), uint64(16)
	return Options{Schema: Schema, Enabled: true, IPv4: &v4, IPv6: &v6, LUID4: &l4, LUID6: &l6, Identity: strings.Repeat("a", 64), Fingerprint: strings.Repeat("b", 64), DNS: []DNSEndpoint{{Address: "192.0.2.53", Owner: l4, IfIndex: v4}, {Address: "2001:db8::53", Owner: l6, IfIndex: v6}}}
}
func fixturePolicy(t *testing.T, bind func(string, syscall.RawConn) error) *Policy {
	t.Helper()
	p, e := newPolicy(fixtureOptions(), bind, nil)
	if e != nil {
		t.Fatal(e)
	}
	p.owner = func(DNSEndpoint) error { return nil }
	t.Cleanup(p.Fail)
	return p
}
func TestControlledSocketFamiliesLoopbackAndFailures(t *testing.T) {
	var calls []string
	p := fixturePolicy(t, func(n string, _ syscall.RawConn) error { calls = append(calls, n); return nil })
	for _, a := range []string{"127.0.0.1:9", "[::1]:9"} {
		if e := p.Control(context.Background(), "tcp", a, nil); e != nil {
			t.Fatal(e)
		}
	}
	if len(calls) != 0 {
		t.Fatal("bound loopback")
	}
	for _, x := range []struct{ n, a string }{{"tcp", "192.0.2.1:80"}, {"tcp", "[2001:db8::1]:80"}, {"udp", "192.0.2.2:53"}, {"udp", "[2001:db8::2]:53"}} {
		if e := p.Control(context.Background(), x.n, x.a, nil); e != nil {
			t.Fatal(e)
		}
	}
	if strings.Join(calls, ",") != "tcp4,tcp6,udp4,udp6" {
		t.Fatal(calls)
	}
	p.bind = func(string, syscall.RawConn) error { return errors.New("denied") }
	if p.Control(context.Background(), "tcp", "192.0.2.1:80", nil) == nil || p.Ready() {
		t.Fatal("bind failure must fail closed")
	}
}
func TestBootstrapNeverUsesSystemDestination(t *testing.T) {
	p := fixturePolicy(t, func(string, syscall.RawConn) error { return nil })
	c, e := p.resolverConn(context.Background(), "udp", "untrusted-system.example:53")
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := c.(resolverCancel); !ok {
		t.Fatal("must be private in-memory resolver stream")
	}
	c.Close()
	if p.Options.DNS[0].Address != "192.0.2.53" {
		t.Fatal("physical endpoints mutated")
	}
}
func TestUnsupportedPlatformDoesNotBind(t *testing.T) {
	if Supported {
		t.Skip("non-Windows")
	}
	if _, e := New(Options{Enabled: true}); e == nil {
		t.Fatal("unsupported accepted")
	}
}
func TestK2DisabledBusinessFamilyKeepsRegisteredIPv6DNSException(t *testing.T) {
	bound := 0
	p := fixturePolicy(t, func(string, syscall.RawConn) error { bound++; return nil })
	p.SetIPv6(false)
	if e := p.Control(context.Background(), "tcp", "[2001:db8::1]:443", nil); e == nil || !p.Ready() || bound != 0 {
		t.Fatal("business IPv6 guard weakened")
	}
	called := ""
	p.dnsConnect = func(_ context.Context, n, a string, _ func(context.Context, string, string, syscall.RawConn) error) (net.Conn, error) {
		called = n + " " + a
		return nil, errors.New("no remote packets in test")
	}
	state := p.dns.Load()
	ep := p.Options.DNS[1]
	if _, e := p.dnsDial(context.Background(), "udp", ep, state); e == nil || called != "udp6 [2001:db8::53]:53" {
		t.Fatal("registered IPv6 DNS exception lost", called, e)
	}
	ep.Owner++
	if _, e := p.dnsDial(context.Background(), "udp", ep, state); e == nil || p.Ready() {
		t.Fatal("unregistered endpoint trusted")
	}
}
