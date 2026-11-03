package clientegress

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestControlledSocketFamiliesLoopbackAndFailures(t *testing.T) {
	v4, v6 := uint32(4), uint32(6)
	calls := []string{}
	p, e := newPolicy(Options{Enabled: true, IPv4: &v4, IPv6: &v6, DNS: []string{"192.0.2.53"}}, func(n string, _ syscall.RawConn) error { calls = append(calls, n); return nil }, nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, a := range []string{"127.0.0.1:9", "[::1]:9"} {
		if e = p.Control(context.Background(), "tcp", a, nil); e != nil {
			t.Fatal(e)
		}
	}
	if len(calls) != 0 {
		t.Fatal("bound loopback")
	}
	for _, x := range []struct{ n, a string }{{"tcp", "192.0.2.1:80"}, {"tcp", "[2001:db8::1]:80"}, {"udp", "192.0.2.2:53"}, {"udp", "[2001:db8::2]:53"}} {
		if e = p.Control(context.Background(), x.n, x.a, nil); e != nil {
			t.Fatal(e)
		}
	}
	if len(calls) != 4 || calls[0] != "tcp4" || calls[1] != "tcp6" || calls[2] != "udp4" || calls[3] != "udp6" {
		t.Fatal("family dispatch")
	}
	p.bind = func(string, syscall.RawConn) error { return errors.New("denied") }
	if p.Control(context.Background(), "tcp", "192.0.2.1:80", nil) == nil || p.Ready() {
		t.Fatal("binding failure ready")
	}
}
func TestBootstrapNeverUsesSystemDestination(t *testing.T) {
	i := uint32(1)
	p, e := newPolicy(Options{Enabled: true, IPv4: &i, DNS: []string{"192.0.2.53"}}, func(string, syscall.RawConn) error { return nil }, nil)
	if e != nil {
		t.Fatal(e)
	}
	asked := ""
	p.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		asked = address
		return nil, errors.New("no packets in test")
	}
	_, e = p.resolver.Dial(context.Background(), "udp", "untrusted-system.example:53")
	if e == nil || asked != "192.0.2.53:53" {
		t.Fatal("bootstrap used system resolver")
	}
	if p.Control(context.Background(), "tcp", "[2001:db8::1]:80", nil) == nil || p.Ready() {
		t.Fatal("missing family must fail closed")
	}
}
func TestUnsupportedPlatformDoesNotBind(t *testing.T) {
	if Supported {
		t.Skip("non-Windows invariant")
	}
	if _, e := New(Options{Enabled: true}); e == nil {
		t.Fatal("non-Windows accepted network action")
	}
}

func TestK2DisabledFamilyDoesNotFailPhysicalEgress(t *testing.T) {
	v4, v6 := uint32(4), uint32(6)
	bound := 0
	p, e := newPolicy(Options{Enabled: true, IPv4: &v4, IPv6: &v6, DNS: []string{"2001:db8::53", "192.0.2.53"}}, func(string, syscall.RawConn) error { bound++; return nil }, nil)
	if e != nil {
		t.Fatal(e)
	}
	p.SetIPv6(false)
	if e = p.Control(context.Background(), "tcp", "[2001:db8::1]:443", nil); e == nil || !p.Ready() || bound != 0 {
		t.Fatal(e, p.Ready(), bound)
	}
	called := ""
	p.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		called = address
		return nil, errors.New("test no network")
	}
	_, e = p.resolver.Dial(context.Background(), "udp", "ignored:53")
	if e == nil || called != "192.0.2.53:53" {
		t.Fatal(e, called)
	}
	if p.Options.IPv6 == nil || *p.Options.IPv6 != 6 || len(p.Options.DNS) != 2 {
		t.Fatal("physical snapshot mutated")
	}
	p.SetIPv6(true)
	if e = p.Control(context.Background(), "tcp", "[2001:db8::1]:443", nil); e != nil || bound != 1 {
		t.Fatal(e, bound)
	}
}
