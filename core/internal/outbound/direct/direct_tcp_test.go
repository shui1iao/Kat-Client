package direct

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestK2IPv6TCPUDPRejectedBeforeIO(t *testing.T) {
	d := New(Options{DisableIPv6: true})
	_, e := d.DialTCP(context.Background(), outbound.Addr{Host: "2001:db8::1", Port: 443})
	if !errors.Is(e, ErrIPv6Disabled) {
		t.Fatal(e)
	}
	pc, e := d.ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	if pc.(*packetConn).v6 != nil {
		t.Fatal("created udp6 socket while disabled")
	}
	_, e = pc.WriteTo([]byte("no send"), outbound.Addr{Host: "2001:db8::1", Port: 443})
	if !errors.Is(e, ErrIPv6Disabled) {
		t.Fatal(e)
	}
	ips, e := d.resolve(context.Background(), "::ffff:192.0.2.1")
	if e != nil || len(ips) != 1 || ips[0] != netip.MustParseAddr("192.0.2.1") {
		t.Fatal(ips, e)
	}
}

func TestRound2ActualDirectIPObserver(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e == nil {
			c.Close()
		}
	}()
	var ips []netip.Addr
	var chosen netip.Addr
	ctx := outbound.WithDialObserver(context.Background(), func(p []netip.Addr, ip netip.Addr) { ips = p; chosen = ip })
	d := New(Options{Resolve: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}})
	c, e := d.DialTCP(ctx, outbound.Addr{Host: "resolved.test", Port: outboundPort(l.Addr().String())})
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	<-done
	if len(ips) != 1 || chosen.String() != "127.0.0.1" {
		t.Fatal(ips, chosen)
	}
	ctx2 := outbound.WithDialObserver(ctx, nil)
	chosen = netip.Addr{}
	outbound.ObserveDial(ctx2, nil, netip.MustParseAddr("1.2.3.4"))
	if chosen.IsValid() {
		t.Fatal("underlay observer was not stripped")
	}
	_ = time.Second
}
func outboundPort(s string) uint16 { a, _ := netip.ParseAddrPort(s); return a.Port() }
