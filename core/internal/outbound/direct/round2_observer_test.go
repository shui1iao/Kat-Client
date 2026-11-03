package direct

import (
	"context"
	"github.com/shui1iao/Kat/internal/outbound"
	"net"
	"net/netip"
	"testing"
	"time"
)

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
