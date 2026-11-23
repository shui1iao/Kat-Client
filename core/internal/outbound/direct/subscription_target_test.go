package direct

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"net"
	"net/netip"
	"testing"
)

func TestSubscriptionDirectChecksFinalResolution(t *testing.T) {
	sentinel := errors.New("offline dial observed")
	var ips []netip.Addr
	resolved, dialed := 0, 0
	var chosen string
	d := New(Options{Resolve: func(context.Context, string) ([]netip.Addr, error) { resolved++; return ips, nil }, DialContext: func(_ context.Context, _, peer string) (net.Conn, error) {
		dialed++
		chosen = peer
		return nil, sentinel
	}})
	ctx := outbound.WithPublicTarget(context.Background())
	local := netip.MustParseAddr("192.168.1.1")
	pub := netip.MustParseAddr("8.8.8.8")
	dst := outbound.Addr{Host: "resource.invalid", Port: 443}
	for _, ans := range [][]netip.Addr{{local}, {pub, local}} {
		ips = ans
		_, e := d.DialTCP(ctx, dst)
		if !errors.Is(e, ErrBlocked) || dialed != 0 {
			t.Fatal("unexpected socket for non-public answer", e)
		}
	}
	ips = []netip.Addr{pub}
	_, e := d.DialTCP(ctx, dst)
	if !errors.Is(e, sentinel) || dialed != 1 || resolved != 3 || chosen != "8.8.8.8:443" {
		t.Fatal("expected one literal public dial", resolved, dialed, e)
	}
	ips = []netip.Addr{local}
	_, e = d.DialTCP(context.Background(), dst)
	if !errors.Is(e, sentinel) || dialed != 2 {
		t.Fatal("operator target unexpectedly restricted", e)
	}
}
