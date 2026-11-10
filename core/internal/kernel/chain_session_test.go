package kernel

import (
	"context"
	"errors"

	"io"
	"net"

	"net/netip"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

func chainRoundTrip(t *testing.T, c net.Conn) {
	t.Helper()
	p := []byte("chain-old-and-new-stream")
	c.SetDeadline(time.Now().Add(time.Second))
	if _, e := c.Write(p); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(p))
	if _, e := io.ReadFull(c, got); e != nil {
		t.Fatal(e)
	}
	if string(got) != string(p) {
		t.Fatal("payload changed")
	}
}

func chainOpen(t *testing.T, ob outbound.Outbound, dst outbound.Addr) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, e := ob.DialTCP(ctx, dst)
	if e != nil {
		t.Fatal(e)
	}
	chainRoundTrip(t, c)
	return c
}

func TestChainStripPreservesBudgetAndValues(t *testing.T) {
	type retainedKey struct{}
	calls := 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, retainedKey{}, "keep")
	ctx = outbound.WithDialObserver(withHops(withInbound(ctx, 0), &hops{}), func([]netip.Addr, netip.Addr) { calls++ })
	got := strip(ctx)
	for range 4 {
		if again := strip(got); again != got {
			t.Fatal("repeated strip rebuilt an identical context")
		}
	}
	outbound.ObserveDial(got, nil, netip.Addr{})
	if calls != 0 || isClient(got) || got.Value(hopsKey{}).(*hops) != nil || got.Value(retainedKey{}) != "keep" {
		t.Fatal("underlay context isolation changed")
	}
	outbound.ObserveDial(ctx, nil, netip.Addr{})
	if calls != 1 || !isClient(ctx) {
		t.Fatal("parent context mutated")
	}
	before, _ := ctx.Deadline()
	after, _ := got.Deadline()
	if before != after || ctx.Done() != got.Done() {
		t.Fatal("budget lost")
	}
	cancel()
	if !errors.Is(got.Err(), context.Canceled) {
		t.Fatal("cancel lost")
	}
}

func TestChainReferencesFailClosed(t *testing.T) {
	for _, kind := range []string{"missing-via", "missing-member", "via-group-cycle", "five-hops"} {
		t.Run(kind, func(t *testing.T) {
			c := socksCfg("127.0.0.1:0")
			c.Outbounds = []OutboundConfig{{Name: "a", Type: "socks5", Server: "127.0.0.1", Port: 9}}
			switch kind {
			case "missing-via":
				c.Outbounds[0].Via = "missing"
			case "missing-member":
				c.Groups = []GroupConfig{{Name: "g", Type: "select", Members: []string{"missing"}}}
			case "via-group-cycle":
				c.Outbounds[0].Via = "g"
				c.Groups = []GroupConfig{{Name: "g", Type: "select", Members: []string{"a"}}}
			case "five-hops":
				for _, name := range []string{"b", "c", "d", "e"} {
					prev := c.Outbounds[len(c.Outbounds)-1].Name
					c.Outbounds = append(c.Outbounds, OutboundConfig{Name: name, Type: "socks5", Server: "127.0.0.1", Port: 9, Via: prev})
				}
			}
			if e := c.Validate(); e == nil {
				t.Fatal("invalid chain accepted")
			}
		})
	}
}
