package direct

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

func TestC50PacketSourceBeforeBind(t *testing.T) {
	for _, tc := range []struct {
		network, configured, selected string
		v6                            bool
	}{
		{"udp4", "127.0.0.2", "127.0.0.1", false},
		{"udp6", "::", "::1", true},
	} {
		t.Run(tc.network, func(t *testing.T) {
			configured, selected := netip.MustParseAddr(tc.configured), netip.MustParseAddr(tc.selected)
			peer, e := net.ListenUDP(tc.network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(selected, 0)))
			if e != nil {
				t.Fatal(e)
			}
			defer peer.Close()
			sources, controls := 0, 0
			o := Options{PacketSource: func(n string, b netip.Addr) (netip.Addr, error) {
				sources++
				if n != tc.network || b != configured {
					t.Fatalf("source input %s %s", n, b)
				}
				return selected, nil
			},
				PacketControl: func(n string, c *net.UDPConn) error {
					controls++
					if sources != 1 || n != tc.network || c.LocalAddr().(*net.UDPAddr).AddrPort().Addr() != selected {
						t.Fatalf("control before selected bind: %v", c.LocalAddr())
					}
					return nil
				}}
			if tc.v6 {
				o.BindIPv6 = configured
			} else {
				o.BindIPv4 = configured
			}
			d := New(o)
			pc, e := d.ListenPacket(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer pc.Close()
			p := pc.(*packetConn)
			if sources != 0 || controls != 0 {
				t.Fatal("ordinary/local sockets called remote hooks")
			}
			c, e := p.remoteSocket(tc.v6)
			if e != nil {
				t.Fatal(e)
			}
			cached, e := p.remoteSocket(tc.v6)
			if e != nil || cached != c || sources != 1 || controls != 1 {
				t.Fatal("cached socket rebound or hooks rerun")
			}
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, e = c.WriteToUDPAddrPort([]byte("bound"), peer.LocalAddr().(*net.UDPAddr).AddrPort()); e != nil {
				t.Fatal(e)
			}
			var b [8]byte
			n, src, e := peer.ReadFromUDPAddrPort(b[:])
			if e != nil || string(b[:n]) != "bound" || src.Addr() != selected {
				t.Fatalf("actual source=%v payload=%q err=%v", src, b[:n], e)
			}
		})
	}
}

func TestC50PacketSourceErrorDoesNotFallback(t *testing.T) {
	want := errors.New("source unavailable")
	sources, controls := 0, 0
	d := New(Options{DisableIPv6: true, PacketSource: func(n string, b netip.Addr) (netip.Addr, error) {
		sources++
		if n != "udp4" || b.IsValid() {
			t.Fatalf("configured source changed: %s %s", n, b)
		}
		return netip.Addr{}, want
	}, PacketControl: func(string, *net.UDPConn) error { controls++; return nil }})
	pc, e := d.ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	// The hook fails before creating a remote socket, so no packet can escape.
	n, e := pc.WriteTo([]byte("must-not-send"), outbound.Addr{Host: "192.0.2.1", Port: 9})
	if n != 0 || !errors.Is(e, want) || sources != 1 || controls != 0 || pc.(*packetConn).remote4 != nil {
		t.Fatalf("fallback after source error: n=%d err=%v source=%d control=%d", n, e, sources, controls)
	}
}

func TestC50PacketSourceOrdinaryCompatibility(t *testing.T) {
	for _, mode := range []string{"nil", "ordinary-switch-pass-through"} {
		t.Run(mode, func(t *testing.T) {
			o := Options{DisableIPv6: true, PacketControl: func(string, *net.UDPConn) error { return nil }}
			if mode != "nil" {
				o.PacketSource = func(_ string, b netip.Addr) (netip.Addr, error) { return b, nil }
			}
			d := New(o)
			pc, e := d.ListenPacket(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			defer pc.Close()
			c, e := pc.(*packetConn).remoteSocket(false)
			if e != nil {
				t.Fatal(e)
			}
			if !c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().IsUnspecified() {
				t.Fatalf("ordinary default changed: %v", c.LocalAddr())
			}
		})
	}
}
