package kernel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

func TestC50PacketSourceKernelDirect(t *testing.T) {
	ip := netip.MustParseAddr(c50LocalIP(t, false))
	peer, e := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)))
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	selected, controlled, released := 0, 0, 0
	want := errors.New("physical fenced")
	fail := false
	s := c50Server(t, nil, func(c *Config) {
		// socksCfg binds loopback for unrelated tests. Exercise an unconfigured
		// remote source here, letting PacketSource choose the actual local IP.
		c.UDPBindIPv4, c.UDPBindIPv6 = "", ""
		c.SetClientEgress(&ClientEgress{
			PacketSource: func(n string, b netip.Addr) (netip.Addr, error) {
				selected++
				if n != "udp4" || b.IsValid() {
					t.Fatalf("kernel changed source input: %s %s", n, b)
				}
				if fail {
					return netip.Addr{}, want
				}
				return ip, nil
			},
			PacketControl: func(n string, c *net.UDPConn) error {
				controlled++
				if n != "udp4" || c.LocalAddr().(*net.UDPAddr).AddrPort().Addr() != ip {
					t.Fatalf("not selected source %s %v", n, c.LocalAddr())
				}
				return nil
			},
			PacketRelease: func(*net.UDPConn) { released++ },
		})
	})
	// Use the same production direct outbound installed by buildRouting.
	cur := s.current()
	rt, e := cur.buildRouting()
	if e != nil {
		t.Fatal(e)
	}
	defer rt.close()
	pc, e := rt.nodes["direct"].ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	dst := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	addr := outbound.Addr{Host: dst.Addr().String(), Port: dst.Port()}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = pc.WriteTo([]byte("hook"), addr); e != nil {
		t.Fatal(e)
	}
	var b [8]byte
	n, src, e := peer.ReadFromUDPAddrPort(b[:])
	if e != nil || src.Addr() != ip || string(b[:n]) != "hook" {
		t.Fatalf("upstream src=%v err=%v", src, e)
	}
	if _, e = peer.WriteToUDPAddrPort([]byte("reply"), src); e != nil {
		t.Fatal(e)
	}
	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	n, from, e := pc.ReadFrom(b[:])
	if e != nil || string(b[:n]) != "reply" || from != addr {
		t.Fatalf("downstream %q from=%v err=%v", b[:n], from, e)
	}
	_ = pc.Close()
	if selected != 1 || controlled != 1 || released != 1 {
		t.Fatalf("hook counts %d/%d/%d", selected, controlled, released)
	}
	fail = true
	pc, e = rt.nodes["direct"].ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	n, e = pc.WriteTo([]byte("blocked"), addr)
	if n != 0 || !errors.Is(e, want) || controlled != 1 {
		t.Fatalf("kernel hook error hidden: n=%d err=%v control=%d", n, e, controlled)
	}
}
