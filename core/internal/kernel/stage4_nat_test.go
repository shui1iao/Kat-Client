package kernel

import (
	"bytes"
	"context"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func stage4UDP(t *testing.T, p *c50Peer, v6 bool) *gonet.UDPConn {
	t.Helper()
	ip := netip.MustParseAddr("10.50.0.2")
	proto := ipv4.ProtocolNumber
	if v6 {
		ip = netip.MustParseAddr("fd50::2")
		proto = ipv6.ProtocolNumber
	}
	c, e := gonet.DialUDP(p.s, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ip.AsSlice()), Port: 40444}, nil, proto)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
func stage4Socket(t *testing.T, network, ip string) *net.UDPConn {
	t.Helper()
	c, e := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(ip), 0)))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// Real gVisor IP stacks + real local unconnected sockets; no Wintun/PnP claim.
func TestStage4EIMAndEIFBothFamiliesSingleMeter(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(strconv.FormatBool(v6), func(t *testing.T) {
			network, ip := "udp4", c50LocalIP(t, v6)
			if v6 {
				network = "udp6"
			}
			other := ip
			a, b, c := stage4Socket(t, network, ip), stage4Socket(t, network, ip), stage4Socket(t, network, other)
			var records c49DNSRecords
			s := c50Server(t, &records, func(cfg *Config) {
				cfg.Security = &SecurityOptions{AllowLoopback: true}
				cfg.Limits.UDPIdle = Duration(180 * time.Millisecond)
			})
			p := c50Link(t, c50Ingress(t, s), func() bool { return true }, func() uint64 { return 111 })
			inner := stage4UDP(t, p, v6)
			var external netip.AddrPort
			totalUp, totalDown := uint64(0), uint64(0)
			for i, socket := range []*net.UDPConn{a, b, a, b} {
				msg := []byte("hello")
				_, e := inner.WriteTo(msg, socket.LocalAddr())
				if e != nil {
					t.Fatal(e)
				}
				totalUp += uint64(len(msg))
				_ = socket.SetReadDeadline(time.Now().Add(time.Second))
				buf := make([]byte, 4000)
				n, src, e := socket.ReadFromUDPAddrPort(buf)
				if e != nil || !bytes.Equal(buf[:n], msg) {
					t.Fatal("outbound", e)
				}
				if i == 0 {
					external = src
				} else if src != external {
					t.Fatal("same source/policy changed mapping", external, src)
				}
				reply := []byte("echo")
				_, _ = socket.WriteToUDPAddrPort(reply, src)
				_ = inner.SetReadDeadline(time.Now().Add(time.Second))
				n, peer, e := inner.ReadFrom(buf)
				if e != nil || peer.String() != socket.LocalAddr().String() || !bytes.Equal(buf[:n], reply) {
					t.Fatal("return", peer, e)
				}
				totalDown += uint64(len(reply))
				time.Sleep(65 * time.Millisecond)
			}
			// NEVER wrote to c. Different peer's large datagram must retain its source;
			// this also exercises v4/v6 MTU fragmentation + OS-stack reassembly.
			unsolicited := bytes.Repeat([]byte{77}, 3001)
			if _, e := c.WriteToUDPAddrPort(unsolicited, external); e != nil {
				t.Fatal(e)
			}
			buf := make([]byte, 4000)
			_ = inner.SetReadDeadline(time.Now().Add(time.Second))
			n, peer, e := inner.ReadFrom(buf)
			if e != nil || peer.String() != c.LocalAddr().String() || !bytes.Equal(buf[:n], unsolicited) {
				t.Fatal("EIF/reassembly", n, peer, e)
			}
			totalDown += uint64(n)
			waitFor(t, func() bool { _, ok := records.terminal(); return ok })
			end, _ := records.terminal()
			if end.Target != "udp-association" || end.DestIP != "" || end.UDPAssociation == nil || !end.UDPAssociation.Shared || !end.UDPAssociation.UnmatchedPeer || end.UDPAssociation.ReplyPeer != c.LocalAddr().String() {
				t.Fatalf("unsolicited peer attributed to a visited target: %+v", end)
			}
			records.mu.Lock()
			found := false
			for _, event := range records.events {
				if event.Code == "udp_eif_reply" && event.Target == c.LocalAddr().String() {
					found = true
				}
			}
			records.mu.Unlock()
			if !found {
				t.Fatal("no truthful EIF peer record")
			}
			if end.Up != totalUp || end.Down != totalDown || end.UDPAssociation == nil || end.UDPAssociation.ID == "" || len(end.UDPAssociation.LocalEndpoints) == 0 {
				t.Fatalf("single meter/metadata %+v", end)
			}
			snap := s.reg.Snapshot()
			if snap.Total.Up != totalUp || snap.Total.Down != totalDown {
				t.Fatalf("double count %+v", snap.Total)
			}
		})
	}
}
func TestStage4PolicyAndPhysicalEpochIsolation(t *testing.T) {
	a, b := stage4Socket(t, "udp4", c50LocalIP(t, false)), stage4Socket(t, "udp4", c50LocalIP(t, false))
	var epoch atomic.Uint64
	epoch.Store(1)
	var records c49DNSRecords
	s := c50Server(t, &records, func(cfg *Config) {
		cfg.Security = &SecurityOptions{AllowLoopback: true}
		cfg.Routing = &RoutingOptions{Rules: []RouteRule{{DstPort: strconv.Itoa(b.LocalAddr().(*net.UDPAddr).Port), Action: "direct"}}, Final: "direct"}
		cfg.SetClientEgress(&ClientEgress{UDPBinding: func(bool) (uint64, string, error) { return epoch.Load(), "owner:14/4/2", nil }})
	})
	p := c50Link(t, c50Ingress(t, s), func() bool { return true }, func() uint64 { return 112 })
	inner := stage4UDP(t, p, false)
	send := func(sock *net.UDPConn) netip.AddrPort {
		_, e := inner.WriteTo([]byte("x"), sock.LocalAddr())
		if e != nil {
			t.Fatal(e)
		}
		_ = sock.SetReadDeadline(time.Now().Add(time.Second))
		_, ap, e := sock.ReadFromUDPAddrPort(make([]byte, 8))
		if e != nil {
			t.Fatal(e)
		}
		return ap
	}
	ap, bp := send(a), send(b)
	if ap == bp {
		t.Fatal("cross policy shared")
	}
	if again := send(a); again != ap {
		t.Fatal("same policy not reused")
	}
	epoch.Store(2)
	if send(a) == ap {
		t.Fatal("new physical epoch reused")
	}
}
func TestStage4SecurityEpochDiscardsOldAssociationReply(t *testing.T) {
	a, c := stage4Socket(t, "udp4", c50LocalIP(t, false)), stage4Socket(t, "udp4", c50LocalIP(t, false))
	var epoch atomic.Uint64
	epoch.Store(1)
	s := c50Server(t, nil, func(cfg *Config) { cfg.Security = &SecurityOptions{AllowLoopback: true} })
	p := c50Link(t, c50Ingress(t, s), func() bool { return true }, epoch.Load)
	inner := stage4UDP(t, p, false)
	_, _ = inner.WriteTo([]byte("x"), a.LocalAddr())
	_ = a.SetReadDeadline(time.Now().Add(time.Second))
	_, old, e := a.ReadFromUDPAddrPort(make([]byte, 8))
	if e != nil {
		t.Fatal(e)
	}
	epoch.Store(2)
	_, _ = inner.WriteTo([]byte("x"), a.LocalAddr())
	_, fresh, e := a.ReadFromUDPAddrPort(make([]byte, 8))
	if e != nil || fresh == old {
		t.Fatal("new source epoch reused", e)
	}
	_, _ = c.WriteToUDPAddrPort([]byte("old"), old)
	_ = inner.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, e = inner.ReadFrom(make([]byte, 8)); e == nil {
		t.Fatal("old association injected into new source")
	}
	_, _ = c.WriteToUDPAddrPort([]byte("new"), fresh)
	_ = inner.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 8)
	n, _, e := inner.ReadFrom(buf)
	if e != nil || string(buf[:n]) != "new" {
		t.Fatal("new association failed", e)
	}
}

var _ = context.Background
