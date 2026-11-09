package direct

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestM2EIFInboxByteBudgetAndDrain(t *testing.T) {
	pc, e := New(Options{DisableIPv6: true}).ListenPacket(outbound.WithEndpointIndependent(context.Background(), true))
	if e != nil {
		t.Fatal(e)
	}
	p := pc.(*packetConn)
	defer p.Close()
	peer := netip.MustParseAddrPort("192.0.2.1:4444")
	payload := make([]byte, 65507)
	for i := 0; i < 4; i++ {
		if !p.enqueue(payload, peer) {
			t.Fatal("under-budget datagram dropped")
		}
	}
	if p.enqueue(payload, peer) {
		t.Fatal("large-payload budget bypassed")
	}
	if _, _, e := p.ReadFrom(make([]byte, 65535)); e != nil {
		t.Fatal(e)
	}
	if !p.enqueue(payload, peer) {
		t.Fatal("read did not release payload quota")
	}
	p.Close()
	p.mu.Lock()
	n := p.queuedBytes
	p.mu.Unlock()
	if n != 0 {
		t.Fatal("close retained payload", n)
	}
}
func TestM2EIFDoesNotBypassPerPacketGuard(t *testing.T) {
	var calls atomic.Int64
	peer, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	d := New(Options{DisableIPv6: true, Guard: func(_ context.Context, ip netip.Addr) bool { calls.Add(1); return !ip.IsLoopback() }})
	p, e := d.ListenPacket(outbound.WithEndpointIndependent(context.Background(), true))
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	ap := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	if _, e = p.WriteTo([]byte("x"), outbound.Addr{Host: ap.Addr().String(), Port: ap.Port()}); e != nil {
		t.Fatal(e)
	}
	if n, e := p.WriteTo([]byte("blocked"), outbound.Addr{Host: "192.0.2.1", Port: 4444}); n != 0 || !errors.Is(e, ErrBlocked) {
		t.Fatal("Guard bypass", n, e)
	}
	if calls.Load() != 2 {
		t.Fatal("Guard not checked per target")
	}
}
func TestM2EIFPhysicalCreateCloseJoin(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releases atomic.Int64
	d := New(Options{DisableIPv6: true, PacketSource: func(string, netip.Addr) (netip.Addr, error) {
		close(entered)
		<-release
		return netip.MustParseAddr("127.0.0.1"), nil
	}, PacketControl: func(string, *net.UDPConn) error { return nil }, PacketRelease: func(*net.UDPConn) { releases.Add(1) }})
	pc, e := d.ListenPacket(outbound.WithEndpointIndependent(context.Background(), true))
	if e != nil {
		t.Fatal(e)
	}
	p := pc.(*packetConn)
	if !p.v4.LocalAddr().(*net.UDPAddr).AddrPort().Addr().IsLoopback() {
		t.Fatal("controlled EIF exposed an unused wildcard socket")
	}
	created, closed := make(chan error, 1), make(chan error, 1)
	go func() { _, e := p.remoteSocket(false); created <- e }()
	<-entered
	go func() { closed <- p.Close() }()
	close(release)
	select {
	case e := <-created:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("creation stuck")
	}
	select {
	case e := <-closed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not join")
	}
	if releases.Load() != 1 {
		t.Fatal("physical socket release owner", releases.Load())
	}
	if _, e := p.remoteSocket(false); !errors.Is(e, net.ErrClosed) {
		t.Fatal("session created after close", e)
	}
}

func TestM2IPv4OnlyPhysicalDomainSkipsIPv6CandidateWithoutFailingPolicy(t *testing.T) {
	var failures atomic.Int64
	d := New(Options{
		Resolve: func(_ context.Context, _ string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("127.0.0.1")}, nil
		},
		PacketSource: func(network string, _ netip.Addr) (netip.Addr, error) {
			if network == "udp6" {
				return netip.Addr{}, errors.New("physical family unavailable")
			}
			return netip.MustParseAddr("127.0.0.1"), nil
		},
		PacketControl: func(string, *net.UDPConn) error { return nil },
		PacketFailure: func() { failures.Add(1) },
	})
	pc, e := d.ListenPacket(outbound.WithEndpointIndependent(context.Background(), true))
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	// Direct literal IPv6 when physical IPv6 is absent must fail without poisoning PacketFailure.
	if _, e = pc.WriteTo([]byte("v6"), outbound.Addr{Host: "2001:db8::1", Port: 53}); e == nil {
		t.Fatal("expected missing physical IPv6 error")
	}
	if failures.Load() != 0 {
		t.Fatalf("missing physical IPv6 poisoned egress policy: %d", failures.Load())
	}
	// Dual-stack domain with IPv6 first must skip unavailable IPv6 and succeed via IPv4 candidate.
	peer, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	port := uint16(peer.LocalAddr().(*net.UDPAddr).Port)
	if _, e = pc.WriteTo([]byte("ok"), outbound.Addr{Host: "dual.example", Port: port}); e != nil {
		t.Fatal("dual-stack fallback failed:", e)
	}
	if failures.Load() != 0 {
		t.Fatalf("unexpected PacketFailure count: %d", failures.Load())
	}
}
