package kernel

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestReviewUDPUsesAuthorizedCandidateWithoutSecondLookup(t *testing.T) {
	ctx := context.Background()
	c, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	aPort := c.LocalAddr().(*net.UDPAddr).AddrPort()
	pc, e := direct.New(direct.Options{Resolve: func(context.Context, string) ([]netip.Addr, error) {
		t.Error("unexpected unpinned DNS lookup")
		return nil, net.ErrClosed
	}}).ListenPacket(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	s := &Server{core: &core{}}
	s.cfg.Limits.DialTimeout = Duration(time.Second)
	a := &udpAssociation{ctx: ctx, server: s, proxies: map[string]*proxySession{"direct": {name: "direct", pc: clientDirectPacket{pc}, chain: []string{"direct"}}}}
	d := Address{"node.test", aPort.Port()}
	a.sendProxy("direct", d, []byte("ok"), d, 0, []netip.AddrPort{aPort})
	c.SetReadDeadline(time.Now().Add(time.Second))
	var b [8]byte
	n, _, e := c.ReadFrom(b[:])
	if e != nil || string(b[:n]) != "ok" {
		t.Fatalf("approved address not reached: %v", e)
	}
}
func TestReviewOnlyOwnedCarrierEndpointRefused(t *testing.T) {
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	s := &Server{listeners: []net.Listener{l}}
	port := l.Addr().(*net.TCPAddr).AddrPort().Port()
	c0 := context.Background()
	a := netip.MustParseAddr("127.0.0.1")
	other := netip.MustParseAddr("127.0.0.2")
	if s.blockOwnCarrier(c0, netip.AddrPortFrom(a, port)) {
		t.Fatal("regular traffic treated as carrier")
	}
	called := 0
	probeErr := errors.New("fake dial")
	d := direct.New(direct.Options{BlockTCP: s.blockOwnCarrier, Resolve: func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{a, other}, nil }, DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
		called++
		if addr != netip.AddrPortFrom(other, port).String() {
			t.Errorf("unexpected dial %s", addr)
		}
		return nil, probeErr
	}})
	_, e = (underlay{d}).DialTCP(c0, outbound.Addr{Host: "local.test", Port: port})
	if !errors.Is(e, probeErr) || called != 1 {
		t.Fatal(e, called)
	}
}
func TestReviewQUICTargetConnectionIdentity(t *testing.T) {
	now := time.Now()
	peer := Address{"192.0.2.1", 443}
	first := &udpSniffState{key: quicConnectionID{1, "aaaa", "s1"}, last: now, res: &sniffResult{host: "a.example"}}
	other := &udpSniffState{key: quicConnectionID{1, "bbbb", "s2"}, last: now, res: &sniffResult{host: "b.example"}}
	u := udpSniffer{targets: map[Address][]*udpSniffState{peer: {first, other}}, count: 2}
	cid, v := quicIDs([]byte{0xc0, 0, 0, 0, 1, 4, 'c', 'c', 'c', 'c', 2, 's', '3'})
	if !v || u.connection(peer, nil, cid, true, true, now, time.Minute) != nil {
		t.Fatal("new Initial inherited a peer's prior SNI")
	}
	next := quicConnectionID{1, "zzzz", "s2"}
	if u.connection(peer, nil, next, true, false, now, time.Minute) != other || u.connection(peer, []byte("@zzzz-data"), quicConnectionID{}, false, false, now, time.Minute) != other {
		t.Fatal("same connection not attributed")
	}
	first.serverCID = other.serverCID
	if u.connection(peer, []byte("@zzzz-data"), quicConnectionID{}, false, false, now, time.Minute) != nil {
		t.Fatal("ambiguous short header inherited SNI")
	}
	if u.connection(peer, []byte("plain-udp"), quicConnectionID{}, false, false, now, time.Minute) != nil {
		t.Fatal("non-QUIC inherited SNI")
	}
}
