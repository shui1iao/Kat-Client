package clientegress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

type proofConn struct {
	closed int
	source string
}

func (c *proofConn) Read([]byte) (int, error)         { return 0, errors.New("unused") }
func (c *proofConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *proofConn) Close() error                     { c.closed++; return nil }
func (c *proofConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.ParseIP(c.source), Port: 7} }
func (c *proofConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *proofConn) SetDeadline(time.Time) error      { return nil }
func (c *proofConn) SetReadDeadline(time.Time) error  { return nil }
func (c *proofConn) SetWriteDeadline(time.Time) error { return nil }
func ownerFixture() OwnerState {
	return OwnerState{LUID: 14, IfIndex: 4, Family: 2, Up: true, Safe: true, Sources: []SourceState{{Address: netip.MustParseAddr("192.0.2.9"), Usable: true}, {Address: netip.MustParseAddr("192.0.2.10"), Usable: true}}}
}
func TestR05OnlyActuallyDeletedSourceRetires(t *testing.T) {
	o := ownerFixture()
	a, b := &proofConn{source: "192.0.2.9"}, &proofConn{source: "192.0.2.10"}
	s := &Switch{sockets: map[net.Conn]bool{a: true, b: true}, owners: map[net.Conn]SocketOwner{a: {Epoch: 1, LUID: 14, IfIndex: 4, Family: 2, Source: netip.MustParseAddr(a.source)}, b: {Epoch: 1, LUID: 14, IfIndex: 4, Family: 2, Source: netip.MustParseAddr(b.source)}}}
	next := EgressSnapshot{Generation: 1, Epoch: 1, Options: fixtureOptions(), Owners: []OwnerState{o}}
	if e := s.installSnapshot(next, nil); e != nil {
		t.Fatal(e)
	}
	next.Generation++
	next.Options.AddressDigest = "new unrelated temporary IPv6 address"
	next.Options.MetricDigest = "changed"
	next.Options.DNS[0], next.Options.DNS[1] = next.Options.DNS[1], next.Options.DNS[0]
	next.Owners[0].Sources = append(next.Owners[0].Sources, SourceState{Address: netip.MustParseAddr("192.0.2.11"), Usable: true})
	s.installSnapshot(next, nil)
	if a.closed+b.closed != 0 {
		t.Fatal("unrelated update killed sockets")
	}
	next.Generation++
	next.Owners[0].Sources = next.Owners[0].Sources[1:]
	s.installSnapshot(next, nil)
	if a.closed != 1 || b.closed != 0 {
		t.Fatal("source deletion not exact", a.closed, b.closed)
	}
	next.Generation++
	next.Owners[0].Safe = false
	s.installSnapshot(next, nil)
	if b.closed != 1 {
		t.Fatal("unsafe bound flow not retired")
	}
}
func TestR05OwnerSwitchEpochKeepsProvenSafeOldFlow(t *testing.T) {
	o := ownerFixture()
	c := &proofConn{source: "192.0.2.9"}
	proof := SocketOwner{Epoch: 7, LUID: 14, IfIndex: 4, Family: 2, Source: netip.MustParseAddr(c.source)}
	s := &Switch{sockets: map[net.Conn]bool{c: true}, owners: map[net.Conn]SocketOwner{c: proof}}
	opts := fixtureOptions()
	newOwner := o
	newOwner.LUID = 99
	newOwner.IfIndex = 19
	opts.LUID4 = &newOwner.LUID
	opts.IPv4 = &newOwner.IfIndex
	next := EgressSnapshot{Generation: 2, Epoch: 8, Options: opts, Owners: []OwnerState{o, newOwner}}
	s.installSnapshot(next, nil)
	if c.closed != 0 || s.owners[c].Epoch != 7 || s.epoch != 8 {
		t.Fatal("old safe flow migrated/killed or epoch unchanged")
	}
	if e := s.installSnapshot(EgressSnapshot{Generation: 1, Epoch: 9}, nil); e == nil || c.closed != 0 {
		t.Fatal("stale observation accepted")
	}
	s.RetireObserved([]OwnerState{newOwner})
	if c.closed != 1 {
		t.Fatal("owner loss did not retire")
	}
}
func TestR05PacketSourceResolvesBeforeBindAndRefusesWildcardProof(t *testing.T) {
	o := ownerFixture()
	snap := EgressSnapshot{Generation: 1, Epoch: 1, Options: fixtureOptions(), Owners: []OwnerState{o}}
	s := &Switch{snapshot: &snap}
	ip, e := s.PacketSource("udp4", netip.IPv4Unspecified())
	if e != nil || ip.String() != "192.0.2.9" {
		t.Fatal(ip, e)
	}
	if _, e = s.PacketSource("udp4", netip.MustParseAddr("198.51.100.1")); e == nil {
		t.Fatal("foreign configured source adopted")
	}
	if e = confirmLocal(SocketOwner{Source: ip, IfIndex: 4}, &net.UDPAddr{IP: net.IPv4zero}); e == nil {
		t.Fatal("wildcard counted as source")
	}
	s.FreezeNew()
	if _, e = s.PacketSource("udp4", netip.Addr{}); e == nil {
		t.Fatal("new socket admitted during fence")
	}
}
func TestDNSCandidateScopeAndRetainedRevisionCancellation(t *testing.T) {
	p := fixturePolicy(t, func(string, syscall.RawConn) error { return nil })
	ctx, cancel, _ := p.DNSContext(context.Background())
	defer cancel()
	old := p.dns.Load()
	opts := p.Options.Clone()
	opts.DNS[1] = DNSEndpoint{Address: "fe80::1", Owner: 16, IfIndex: 6, Scope: 6}
	p.installDNS(opts, 2)
	if old.life.Err() == nil {
		t.Fatal("old revision not fenced")
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("old query not canceled")
	}
	got, _ := p.DNSSnapshot()
	if got.DNS[1].socket() != "[fe80::1%6]:53" {
		t.Fatal(got.DNS[1])
	}
	bad := opts.Clone()
	bad.DNS[1].Scope = 4
	if _, e := newPolicy(bad, p.bind, nil); e == nil {
		t.Fatal("wrong scope accepted")
	}
}

func TestReleasePhysicalRestoresOrdinaryProxyWithoutKillingOldSockets(t *testing.T) {
	c := &proofConn{}
	s := &Switch{current: Blocked(), frozen: true, sockets: map[net.Conn]bool{c: true}}
	s.ReleasePhysical()
	if s.Enabled() || s.frozen || c.closed != 0 {
		t.Fatal("TUN off stranded or killed ordinary proxy")
	}
	ip, e := s.PacketSource("udp4", netip.IPv4Unspecified())
	if e != nil || !ip.IsUnspecified() {
		t.Fatal(ip, e)
	}
}
