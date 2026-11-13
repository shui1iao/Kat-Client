package clientegress

import (
	"context"
	"net/netip"
	"testing"
)

func TestReleaseICMPPhysicalPreflightRejects(t *testing.T) {
	ctx := context.Background()
	for _, dst := range []netip.Addr{{}, netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("224.0.0.1"), netip.MustParseAddr("fe80::1%4")} {
		s := &Switch{}
		if _, _, e := s.PingPhysical(ctx, dst, 41, 0, false, []byte("test")); e == nil {
			t.Fatal("invalid destination accepted", dst)
		}
	}
	dst := netip.MustParseAddr("203.0.113.50")
	snap := EgressSnapshot{Generation: 1, Epoch: 1, Options: fixtureOptions(), Owners: []OwnerState{ownerFixture()}}
	for _, s := range []*Switch{{}, {frozen: true, snapshot: &snap}, {snapshot: &snap, current: Blocked()}} {
		if _, _, e := s.PingPhysical(ctx, dst, 41, 0, false, nil); e == nil || e.Error() != "physical egress unavailable" {
			t.Fatal("unproven physical egress accepted", e)
		}
	}
	s := &Switch{snapshot: &snap, ipv6Set: true, ipv6Enabled: false}
	if _, _, e := s.PingPhysical(ctx, netip.MustParseAddr("2001:db8::50"), 41, 0, false, nil); e == nil || e.Error() != "IPv6 disabled" {
		t.Fatal("disabled IPv6 accepted", e)
	}
}
