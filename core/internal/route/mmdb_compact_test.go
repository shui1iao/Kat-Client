package route

import (
	"net"
	"net/netip"
	"testing"
)

func TestMMDBTableCoalesceAndBoundaries(t *testing.T) {
	var tbl mmdbTable
	// Adjacent IPv4 ranges with identical values coalesce; different values stay distinct.
	for _, item := range []struct {
		cidr string
		val  uint32
	}{
		{"1.0.1.0/24", 1},
		{"1.0.2.0/24", 1},
		{"1.0.3.0/24", 1},
		{"1.0.4.0/24", 2},
		{"255.255.255.255/32", 9},
		{"0.0.0.0/32", 7},
		{"2001:db8:1::/48", 11},
		{"2001:db8:2::/48", 11},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", 12},
	} {
		_, nw, err := net.ParseCIDR(item.cidr)
		if err != nil {
			t.Fatal(err)
		}
		tbl.addNet(nw, item.val)
	}
	tbl.finalize()
	if len(tbl.v4) != 4 {
		t.Fatalf("expected 4 coalesced v4 ranges, got %d: %+v", len(tbl.v4), tbl.v4)
	}
	if len(tbl.v6) != 2 {
		t.Fatalf("expected 2 coalesced v6 ranges, got %d: %+v", len(tbl.v6), tbl.v6)
	}
	for _, tc := range []struct {
		ip   string
		want uint32
	}{
		{"0.0.0.0", 7},
		{"0.0.0.1", 0},
		{"1.0.0.255", 0},
		{"1.0.1.0", 1},
		{"1.0.2.99", 1},
		{"1.0.3.255", 1},
		{"::ffff:1.0.2.42", 1},
		{"1.0.4.1", 2},
		{"255.255.255.255", 9},
		{"2001:db8:1::1", 11},
		{"2001:db8:2::ffff", 11},
		{"2001:db8:3::1", 0},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 12},
	} {
		if got := tbl.lookup(netip.MustParseAddr(tc.ip)); got != tc.want {
			t.Fatalf("lookup(%s) = %d, want %d", tc.ip, got, tc.want)
		}
	}
}

func TestParseGeoIPAndGeositePruned(t *testing.T) {
	db, err := parseGeoIP(testMMDB(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := db.country(netip.MustParseAddr("1.0.1.9")); got != "CN" {
		t.Fatalf("1.0.1.9 -> %q, want CN", got)
	}
	if got := db.country(netip.MustParseAddr("::ffff:1.0.1.9")); got != "CN" {
		t.Fatalf("::ffff:1.0.1.9 -> %q, want CN", got)
	}
	gs, err := parseGeositeDBForRefs(testGeosite(), []string{"google@cn"})
	if err != nil {
		t.Fatal(err)
	}
	if gs.index != nil {
		t.Fatal("expected pruned geosite index to be nil")
	}
	if gs.categories == 0 {
		t.Fatal("expected non-zero category count")
	}
	if !gs.matcher("google@cn").dom.match("www.google.cn") {
		t.Fatal("expected precompiled google@cn to match")
	}
}
