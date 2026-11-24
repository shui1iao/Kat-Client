package route

import (
	"net"
	"net/netip"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

// privateSet is the built-in "private" geoip class (no database needed):
// unspecified/this-network, RFC 1918, CGNAT, loopback, link-local, IETF
// protocol assignments, documentation and benchmarking nets, multicast,
// reserved/broadcast; IPv6 unspecified, loopback, ULA, link-local, multicast
// and documentation.
var privateSet = func() ipSet {
	var s ipSet
	for _, c := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
	} {
		s.add(netip.MustParsePrefix(c))
	}
	s.build()
	return s
}()

func isPrivate(ip netip.Addr) bool { return privateSet.contains(ip) }

type geoDB struct {
	table mmdbTable
	codes []string // 1-based index -> upper-case ISO code
}

type geoRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

// parseGeoIP opens an in-memory MaxMind DB, sanity-checks it with probe
// lookups, and compacts all networks into a pointer-free range table so the
// raw MMDB bytes (and multi-language metadata) can be reclaimed immediately.
func parseGeoIP(b []byte) (db *geoDB, err error) {
	defer func() {
		if recover() != nil {
			db, err = nil, errParse
		}
	}()
	r, e := maxminddb.FromBytes(b)
	if e != nil || r.Metadata.NodeCount == 0 || r.Metadata.IPVersion != 4 && r.Metadata.IPVersion != 6 {
		return nil, errParse
	}
	defer r.Close()
	probes := []string{"1.1.1.1", "8.8.8.8", "223.5.5.5"}
	if r.Metadata.IPVersion == 6 {
		probes = append(probes, "2001:4860:4860::8888", "2400:3200::1")
	}
	for _, p := range probes {
		var rec geoRecord
		if r.Lookup(net.ParseIP(p), &rec) != nil {
			return nil, errParse
		}
	}
	out := &geoDB{}
	codeIdx := make(map[string]uint32, 256)
	it := r.Networks(maxminddb.SkipAliasedNetworks)
	for it.Next() {
		var rec geoRecord
		nw, e := it.Network(&rec)
		if e != nil {
			return nil, errParse
		}
		c := rec.Country.ISOCode
		if c == "" {
			c = rec.RegisteredCountry.ISOCode
		}
		if c == "" {
			continue
		}
		c = strings.ToUpper(c)
		idx, ok := codeIdx[c]
		if !ok {
			out.codes = append(out.codes, c)
			idx = uint32(len(out.codes))
			codeIdx[c] = idx
		}
		out.table.addNet(nw, idx)
	}
	if it.Err() != nil {
		return nil, errParse
	}
	out.table.finalize()
	return out, nil
}

// country returns the upper-case ISO code from country.iso_code, falling back
// to registered_country.iso_code; "" when unknown.
func (g *geoDB) country(ip netip.Addr) string {
	if g == nil {
		return ""
	}
	idx := g.table.lookup(ip)
	if idx == 0 || int(idx) > len(g.codes) {
		return ""
	}
	return g.codes[idx-1]
}
