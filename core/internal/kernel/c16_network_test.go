package kernel

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func k2Context() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 2*time.Second)
}
func TestK2DNSPolicyHostsAndClear(t *testing.T) {
	a := newDNSFixture(t, func(w []byte) []byte { return dnsReply(w, []string{"192.0.2.1", "2001:db8::1"}, 60) })
	b := newDNSFixture(t, func(w []byte) []byte { return dnsReply(w, []string{"192.0.2.2"}, 60) })
	cap := 16
	r, e := newInternalDNS(&DNSOptions{Servers: []string{b.address()}, CacheEntries: &cap, Rules: []DNSRule{{"keyword", "example", []string{a.address()}}, {"domain", "a.example.com", []string{b.address()}}}, Hosts: DNSHosts{"*.local.test": {"192.0.2.3", "2001:db8::3"}, "exact.local.test": {"192.0.2.4"}}})
	if e != nil {
		t.Fatal(e)
	}
	defer r.close()
	r.configureIO(true, net.DefaultResolver.LookupNetIP, (&net.Dialer{}).DialContext, nil)
	ctx, cancel := k2Context()
	defer cancel()
	ips, _, _, e := r.lookupAnswer(ctx, "a.example.com")
	if e != nil || len(ips) != 1 || ips[0].String() != "192.0.2.1" || a.count.Load() != 1 || b.count.Load() != 0 {
		t.Fatal(ips, e, a.count.Load(), b.count.Load())
	}
	_, _, hit, e := r.lookupAnswer(ctx, "a.example.com")
	if e != nil || !hit {
		t.Fatal(hit, e)
	}
	for name, want := range map[string]string{"a.local.test": "192.0.2.3", "exact.local.test": "192.0.2.4"} {
		ips, e = r.lookup(ctx, name)
		if e != nil || len(ips) != 1 || ips[0].String() != want {
			t.Fatal(name, ips, e)
		}
	}
	if _, ok := r.host("local.test"); ok {
		t.Fatal("wildcard matched apex")
	}
	if n := r.clearCache(); n != 1 {
		t.Fatal("clear count", n)
	}
	if n := r.clearCache(); n != 0 {
		t.Fatal(n)
	}
	_, _, hit, e = r.lookupAnswer(ctx, "a.example.com")
	if e != nil || hit || a.count.Load() != 2 {
		t.Fatal(hit, e, a.count.Load())
	}
}
func TestK2NoAAAAAndBootstrapFamily(t *testing.T) {
	var aaaa atomic.Int64
	f := newDNSFixture(t, func(w []byte) []byte {
		var q dnsmessage.Message
		_ = q.Unpack(w)
		if q.Questions[0].Type == dnsmessage.TypeAAAA {
			aaaa.Add(1)
		}
		return dnsReply(w, []string{"192.0.2.1", "2001:db8::1"}, 30)
	})
	for _, enabled := range []bool{false, true} {
		r, e := newInternalDNS(&DNSOptions{Servers: []string{f.address()}})
		if e != nil {
			t.Fatal(e)
		}
		r.configureIO(!enabled, net.DefaultResolver.LookupNetIP, (&net.Dialer{}).DialContext, nil)
		ctx, cancel := k2Context()
		ips, e := r.lookup(ctx, "a.example")
		cancel()
		r.close()
		if e != nil || len(ips) != map[bool]int{false: 1, true: 2}[enabled] {
			t.Fatal(enabled, ips, e)
		}
	}
	if aaaa.Load() != 1 {
		t.Fatal("AAAA count", aaaa.Load())
	}
	r, _ := newInternalDNS(&DNSOptions{Server: "system"})
	r.configureIO(true, func(_ context.Context, n, h string) ([]netip.Addr, error) {
		if n != "ip4" {
			t.Fatal(n)
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}, nil
	}, nil, nil)
	ctx, cancel := k2Context()
	defer cancel()
	ips, e := r.lookup(ctx, "a.example")
	if e != nil || len(ips) != 1 || !ips[0].Is4() {
		t.Fatal(ips, e)
	}
}
func TestK2GatewayWireSemanticsAndTCP(t *testing.T) {
	f := newDNSFixture(t, func(w []byte) []byte {
		var m dnsmessage.Message
		_ = m.Unpack(w)
		q := m.Questions[0]
		m.Response = true
		m.RecursionAvailable = true
		if strings.HasPrefix(q.Name.String(), "nx.") {
			m.RCode = dnsmessage.RCodeNameError
		} else if q.Type == dnsmessage.TypeTXT {
			m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: q.Type, Class: q.Class, TTL: 29}, Body: &dnsmessage.TXTResource{TXT: []string{"retained"}}}}
		} else {
			alias, _ := dnsmessage.NewName("alias.test.")
			m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeCNAME, Class: q.Class, TTL: 27}, Body: &dnsmessage.CNAMEResource{CNAME: alias}}}
			ip := netip.MustParseAddr("192.0.2.8")
			if q.Type == dnsmessage.TypeA {
				m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: alias, Type: q.Type, Class: q.Class, TTL: 31}, Body: &dnsmessage.AResource{A: ip.As4()}})
			} else {
				m.Answers = append(m.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: alias, Type: q.Type, Class: q.Class, TTL: 31}, Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::8").As16()}})
			}
		}
		b, _ := m.Pack()
		return b
	})
	for _, enabled := range []bool{false, true} {
		c, e := DecodeConfig([]byte(`{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"}],"dns":{"servers":["` + f.address() + `"]}}`))
		if e != nil {
			t.Fatal(e)
		}
		c.SetClientIPv6(enabled)
		c.SetClientEgress(&ClientEgress{Bootstrap: net.DefaultResolver.LookupNetIP})
		s, e := Start(c)
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := k2Context()
		p, e := proxy.SOCKS5("tcp", s.Addresses()[0].String(), nil, proxy.Direct)
		if e != nil {
			t.Fatal(e)
		}
		conn, e := p.(proxy.ContextDialer).DialContext(ctx, "tcp", "192.0.2.53:53")
		if e != nil {
			t.Fatal(e)
		}
		conn.SetDeadline(time.Now().Add(time.Second))
		for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypeTXT} {
			wire, _, _ := dnsQuestion("wire.test", typ)
			n := f.count.Load()
			out := binary.BigEndian.AppendUint16(nil, uint16(len(wire)))
			out = append(out, wire...)
			if _, e = conn.Write(out); e != nil {
				t.Fatal(e)
			}
			var size [2]byte
			if _, e = io.ReadFull(conn, size[:]); e != nil {
				t.Fatal(e)
			}
			reply := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, e = io.ReadFull(conn, reply); e != nil {
				t.Fatal(e)
			}
			var m dnsmessage.Message
			if m.Unpack(reply) != nil || !m.Response || m.ID != binary.BigEndian.Uint16(wire[:2]) || m.RCode != dnsmessage.RCodeSuccess {
				t.Fatal(m)
			}
			if typ == dnsmessage.TypeAAAA && !enabled {
				if len(m.Answers) != 0 || f.count.Load() != n {
					t.Fatal("AAAA must be NOERROR/NODATA, no upstream")
				}
			} else if len(m.Answers) == 0 {
				t.Fatal("A/AAAA/TXT missing")
			}
			if typ == dnsmessage.TypeA {
				if _, ok := m.Answers[0].Body.(*dnsmessage.CNAMEResource); !ok || m.Answers[0].Header.TTL != 27 {
					t.Fatal("CNAME/TTL lost", m)
				}
			}
			// Actual association send path used by tun2socks UDP, not just resolver.
			var got []byte
			a := &udpAssociation{server: s.current(), ctx: ctx, writeBack: func(_ Address, b []byte) error { got = append([]byte(nil), b...); return nil }}
			a.send(ctx, packet{target: Address{"192.0.2.53", 53}, payload: wire}, time.Second)
			if len(got) == 0 {
				t.Fatal("UDP gate did not answer")
			}
		}
		wire, _, _ := dnsQuestion("nx.test", dnsmessage.TypeA)
		b, e := s.current().dns.gateway(ctx, wire, false)
		var m dnsmessage.Message
		_ = m.Unpack(b)
		if e != nil || m.RCode != dnsmessage.RCodeNameError {
			t.Fatal(m, e)
		}
		conn.Close()
		cancel()
		closeCtx, stop := k2Context()
		if e = s.Close(closeCtx); e != nil {
			t.Fatal(e)
		}
		stop()
	}
}
func TestK2RejectIPv6AndRetireOldGeneration(t *testing.T) {
	c, _ := DecodeConfig([]byte(`{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"}],"dns":{"server":"system"}}`))
	c.SetClientIPv6(false)
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { ctx, cancel := k2Context(); defer cancel(); s.Close(ctx) }()
	ctx, cancel := k2Context()
	defer cancel()
	_, e = s.current().dial(ctx, Address{"2001:db8::1", 443})
	if !errors.Is(e, direct.ErrIPv6Disabled) {
		t.Fatal(e)
	}
	_, _, _, _, e = s.current().routeUDP(ctx, Address{"2001:db8::1", 443}, netip.Addr{})
	if !errors.Is(e, direct.ErrIPv6Disabled) {
		t.Fatal(e)
	}
	old := s.current()
	c.SetClientIPv6(true)
	if _, e = s.ApplyConfig(c); e != nil {
		t.Fatal(e)
	}
	if old.clientLife.Err() == nil {
		t.Fatal("old traffic context survived IPv6 transition")
	}
	if s.current().cfg.IPv6Disabled() {
		t.Fatal("enable lost")
	}
}
func TestK2MihomoOrderedImport(t *testing.T) {
	raw := []byte(`{"+.example.com":["1.1.1.1","tcp://8.8.8.8"],"exact.test":"1.0.0.1","internal.test":"9.9.9.9"}`)
	rules, e := DecodeMihomoDNSPolicy(raw)
	if e != nil || len(rules) != 3 || rules[0].Match != "domain_suffix" {
		t.Fatal(rules, e)
	}
	for _, bad := range []string{`{"keyword:internal":"1.1.1.1"}`, `{"full:exact.test":"1.1.1.1"}`, `{"geosite:cn":"1.1.1.1"}`, `{"x":"system"}`, `{"x":"1.1.1.1","x":"8.8.8.8"}`} {
		if _, e := DecodeMihomoDNSPolicy([]byte(bad)); e == nil {
			t.Fatal(bad)
		}
	}
	c, e := DecodeConfig([]byte(`{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"}],"dns":{"server":"system","nameserver-policy":{"+.example.com":"1.1.1.1"},"hosts":{"*.example.com":["192.0.2.1","2001:db8::1"],"exact.test":"192.0.2.2"}}}`))
	if e != nil {
		t.Fatal(e)
	}
	if len(c.DNS.Hosts["exact.test"]) != 1 {
		t.Fatal(c.DNS)
	}
}

func TestK2GatewayTruncationCacheAndHosts(t *testing.T) {
	var calls atomic.Int64
	f := newDNSFixture(t, func(w []byte) []byte {
		n := calls.Add(1)
		b := dnsReply(w, []string{"192.0.2.9"}, 60)
		if n == 1 {
			var m dnsmessage.Message
			_ = m.Unpack(b)
			m.Truncated = true
			m.Answers = nil
			b, _ = m.Pack()
			binary.BigEndian.PutUint16(b[6:8], 1)
		} // deliberately incomplete TC UDP body
		return b
	})
	cap := 16
	r, e := newInternalDNS(&DNSOptions{Servers: []string{f.address()}, CacheEntries: &cap, Hosts: DNSHosts{"*.hosts.test.": {"0.0.0.0", "2001:db8::3"}, "EXACT.hosts.test": {"192.0.2.4"}}})
	if e != nil {
		t.Fatal(e)
	}
	defer r.close()
	r.configureIO(true, net.DefaultResolver.LookupNetIP, (&net.Dialer{}).DialContext, nil)
	ctx, cancel := k2Context()
	defer cancel()
	wire, _, _ := dnsQuestion("tc.test", dnsmessage.TypeA)
	b, e := r.gateway(ctx, wire, false)
	var m dnsmessage.Message
	if m.Unpack(b) != nil || e != nil || len(m.Answers) != 1 || f.tcpCount.Load() != 1 || f.count.Load() != 2 {
		t.Fatal(m, e, f.count.Load(), f.tcpCount.Load())
	}
	r.now = func() time.Time { return time.Now().Add(3 * time.Second) }
	binary.BigEndian.PutUint16(wire[:2], 4321)
	b, e = r.gateway(ctx, wire, false)
	_ = m.Unpack(b)
	if e != nil || m.ID != 4321 || f.count.Load() != 2 || m.Answers[0].Header.TTL > 57 {
		t.Fatal("wire cache id/age", m, e)
	}
	if n := r.clearCache(); n != 1 {
		t.Fatal(n)
	}
	if _, e = r.gateway(ctx, wire, false); e != nil || f.count.Load() != 3 {
		t.Fatal(e, f.count.Load())
	}
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		wire, _, _ = dnsQuestion("a.hosts.test", typ)
		b, e = r.gateway(ctx, wire, false)
		_ = m.Unpack(b)
		if e != nil || typ == dnsmessage.TypeA && len(m.Answers) != 1 || typ == dnsmessage.TypeAAAA && len(m.Answers) != 0 {
			t.Fatal(m, e)
		}
	}
	r.configureIO(false, net.DefaultResolver.LookupNetIP, (&net.Dialer{}).DialContext, nil)
	wire, _, _ = dnsQuestion("a.hosts.test", dnsmessage.TypeAAAA)
	b, e = r.gateway(ctx, wire, false)
	_ = m.Unpack(b)
	if e != nil || len(m.Answers) != 1 {
		t.Fatal(m, e)
	}
	if _, e = r.gateway(ctx, []byte("invalid query"), false); e == nil {
		t.Fatal("malformed DNS accepted")
	}
}

func TestK2ClearIncludesRetainedGenerations(t *testing.T) {
	c, _ := DecodeConfig([]byte(`{"inbounds":[{"protocol":"socks5","listen":"127.0.0.1:0"}],"dns":{"servers":["192.0.2.53"]}}`))
	c.SetClientIPv6(false)
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { ctx, cancel := k2Context(); defer cancel(); s.Close(ctx) }()
	old := s.current()
	old.refs.Add(1)
	defer old.unref()
	old.dns.cachePut("old.test", []netip.Addr{netip.MustParseAddr("192.0.2.1")}, time.Minute)
	if _, e = s.ApplyConfig(c); e != nil {
		t.Fatal(e)
	}
	s.current().dns.cachePut("new.test", []netip.Addr{netip.MustParseAddr("192.0.2.2")}, time.Minute)
	count, e := s.ClearDNSCache()
	if e != nil || count != 2 {
		t.Fatal(count, e)
	}
	if _, ok := old.dns.cached("old.test"); ok {
		t.Fatal("retained cache survived clear")
	}
}
