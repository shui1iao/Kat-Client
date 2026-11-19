package kernel

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/route"
)

// TestSniffOverridePublicIPDirectGroupAndProxyZeroExtraDNS verifies that
// override_destination=true on a public IP destination:
// 1. Direct rule: decide() preserves the original IP with 0 extra DNS lookups.
// 2. Group selecting built-in direct leaf: end-to-end TCP dials the original IP via sniffDirectLeaf with 0 extra DNS lookups (Sniffed=true, RemoteDNS=false).
// 3. Group selecting a proxy node: end-to-end TCP sends the sniffed domain to the proxy with 0 local DNS lookups (Sniffed=true, RemoteDNS=true).
// 4. Preceding IP-CIDR rule evaluates using the original IP with 0 DNS lookups.
func TestSniffOverridePublicIPDirectGroupAndProxyZeroExtraDNS(t *testing.T) {
	echoPort := rcEchoTCP(t)
	proxyPort, proxyTargets := startMockSOCKS5Server(t, func(_ string, _ uint16, c net.Conn) {
		_, _ = io.Copy(c, c)
	})

	var dnsQueries atomic.Int32
	badDNS := newDNSFixture(t, func(w []byte) []byte {
		dnsQueries.Add(1)
		return dnsReply(w, []string{"203.0.113.250"}, 120)
	})

	var directMu sync.Mutex
	var directDialed []string

	var evMu sync.Mutex
	var events []ConnectionEvent

	s := startTest(t, Inbound{
		Protocol: "socks5",
		Name:     "kat-client",
		Sniff:    &SniffOptions{Enabled: true, TCPPorts: "443", OverrideDestination: true},
	}, func(c *Config) {
		c.DNS = &DNSOptions{Server: badDNS.address()}
		c.SetConnectionSink(func(ev ConnectionEvent) {
			evMu.Lock()
			events = append(events, ev)
			evMu.Unlock()
		})
		c.Outbounds = []OutboundConfig{
			{Name: "proxy-out", Type: "socks5", Server: "127.0.0.1", Port: proxyPort},
		}
		c.Groups = []GroupConfig{
			{Name: "grp-direct", Type: "select", Members: []string{"direct", "proxy-out"}, Selected: "direct"},
			{Name: "grp-proxy", Type: "select", Members: []string{"proxy-out", "direct"}, Selected: "proxy-out"},
		}
		c.Routing = &RoutingOptions{
			Rules: []RouteRule{
				{IPCIDR: "198.51.100.90/32", Action: "direct"},
				{DomainSuffix: "iprule.example", Outbound: "proxy-out"},
				{DomainSuffix: "direct-rule.example", Action: "direct"},
				{DomainSuffix: "group-direct.example", Outbound: "grp-direct"},
				{DomainSuffix: "group-proxy.example", Outbound: "grp-proxy"},
			},
			Final: "reject",
		}
		c.SetClientEgress(&ClientEgress{
			Active: func() bool { return true },
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, _ := net.SplitHostPort(addr)
				if ip, err := netip.ParseAddr(host); err == nil && !ip.IsLoopback() {
					directMu.Lock()
					directDialed = append(directDialed, addr)
					directMu.Unlock()
					return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(echoPort))))
				}
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			Bootstrap: net.DefaultResolver.LookupNetIP,
		})
	})

	g := s.current()
	sniffOpt := g.cfg.Inbounds[0].Sniff
	srcIP := netip.MustParseAddr("127.0.0.1")

	// 1. Direct rule -> decide() keeps original IP 198.51.100.11, 0 DNS queries
	ctxDirect := withSniff(context.Background(), sniffOpt.applyResult("tls", "www.direct-rule.example"))
	dDirect, _, err := g.decide(ctxDirect, "tcp", Address{Host: "198.51.100.11", Port: 443}, srcIP)
	if err != nil || dDirect.Kind != route.Direct || len(dDirect.Candidates) != 1 || dDirect.Candidates[0] != netip.MustParseAddr("198.51.100.11") {
		t.Fatalf("direct rule decide mismatch: d=%+v err=%v", dDirect, err)
	}

	// 4. Preceding IP-CIDR rule matches original IP 198.51.100.90 before domain rule -> direct, 0 DNS queries
	ctxIPRule := withSniff(context.Background(), sniffOpt.applyResult("tls", "www.iprule.example"))
	dIP, _, err := g.decide(ctxIPRule, "tcp", Address{Host: "198.51.100.90", Port: 443}, srcIP)
	if err != nil || dIP.Kind != route.Direct || len(dIP.Candidates) != 1 || dIP.Candidates[0] != netip.MustParseAddr("198.51.100.90") {
		t.Fatalf("preceding IP-CIDR rule decide mismatch: d=%+v err=%v", dIP, err)
	}

	client := socksClient(t, s)

	// 2. End-to-end TCP: select group choosing direct leaf -> dials original public IP 198.51.100.12:443, 0 DNS queries
	if !sendFirst(t, client, outbound.Addr{Host: "198.51.100.12", Port: 443}, tlsHello(t, "www.group-direct.example")) {
		t.Fatal("group->direct connection failed")
	}
	// 3. End-to-end TCP: select group choosing proxy -> proxy receives sniffed domain www.group-proxy.example:443, 0 local DNS queries
	if !sendFirst(t, client, outbound.Addr{Host: "198.51.100.13", Port: 443}, tlsHello(t, "www.group-proxy.example")) {
		t.Fatal("group->proxy connection failed")
	}

	if got := dnsQueries.Load(); got != 0 {
		t.Fatalf("expected 0 extra DNS queries, got %d", got)
	}

	directMu.Lock()
	gotDirect := append([]string(nil), directDialed...)
	directMu.Unlock()
	if len(gotDirect) != 1 || gotDirect[0] != "198.51.100.12:443" {
		t.Fatalf("group->direct dialed mismatch: got %v, want [198.51.100.12:443]", gotDirect)
	}

	gotProxy := proxyTargets()
	if len(gotProxy) != 1 || gotProxy[0] != "www.group-proxy.example:443" {
		t.Fatalf("proxy targets mismatch: got %v, want [www.group-proxy.example:443]", gotProxy)
	}

	waitFor(t, func() bool {
		evMu.Lock()
		defer evMu.Unlock()
		n := 0
		for _, ev := range events {
			if ev.Ended && ev.Network == "tcp" {
				n++
			}
		}
		return n >= 2
	})

	evMu.Lock()
	byHost := map[string]ConnectionEvent{}
	for _, ev := range events {
		if ev.Ended && ev.Network == "tcp" {
			byHost[ev.DestHost] = ev
		}
	}
	evMu.Unlock()

	for _, tc := range []struct {
		host      string
		remoteDNS bool
	}{
		{"www.group-direct.example", false},
		{"www.group-proxy.example", true},
	} {
		ev, ok := byHost[tc.host]
		if !ok {
			t.Fatalf("missing ended event for %s (got=%v)", tc.host, byHost)
		}
		if !ev.Sniffed || ev.RemoteDNS != tc.remoteDNS {
			t.Fatalf("%s: got Sniffed=%v RemoteDNS=%v, want Sniffed=true RemoteDNS=%v", tc.host, ev.Sniffed, ev.RemoteDNS, tc.remoteDNS)
		}
	}
}
