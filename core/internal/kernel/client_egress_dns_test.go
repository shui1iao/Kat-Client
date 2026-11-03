package kernel

import (
	"context"
	"net/netip"
	"testing"

	"github.com/shui1iao/Kat/internal/route"
)

// Bero 2026-10-29: with TUN on, the host's original (private LAN) resolver is
// routed into TUN; in global mode it was sent through the node and timed out.
func TestClientEgressOriginalResolverIsDirectNotNode(t *testing.T) {
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Outbounds = []OutboundConfig{{Name: "node", Type: "socks5", Server: "127.0.0.1", Port: 9}}
	c.Routing = &RoutingOptions{Final: "node"}
	resolver := netip.MustParseAddr("192.168.77.1")
	c.SetClientEgress(&ClientEgress{DNSServers: []netip.Addr{resolver}})
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	cur := s.current()
	for _, network := range []string{"udp", "tcp"} {
		d, host, e := cur.decide(context.Background(), network, Address{Host: "192.168.77.1", Port: 53}, netip.Addr{})
		if e != nil || d.Kind != route.Direct || len(d.Candidates) != 1 || d.Candidates[0] != resolver || host != "192.168.77.1" {
			t.Fatalf("%s original resolver not direct: %+v %v", network, d, e)
		}
		for _, other := range []Address{{Host: "192.168.77.1", Port: 443}, {Host: "8.8.8.8", Port: 53}, {Host: "dns.example", Port: 53}} {
			if d, _, e := cur.decide(context.Background(), network, other, netip.Addr{}); e != nil || d.Kind != route.Proxy || d.Outbound != "node" {
				t.Fatalf("%s %v must keep routing: %+v %v", network, other, d, e)
			}
		}
	}
	if _, proxy, _, _, e := cur.routeUDP(context.Background(), Address{Host: "192.168.77.1", Port: 53}, netip.Addr{}); e != nil || proxy != "direct" {
		t.Fatalf("UDP original resolver must use the bound direct outbound: %q %v", proxy, e)
	}
	next := cur.cfg
	next.SetClientEgress(nil)
	if _, e = s.ApplyConfig(next); e != nil {
		t.Fatal(e)
	}
	if d, _, e := s.current().decide(context.Background(), "udp", Address{Host: "192.168.77.1", Port: 53}, netip.Addr{}); e != nil || d.Kind != route.Proxy {
		t.Fatalf("without egress the resolver follows normal routing: %+v %v", d, e)
	}
}
