package kernel

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestR9SystemDNSClientEgressUsesPhysicalBootstrapAcrossReload(t *testing.T) {
	var calls atomic.Int32
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.SetClientEgress(&ClientEgress{Bootstrap: func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		calls.Add(1)
		return []netip.Addr{netip.MustParseAddr("8.8.4.4")}, nil
	}, DNSServers: []netip.Addr{netip.MustParseAddr("192.168.77.1")}})
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	for i := 0; i < 2; i++ {
		r, e := s.QueryDNS(context.Background(), "physical-only.invalid", "A")
		if e != nil || r.Server != "system" || len(r.Addresses) != 1 {
			t.Fatal("fell through system/TUN resolver", r, e)
		}
		if i == 0 {
			next := s.current().cfg
			if _, e := s.ApplyConfig(next); e != nil {
				t.Fatal(e)
			}
		}
	}
	if calls.Load() != 2 {
		t.Fatal("system unexpectedly cached or bypassed hook", calls.Load())
	}
	// Production physical bootstrap never calls the OS destination resolver:
	// it sends literal original NIC DNS through the bound physical socket.
	b, e := os.ReadFile("../clientegress/policy.go")
	if e != nil {
		t.Fatal(e)
	}
	revBytes, e := os.ReadFile("../clientegress/dns_revision.go")
	if e != nil {
		t.Fatal(e)
	}
	sysBytes, e := os.ReadFile("../clientegress/system_dns.go")
	if e != nil {
		t.Fatal(e)
	}
	src := string(b)
	a := strings.Index(src, "func (p *Policy) Bootstrap")
	if a < 0 {
		t.Fatal("bootstrap missing")
	}
	src = src[a:]
	for _, content := range []string{string(b), string(revBytes), string(sysBytes)} {
		if strings.Contains(content, "net.DefaultResolver") {
			t.Fatal("physical DNS reenters TUN")
		}
	}
	revSrc := string(revBytes)
	sysSrc := string(sysBytes)
	if !strings.Contains(src, "state.resolver.LookupNetIP") || !strings.Contains(revSrc, "Dial: p.resolverConn") || !strings.Contains(sysSrc, "state.options.DNS") || !strings.Contains(sysSrc, "ControlContext: control") {
		t.Fatal("physical binding lost")
	}
}
