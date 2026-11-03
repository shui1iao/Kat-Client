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
	src := string(b)
	a := strings.Index(src, "func (p *Policy) Bootstrap")
	if a < 0 {
		t.Fatal("bootstrap missing")
	}
	src = src[a:]
	if strings.Contains(src, "net.DefaultResolver") {
		t.Fatal("physical DNS reenters TUN")
	}
	full := string(b)
	if !strings.Contains(full, "ip := o.DNS") || !strings.Contains(full, "ControlContext: p.Control") || !strings.Contains(src, "p.resolver.LookupNetIP") {
		t.Fatal("physical binding lost")
	}
}
