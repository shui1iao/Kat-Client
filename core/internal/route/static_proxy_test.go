package route

import (
	"net/netip"
	"testing"
)

func TestMatchStaticProxyStrictPrecedingUnknownRules(t *testing.T) {
	t.Run("static proxy before any unknown rule", func(t *testing.T) {
		e, err := NewReadOnlyEngine(Options{
			Rules: []Rule{
				{DomainSuffix: "openai.com", Outbound: "ai-proxy"},
				{IPCIDR: "10.0.0.0/8", Action: "direct"},
			},
			Final: "direct",
		})
		if err != nil {
			t.Fatal(err)
		}
		d, ok := e.MatchStaticDomain("api.openai.com")
		if !ok || d.Kind != Proxy || d.Outbound != "ai-proxy" {
			t.Fatalf("expected Proxy ai-proxy, got (%+v, %v)", d, ok)
		}
		if d, ok := e.MatchStaticDomain("other.example.com"); ok {
			t.Fatalf("ordinary domain should not match static domain rule: (%+v, %v)", d, ok)
		}
	})

	t.Run("preceding unknown direct IP/process/port rule blocks static proxy", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			first Rule
		}{
			{"ip_cidr_direct", Rule{IPCIDR: "198.51.100.0/24", Action: "direct"}},
			{"process_name_direct", Rule{ProcessName: "LocalApp", Action: "direct"}},
			{"dst_port_direct", Rule{DstPort: "8080", Action: "direct"}},
			{"ip_cidr_reject", Rule{IPCIDR: "203.0.113.0/24", Action: "reject"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				e, err := NewReadOnlyEngine(Options{
					Rules: []Rule{
						tc.first,
						{DomainSuffix: "blocked.example", Outbound: "proxy-out"},
					},
					Final: "proxy-out",
				})
				if err != nil {
					t.Fatal(err)
				}
				if d, ok := e.MatchStaticDomain("sub.blocked.example"); ok && d.Kind == Proxy {
					t.Fatalf("preceding unknown non-proxy rule %s must block static proxy, got (%+v, %v)", tc.name, d, ok)
				}
			})
		}
	})

	t.Run("preceding unknown proxy rule does not block static proxy", func(t *testing.T) {
		e, err := NewReadOnlyEngine(Options{
			Rules: []Rule{
				{ProcessName: "SpecialProxyApp", Outbound: "alt-proxy"},
				{DomainSuffix: "safe-proxy.example", Outbound: "main-proxy"},
			},
			Final: "direct",
		})
		if err != nil {
			t.Fatal(err)
		}
		d, ok := e.MatchStaticDomain("api.safe-proxy.example")
		if !ok || d.Kind != Proxy || d.Outbound != "main-proxy" {
			t.Fatalf("preceding proxy-only unknown rule should allow static proxy, got (%+v, %v)", d, ok)
		}
	})

	t.Run("final proxy alone is not static proxy and IP literal rejected", func(t *testing.T) {
		e, err := NewReadOnlyEngine(Options{
			Rules: []Rule{
				{DomainSuffix: "cn", Action: "direct"},
			},
			Final: "proxy-out",
		})
		if err != nil {
			t.Fatal(err)
		}
		if d, ok := e.MatchStaticDomain("adguard.home.arpa"); ok && d.Kind == Proxy {
			t.Fatalf("Final=proxy-out alone must not classify ordinary domain as static proxy: (%+v, %v)", d, ok)
		}
		if d, ok := e.MatchStaticDomain(netip.MustParseAddr("1.1.1.1").String()); ok {
			t.Fatalf("IP literal must not match static domain: (%+v, %v)", d, ok)
		}
	})
}
