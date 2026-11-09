package kernel

import (
	"github.com/shui1iao/Kat/internal/route"
	"testing"
)

// Representative constructed fixture. No Start, resolver, dial or listener.
// dnsName is the actual kernel admission oracle, not a copied validator.
func TestRuleInspectorBaselineUnderscoreAdmission(t *testing.T) {
	_, admissionErr := dnsName("a_b.example.com")
	if admissionErr == nil {
		t.Fatal("real kernel unexpectedly admits underscore")
	}
	routing := &RoutingOptions{Rules: []RouteRule{{DomainSuffix: "example.com", Outbound: "Proxy"}}, Final: "direct"}
	e, err := route.NewEngine(route.Options{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	s := &Server{core: &core{}, rt: &routingRuntime{engine: e}}
	s.refs.Store(1)
	got, err := s.OfflineRuleView(routing, "https://a_b.example.com/")
	t.Logf("kernel.dnsName error=%v OfflineRuleView=%+v err=%v; required=target rejected", admissionErr, got, err)
	if err == nil {
		t.Fatalf("Offline must reject a target rejected by real kernel dnsName; got=%+v", got)
	}
	if s.refs.Load() != 1 {
		t.Fatalf("generation reference leaked: %d", s.refs.Load())
	}
}
