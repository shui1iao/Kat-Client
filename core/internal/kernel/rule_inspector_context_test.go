package kernel

// Representative in-memory generations only: no Start, listeners, DNS or dials.
import (
	"errors"
	"github.com/shui1iao/Kat/internal/route"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func riGeneration(t *testing.T, k *core, c Config, id uint64) *Server {
	t.Helper()
	e, err := route.NewEngine(c.routeOptions(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	g := &Server{core: k, cfg: c, rt: &routingRuntime{engine: e}, id: id}
	g.refs.Store(1)
	return g
}
func TestRuleInspectorKernelAdmissionMatchesDNSName(t *testing.T) {
	k := &core{}
	g := riGeneration(t, k, Config{}, 1)
	k.gen.Store(g)
	routing := &RoutingOptions{Rules: []RouteRule{{DomainSuffix: "example.com", Outbound: "Proxy"}}, Final: "Tail"}
	domains := []string{"ExAmPle.COM.", "a-b.example.com", "a_b.example.com", "bad..example.com", "-bad.example.com", "bad-.example.com", "例子.example.com", strings.Repeat("a", 63) + ".example.com", strings.Repeat("a", 64) + ".example.com", "a.example.com.."}
	for _, host := range domains {
		t.Run(host, func(t *testing.T) {
			want, admissionErr := dnsName(host)
			got, err := g.OfflineRuleViewWithContext(routing, route.OfflineInput{Target: "https://" + host + "/"})
			t.Logf("real dnsName=%q err=%v offline=%+v err=%v", want, admissionErr, got, err)
			if (admissionErr != nil) != (err != nil) {
				t.Fatal("offline/kernel target admission mismatch")
			}
			if err == nil && got.Known.Host != want {
				t.Fatalf("normalization mismatch %q vs %q", got.Known.Host, want)
			}
			if err != nil {
				var ie *route.OfflineInputError
				if !errors.As(err, &ie) || ie.Field != "target" {
					t.Fatalf("not target field error: %v", err)
				}
			}
		})
	}
	if g.refs.Load() != 1 {
		t.Fatal("reference leak", g.refs.Load())
	}
}
func TestRuleInspectorCurrentGenerationResourcesAndIPv6(t *testing.T) {
	k := &core{}
	makeConfig := func(name, body string, ipv6 bool) Config {
		p := filepath.Join(t.TempDir(), name+".json")
		if err := os.WriteFile(p, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		c := Config{Routing: &RoutingOptions{Final: "direct"}, RuleSets: []RuleSetConfig{{Name: "S", Format: "sing-box-json", Path: p}}}
		c.SetClientIPv6(ipv6)
		return c
	}
	old := riGeneration(t, k, makeConfig("old", `{"version":1,"rules":[]}`, true), 11)
	current := riGeneration(t, k, makeConfig("current", `{"version":1,"rules":[{"ip_cidr":["2001:db8::/32"]}]}`, false), 12)
	root := &Server{core: k}
	accepted := &RoutingOptions{Rules: []RouteRule{{RuleSet: "S", Action: "reject"}}, Final: "Tail"}
	k.gen.Store(old)
	a, err := root.OfflineRuleViewWithContext(accepted, route.OfflineInput{Target: "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	k.gen.Store(current)
	b, err := root.OfflineRuleViewWithContext(accepted, route.OfflineInput{Target: "2001:db8::1"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("generation11=%+v generation12=%+v", a, b)
	if a.Status != "final" || a.Policy != "Tail" || len(a.AdmissionWarnings) != 0 || b.Status != "matched" || b.Policy != "reject" || b.Rule != 1 || !reflect.DeepEqual(b.AdmissionWarnings, []string{"ipv6_disabled"}) {
		t.Fatal("generation/resource/admission mismatch", a, b)
	}
	if a.Resources[0].Entries == nil || *a.Resources[0].Entries != 0 || b.Resources[0].Entries == nil || *b.Resources[0].Entries != 1 {
		t.Fatal("wrong generation resource snapshot", a, b)
	}
	// Warning is independent of a simulated proxy result, not a rewritten rejection.
	proxy := &RoutingOptions{Rules: []RouteRule{{IPCIDR: "2001:db8::/32", Outbound: "Proxy"}}, Final: "Tail"}
	c, err := root.OfflineRuleViewWithContext(proxy, route.OfflineInput{Target: "2001:db8::1"})
	if err != nil || c.Policy != "Proxy" || !reflect.DeepEqual(c.AdmissionWarnings, []string{"ipv6_disabled"}) {
		t.Fatal(c, err)
	}
	mapped, err := root.OfflineRuleViewWithContext(proxy, route.OfflineInput{Target: "::ffff:192.0.2.1"})
	if err != nil || len(mapped.AdmissionWarnings) != 0 {
		t.Fatal(mapped, err)
	}
	if old.refs.Load() != 1 || current.refs.Load() != 1 {
		t.Fatalf("references leaked old=%d current=%d", old.refs.Load(), current.refs.Load())
	}
}
func TestRuleInspectorStoppedAndUnavailableGeneration(t *testing.T) {
	s := &Server{}
	if _, err := s.OfflineRuleViewWithContext(nil, route.OfflineInput{Target: "192.0.2.1"}); !errors.Is(err, ErrCoreNotRunning) {
		t.Fatal(err)
	}
	s.refs.Store(1)
	s.core = &core{}
	if _, err := s.OfflineRuleViewWithContext(nil, route.OfflineInput{Target: "192.0.2.1"}); !errors.Is(err, ErrCoreNotRunning) {
		t.Fatal(err)
	}
	if s.refs.Load() != 1 {
		t.Fatal("failed reference must be returned")
	}
}
