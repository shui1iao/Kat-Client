package route

// Representative task-local fixtures; all files are under testing.TempDir.
import (
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestRuleInspectorResourceValueNotCountersOrTime(t *testing.T) {
	now := time.Now()
	zero := 0
	// Exercise every actual immutable resource pointer type without fabricating
	// database lookups: this test covers state identity, not GeoIP correctness.
	for _, tc := range []struct {
		kind  string
		value any
	}{
		{"rule_set", &setData{mono: true}}, {"geoip", &geoDB{}}, {"asn", &asnDB{}}, {"geosite", &siteDB{}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			s := &source{kind: tc.kind, metadata: ResourceView{Entries: &zero, UpdatedAt: &now, State: "ok"}}
			absent := offlineResource(s, tc.kind, "S", tc.value)
			if absent.DataAvailable == nil || *absent.DataAvailable || absent.Warning != "not_loaded" {
				t.Fatal("counters/time invented loaded state", absent)
			}
			s.value = tc.value
			s.metadata = ResourceView{State: "error", Code: "parse"}
			s.mtime = time.Time{}
			loaded := offlineResource(s, tc.kind, "S", tc.value)
			if loaded.DataAvailable == nil || !*loaded.DataAvailable || loaded.Warning != "refresh_failed_using_loaded" || loaded.Entries != nil {
				t.Fatal("loaded state incorrectly inferred", loaded)
			}
			mismatch := offlineResource(s, tc.kind, "S", nil)
			if mismatch.DataAvailable != nil || mismatch.Warning != "state_unavailable" {
				t.Fatal("mismatched pointer must be unknown availability", mismatch)
			}
		})
	}
}

func TestRuleInspectorUnloadedDatabaseSemanticsAndDependencyScope(t *testing.T) {
	dir := t.TempDir()
	o := Options{Rules: []Rule{{GeoIP: "CN", Action: "reject"}, {IPASN: "13335", Action: "reject"}, {SrcGeoIP: "CN", Action: "reject"}, {SrcIPASN: "13335", Action: "reject"}, {Geosite: "test", Action: "reject"}}, Final: "Tail", GeoIP: &GeoIPOptions{Path: filepath.Join(dir, "geo.mmdb")}, ASN: &GeoIPOptions{Path: filepath.Join(dir, "asn.mmdb")}, Geosite: &GeoIPOptions{Path: filepath.Join(dir, "site.dat")}}
	e := riEngine(t, o)
	g := riAgainstDecide(t, e, o, OfflineInput{Target: "192.0.2.1"}, Metadata{IP: netip.MustParseAddr("192.0.2.1")})
	if g.Status != "final" || len(g.Missing) != 0 || len(g.Resources) != 3 || len(g.ResourceWarnings) != 3 {
		t.Fatal("unavailable DB must preserve live false, without demanding source IP", g)
	}
	for _, r := range g.Resources {
		if r.DataAvailable == nil || *r.DataAvailable || r.Warning != "not_loaded" {
			t.Fatal(r)
		}
	}
	// Earlier decisive rule means the configured-but-unused databases do not
	// contaminate this result with unrelated warnings.
	o.Rules = append([]Rule{{IPCIDR: "192.0.2.0/24", Action: "reject"}}, o.Rules...)
	g = riOffline(t, e, o, OfflineInput{Target: "192.0.2.1"})
	if g.Rule != 1 || len(g.Resources) != 0 || len(g.ResourceWarnings) != 0 {
		t.Fatal("irrelevant resources included", g)
	}
}
func TestRuleInspectorResourceResultBounds(t *testing.T) {
	dir := t.TempDir()
	o := Options{Final: "Tail"}
	var subs []Rule
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("S%02d", i)
		o.RuleSets = append(o.RuleSets, RuleSetOptions{Name: name, Format: "sing-box-json", Path: filepath.Join(dir, name+".json")})
		subs = append(subs, Rule{RuleSet: name})
	}
	o.Rules = []Rule{{Or: subs, Action: "reject"}}
	e := riEngine(t, o)
	g := riAgainstDecide(t, e, o, OfflineInput{Target: "192.0.2.1"}, Metadata{IP: netip.MustParseAddr("192.0.2.1")})
	if len(g.Resources) != 16 || g.ResourcesMore != 4 || len(g.ResourceWarnings) != 8 || g.ResourceWarningsMore != 12 {
		t.Fatal("bounds/counts incorrect", g)
	}
	// Offline does not invoke the configured loader: all fixtures remain missing.
	for _, s := range e.sources {
		if s.value != nil {
			t.Fatal("offline loaded an absent fixture")
		}
	}
}
