package route

// All fixtures in this file are representative constructions, not field captures.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"
)

func riPort(n uint16) *uint16 { return &n }
func riEngine(t *testing.T, o Options) *Engine {
	t.Helper()
	e, err := NewEngine(o, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}
func riSet(t *testing.T, body string, rules []Rule) (Options, *Engine) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "S.json")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	o := Options{Rules: rules, Final: "Tail", RuleSets: []RuleSetOptions{{Name: "S", Format: "sing-box-json", Path: p}}}
	return o, riEngine(t, o)
}
func riOffline(t *testing.T, e *Engine, o Options, in OfflineInput) OfflineResult {
	t.Helper()
	got, err := e.OfflineWithContext(o, in)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("offline=%+v", got)
	return got
}
func riAgainstDecide(t *testing.T, e *Engine, o Options, in OfflineInput, m Metadata) OfflineResult {
	t.Helper()
	got := riOffline(t, e, o, in)
	calls := 0
	resolver := func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return nil, errors.New("fixture forbids DNS")
	}
	d, err := e.Decide(context.Background(), m, resolver)
	t.Logf("real Decide=%+v err=%v resolver_calls=%d", d, err, calls)
	if err != nil || calls != 0 {
		t.Fatalf("fixture must be decidable without DNS: %+v %v calls=%d", d, err, calls)
	}
	policy := d.Kind.String()
	if d.Kind == Proxy {
		policy = d.Outbound
	}
	if got.Status == "unknown" || got.Policy != policy || got.Rule != d.Rule {
		t.Fatalf("Offline/real Decide mismatch: offline=%+v Decide=%+v", got, d)
	}
	wantRow := d.Rule
	if wantRow == 0 {
		wantRow = len(o.Rules) + 1
	}
	if got.DisplayRow != wantRow {
		t.Fatalf("display row=%d want=%d", got.DisplayRow, wantRow)
	}
	return got
}

func TestRuleInspectorMetadataUnknownAndHandSupplied(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.1")
	tests := []struct {
		name  string
		rule  Rule
		field string
		in    OfflineInput
		m     Metadata
	}{
		{"target-port", Rule{DstPort: "443"}, "target_port", OfflineInput{TargetPort: riPort(443)}, Metadata{Port: 443}},
		{"network", Rule{Network: "udp"}, "network", OfflineInput{Network: "UDP"}, Metadata{Network: "udp"}},
		{"sniff-protocol", Rule{Protocol: "quic"}, "protocol", OfflineInput{Protocol: "QUIC"}, Metadata{Protocol: "quic"}},
		{"source-ip", Rule{SrcIPCIDR: "198.51.100.0/24"}, "source_ip", OfflineInput{SourceIP: "::ffff:198.51.100.2"}, Metadata{Source: netip.MustParseAddr("198.51.100.2")}},
		{"source-port", Rule{SrcPort: "54321"}, "source_port", OfflineInput{SourcePort: riPort(54321)}, Metadata{SrcPort: 54321}},
		{"inbound-name", Rule{InName: "local"}, "inbound_name", OfflineInput{InboundName: "local"}, Metadata{InName: "local"}},
		{"inbound-type", Rule{InType: "socks5"}, "inbound_type", OfflineInput{InboundType: "socks5"}, Metadata{InType: "socks5"}},
		{"inbound-port", Rule{InPort: "1080"}, "inbound_port", OfflineInput{InboundPort: riPort(1080)}, Metadata{InPort: 1080}},
		{"process-name", Rule{ProcessName: "app.exe"}, "process_name", OfflineInput{ProcessName: "APP.EXE"}, Metadata{ProcessName: "app.exe", ProcessStatus: "known"}},
	}
	var all []Rule
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := tc.rule
			rule.Action = "reject"
			o := Options{Rules: []Rule{rule}, Final: "direct"}
			e := riEngine(t, o)
			got := riOffline(t, e, o, OfflineInput{Target: "192.0.2.1"})
			if got.Status != "unknown" || !reflect.DeepEqual(got.Missing, []string{tc.field}) || got.Policy != "" || got.CandidatePolicy != "reject" || got.BlockedRule != 1 {
				t.Fatalf("unknown contract: %+v", got)
			}
			if got.Known.Network != "" || got.Known.Protocol != "" || got.Known.ProcessName != "" || got.Known.SourceIP != "" || got.Known.Port != 0 {
				t.Fatalf("invented metadata: %+v", got.Known)
			}
			tc.in.Target = "192.0.2.1"
			tc.m.IP = ip
			filled := riAgainstDecide(t, e, o, tc.in, tc.m)
			if filled.Status != "matched" {
				t.Fatal(filled)
			}
			// A fully specified contradictory value uses the existing matcher, not the tool's own oracle.
			o.Rules[0].Not = &tc.rule
			o.Rules[0].ProcessName = ""
			o.Rules[0].DstPort = ""
			o.Rules[0].Network = ""
			o.Rules[0].Protocol = ""
			o.Rules[0].SrcIPCIDR = ""
			o.Rules[0].SrcPort = ""
			o.Rules[0].InName = ""
			o.Rules[0].InType = ""
			o.Rules[0].InPort = ""
			notEngine := riEngine(t, o)
			notResult := riAgainstDecide(t, notEngine, o, tc.in, tc.m)
			if notResult.Status != "final" {
				t.Fatal(notResult)
			}
		})
		all = append(all, tc.rule)
	}
	o := Options{Rules: []Rule{{And: all, Outbound: "Proxy"}}, Final: "direct"}
	e := riEngine(t, o)
	got := riOffline(t, e, o, OfflineInput{Target: "192.0.2.1"})
	if got.Status != "unknown" || len(got.Missing) != 9 {
		t.Fatalf("must report all 9 absent metadata, got=%+v", got)
	}
	// An HTTPS URL implies only port, never transport or sniff protocol.
	for _, r := range []Rule{{Network: "tcp", Action: "reject"}, {Protocol: "tls", Action: "reject"}} {
		o := Options{Rules: []Rule{r}, Final: "direct"}
		g := riOffline(t, riEngine(t, o), o, OfflineInput{Target: "https://example.com/"})
		if g.Status != "unknown" || g.Known.Port != 443 || g.Known.Network != "" || g.Known.Protocol != "" {
			t.Fatal(g)
		}
	}
}

func TestRuleInspectorTargetParsingAndPortConflicts(t *testing.T) {
	tests := []struct {
		target, host, ip string
		port             uint16
		source           string
		manual           *uint16
		field            string
	}{
		{target: "ExAmPle.COM.", host: "example.com", source: "unspecified"},
		{target: "http://ExAmPle.COM/path?q=x", host: "example.com", port: 80, source: "url_default"},
		{target: "https://example.com/", host: "example.com", port: 443, source: "url_default"},
		{target: "https://example.com:8443/", host: "example.com", port: 8443, source: "url_explicit"},
		{target: "example.com:443", host: "example.com", port: 443, source: "url_explicit"},
		{target: "2001:db8::443", ip: "2001:db8::443", source: "unspecified"},
		{target: "[2001:db8::1]:8443", ip: "2001:db8::1", port: 8443, source: "url_explicit"},
		{target: "::ffff:192.0.2.1", ip: "192.0.2.1", source: "unspecified"},
		{target: "192.0.2.1", ip: "192.0.2.1", port: 1234, source: "manual", manual: riPort(1234)},
		{target: "https://example.com/", host: "example.com", port: 443, source: "url_default", manual: riPort(443)},
		{target: "https://example.com:8443/", host: "example.com", port: 8443, source: "url_explicit", manual: riPort(8443)},
		{target: "https://example.com/", manual: riPort(8443), field: "target_port"},
		{target: "http://example.com/", manual: riPort(443), field: "target_port"},
		{target: "https://example.com:8443/", manual: riPort(443), field: "target_port"},
		{target: "192.0.2.1", manual: riPort(0), field: "target_port"},
	}
	for _, bad := range []string{"fe80::1%eth0", "http://[fe80::1%25eth0]/", "https://a_b.example.com/", "bad..example", "-bad.example", "bad-.example", "例子.example", "[example.com]", "http://u:p@example.com/", "example.com/path", "https://example.com/#x", "example.com:0", "example.com:65536", "example.com:", "ftp://example.com", "bad example.com"} {
		tests = append(tests, struct {
			target, host, ip string
			port             uint16
			source           string
			manual           *uint16
			field            string
		}{target: bad, field: "target"})
	}
	for _, tc := range tests {
		t.Run(tc.target+fmt.Sprint(tc.manual), func(t *testing.T) {
			m, k, err := offlineMetadata(OfflineInput{Target: tc.target, TargetPort: tc.manual})
			t.Logf("metadata=%+v known=%+v err=%v", m, k, err)
			if tc.field != "" {
				var ie *OfflineInputError
				if !errors.As(err, &ie) || ie.Field != tc.field {
					t.Fatalf("wanted field %s got %v", tc.field, err)
				}
				return
			}
			if err != nil || k.Host != tc.host || k.IP != tc.ip || k.Port != tc.port || k.PortSource != tc.source || k.Network != "" || k.Protocol != "" {
				t.Fatalf("bad parse: %+v err=%v", k, err)
			}
		})
	}
}

func TestRuleInspectorLogicalOrderAndNoResolve(t *testing.T) {
	unknown := Rule{ProcessName: "app.exe"}
	tests := []struct {
		name            string
		rules           []Rule
		input           OfflineInput
		status, missing string
		m               Metadata
	}{
		{"AND false overrides unknown", []Rule{{And: []Rule{unknown, {IPCIDR: "198.51.100.0/24"}}, Action: "reject"}}, OfflineInput{Target: "192.0.2.1"}, "final", "", Metadata{IP: netip.MustParseAddr("192.0.2.1")}},
		{"OR true overrides unknown", []Rule{{Or: []Rule{unknown, {IPCIDR: "192.0.2.0/24"}}, Action: "reject"}}, OfflineInput{Target: "192.0.2.1"}, "matched", "", Metadata{IP: netip.MustParseAddr("192.0.2.1")}},
		{"NOT unknown", []Rule{{Not: &unknown, Action: "reject"}}, OfflineInput{Target: "192.0.2.1"}, "unknown", "process_name", Metadata{}},
		{"earliest unknown blocks later match", []Rule{{Network: "tcp", Action: "reject"}, {DomainSuffix: "example.com", Outbound: "Proxy"}}, OfflineInput{Target: "a.example.com"}, "unknown", "network", Metadata{}},
		{"domain no_resolve false", []Rule{{IPCIDR: "192.0.2.0/24", NoResolve: true, Action: "reject"}}, OfflineInput{Target: "example.com"}, "final", "", Metadata{Host: "example.com"}},
		{"domain NOT no_resolve true", []Rule{{Not: &Rule{IPCIDR: "192.0.2.0/24", NoResolve: true}, Action: "reject"}}, OfflineInput{Target: "example.com"}, "matched", "", Metadata{Host: "example.com"}},
		{"known IP still matches no_resolve", []Rule{{IPCIDR: "192.0.2.0/24", NoResolve: true, Action: "reject"}}, OfflineInput{Target: "192.0.2.1"}, "matched", "", Metadata{IP: netip.MustParseAddr("192.0.2.1")}},
		{"domain requires destination IP", []Rule{{IPCIDR: "192.0.2.0/24", Action: "reject"}}, OfflineInput{Target: "example.com"}, "unknown", "destination_ip", Metadata{}},
		{"outbound reject normalized", []Rule{{IPCIDR: "192.0.2.0/24", Outbound: "reject"}}, OfflineInput{Target: "192.0.2.1"}, "matched", "", Metadata{IP: netip.MustParseAddr("192.0.2.1")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o := Options{Rules: tc.rules, Final: "Tail"}
			e := riEngine(t, o)
			g := riOffline(t, e, o, tc.input)
			if g.Status != tc.status {
				t.Fatal(g)
			}
			if tc.missing != "" {
				if !slices.Contains(g.Missing, tc.missing) || g.Rule != 1 || g.BlockedRule != 1 || g.Policy != "" {
					t.Fatal(g)
				}
			} else {
				riAgainstDecide(t, e, o, tc.input, tc.m)
			}
		})
	}
}

func TestRuleInspectorRuleSetIndexesAndExtra(t *testing.T) {
	body := `{"version":1,"rules":[{"domain_suffix":["example.com"]},{"network":["udp"],"port":[443]}]}`
	o, e := riSet(t, body, []Rule{{RuleSet: "S", Action: "reject"}})
	if e.sets[0].data.Load().dom.empty() || len(e.sets[0].data.Load().extra) == 0 {
		t.Fatal("fixture did not exercise both index and extra")
	}
	riAgainstDecide(t, e, o, OfflineInput{Target: "a.example.com"}, Metadata{Host: "a.example.com"})
	g := riOffline(t, e, o, OfflineInput{Target: "192.0.2.1", TargetPort: riPort(443)})
	if g.Status != "unknown" || !slices.Contains(g.Missing, "network") {
		t.Fatal(g)
	}
	for _, network := range []string{"tcp", "udp"} {
		riAgainstDecide(t, e, o, OfflineInput{Target: "192.0.2.1", Network: network, TargetPort: riPort(443)}, Metadata{IP: netip.MustParseAddr("192.0.2.1"), Network: network, Port: 443})
	}
	// Rule-set no_resolve suppresses destination DNS only, not source/transport metadata.
	body = `{"version":1,"rules":[{"type":"logical","mode":"or","rules":[{"ip_cidr":["192.0.2.0/24"]},{"network":["udp"],"source_ip_cidr":["198.51.100.0/24"]}]}]}`
	o, e = riSet(t, body, []Rule{{RuleSet: "S", NoResolve: true, Action: "reject"}})
	g = riOffline(t, e, o, OfflineInput{Target: "other.example"})
	if g.Status != "unknown" || slices.Contains(g.Missing, "destination_ip") || !slices.Contains(g.Missing, "source_ip") || !slices.Contains(g.Missing, "network") {
		t.Fatal(g)
	}
	riAgainstDecide(t, e, o, OfflineInput{Target: "other.example", Network: "udp", SourceIP: "198.51.100.2"}, Metadata{Host: "other.example", Network: "udp", Source: netip.MustParseAddr("198.51.100.2")})
	riAgainstDecide(t, e, o, OfflineInput{Target: "192.0.2.1"}, Metadata{IP: netip.MustParseAddr("192.0.2.1")})
	// Index port sentinel cannot override NOT(unknown), and a true domain index may still short-circuit it.
	o, e = riSet(t, `{"version":1,"rules":[{"port_range":[":443"]}]}`, []Rule{{Not: &Rule{RuleSet: "S"}, Action: "reject"}})
	g = riOffline(t, e, o, OfflineInput{Target: "192.0.2.1"})
	if g.Status != "unknown" || !slices.Contains(g.Missing, "target_port") {
		t.Fatal(g)
	}
	for _, port := range []uint16{443, 8443} {
		riAgainstDecide(t, e, o, OfflineInput{Target: "192.0.2.1", TargetPort: riPort(port)}, Metadata{IP: netip.MustParseAddr("192.0.2.1"), Port: port})
	}
	o, e = riSet(t, `{"version":1,"rules":[{"port_range":[":443"]},{"domain_suffix":["example.com"]}]}`, []Rule{{RuleSet: "S", Action: "reject"}})
	riAgainstDecide(t, e, o, OfflineInput{Target: "a.example.com"}, Metadata{Host: "a.example.com"})
}

func TestRuleInspectorResourceStatesAndImmutableAcceptedOptions(t *testing.T) {
	for _, tc := range []struct {
		name, body  string
		available   bool
		warning     string
		refreshFail bool
	}{
		{"valid-empty", `{"version":1,"rules":[]}`, true, "", false},
		{"never-loaded", "", false, "not_loaded", false},
		{"old-valid-refresh-failed", `{"version":1,"rules":[{"domain_suffix":["example.com"]}]}`, true, "refresh_failed_using_loaded", true},
		{"valid-empty-refresh-failed", `{"version":1,"rules":[]}`, true, "refresh_failed_using_loaded", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "S.json")
			if tc.body != "" {
				if err := os.WriteFile(p, []byte(tc.body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			o := Options{Rules: []Rule{{RuleSet: "S", Action: "reject"}, {DomainSuffix: "example.com", Outbound: "Proxy"}}, Final: "Tail", RuleSets: []RuleSetOptions{{Name: "S", Format: "sing-box-json", Path: p}}}
			e := riEngine(t, o)
			if tc.refreshFail {
				err := e.RefreshResourceWith(context.Background(), "rule_set", "S", func(string, int64) ([]byte, error) { return []byte(`not-json`), nil }, nil)
				if err == nil {
					t.Fatal("invalid refresh unexpectedly succeeded")
				}
			}
			// Make mtime useless. Loaded state must come from the actual retained value.
			e.sets[0].src.mtime = time.Time{}
			g := riAgainstDecide(t, e, o, OfflineInput{Target: "a.example.com"}, Metadata{Host: "a.example.com"})
			if len(g.Resources) != 1 {
				t.Fatal(g)
			}
			r := g.Resources[0]
			if r.DataAvailable == nil || *r.DataAvailable != tc.available || r.Warning != tc.warning {
				t.Fatalf("wrong resource distinction: %+v", r)
			}
			if tc.name == "valid-empty" && (r.Entries == nil || *r.Entries != 0) {
				t.Fatal("valid empty must retain entries=0", r)
			}
			if tc.name == "old-valid-refresh-failed" && g.Rule != 1 {
				t.Fatal("refresh failure discarded old matching data", g)
			}
			if (tc.name == "never-loaded" || tc.name == "valid-empty") && g.Rule != 2 {
				t.Fatal("live empty semantics changed", g)
			}
			if r.Entries != nil {
				*r.Entries = 999
			}
			again := riOffline(t, e, o, OfflineInput{Target: "a.example.com"})
			if again.Resources[0].Entries != nil && *again.Resources[0].Entries == 999 {
				t.Fatal("result aliased source metadata")
			}
		})
	}
	// Nested Validate must not mutate accepted rules or root resource descriptors.
	o, e := riSet(t, `{"version":1,"rules":[]}`, []Rule{{And: []Rule{{DomainSuffix: "ExAmPle.COM."}, {Or: []Rule{{Network: "TCP"}, {Protocol: "TLS"}}}}, Outbound: "Proxy"}})
	o.Rules[0].And[0].DomainSuffix = "ExAmPle.COM."
	o.GeoIP = &GeoIPOptions{Path: filepath.Join(t.TempDir(), "missing.mmdb")}
	before, _ := json.Marshal(o)
	_, err := e.OfflineWithContext(o, OfflineInput{Target: "https://example.com/", Network: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(o)
	if string(before) != string(after) {
		t.Fatalf("accepted options mutated before=%s after=%s", before, after)
	}
}

func TestRuleInspectorSnapshotRace(t *testing.T) {
	o, e := riSet(t, `{"version":1,"rules":[]}`, []Rule{{RuleSet: "S", Action: "reject"}})
	bodies := []string{`{"version":1,"rules":[]}`, `{"version":1,"rules":[{"domain":["example.com"]}]}`}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	wg.Go(func() {
		for i := 0; i < 80; i++ {
			b := bodies[i%2]
			if err := e.RefreshResourceWith(context.Background(), "rule_set", "S", func(string, int64) ([]byte, error) { return []byte(b), nil }, nil); err != nil {
				errs <- err
				return
			}
		}
	})
	for range 2 {
		wg.Go(func() {
			for range 100 {
				g, err := e.OfflineWithContext(o, OfflineInput{Target: "example.com"})
				if err != nil {
					errs <- err
					return
				}
				if len(g.Resources) != 1 {
					errs <- fmt.Errorf("missing resource %+v", g)
					return
				}
				r := g.Resources[0]
				if r.DataAvailable == nil || !*r.DataAvailable || r.Warning != "" || r.Entries == nil || (g.Status == "matched" && *r.Entries != 1) || (g.Status == "final" && *r.Entries != 0) {
					errs <- fmt.Errorf("torn snapshot result=%+v resource=%+v", g, r)
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
