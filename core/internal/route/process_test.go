package route

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestProcessSchemaAndIdentity(t *testing.T) {
	for _, name := range []string{`C:\x.exe`, "/bin/curl", "..", "a/b", "a\x00b", "x*", " x.exe"} {
		o := Options{Rules: []Rule{{ProcessName: name, Action: "reject"}}}
		if o.Validate() == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	var r Rule
	if err := json.Unmarshal([]byte(`{"process_name":"ChRoMe.ExE","action":"reject"}`), &r); err != nil {
		t.Fatal(err)
	}
	o := Options{Rules: []Rule{r}}
	if err := o.Validate(); err != nil {
		t.Fatal(err)
	}
	if o.Rules[0].ProcessName != "chrome.exe" {
		t.Fatal(o)
	}
	e := mustEngine(t, o, nil)
	for _, name := range []string{"chrome.exe", "CHROME.EXE"} {
		d, err := e.Decide(context.Background(), Metadata{IP: ip("1.1.1.1"), ProcessName: name, ProcessStatus: "known"}, nil)
		if err != nil || d.Kind != Reject || d.Rule != 1 {
			t.Fatal(name, d, err)
		}
	}
	d, err := e.Decide(context.Background(), Metadata{IP: ip("1.1.1.1"), ProcessName: "other.exe", ProcessStatus: "known"}, nil)
	if err != nil || d.Kind != Direct || d.Rule != 0 {
		t.Fatal(d, err)
	}
	for _, status := range []string{"", "unknown", "ambiguous", "denied", "closed", "changed", "unsupported"} {
		d, err := e.Decide(context.Background(), Metadata{IP: ip("1.1.1.1"), ProcessName: "chrome.exe", ProcessStatus: status}, nil)
		var u *ProcessUnavailableError
		if !errors.As(err, &u) || d.Kind != Reject || u.Rule != 1 {
			t.Fatal(status, d, err)
		}
	}
}
func TestProcessOrderedLogical(t *testing.T) {
	proc := Rule{ProcessName: "app.exe"}
	not := Rule{Not: &proc, Outbound: "hit"}
	cases := []struct {
		name    string
		rules   []Rule
		host    string
		want    string
		unknown bool
	}{
		{"not unknown", []Rule{not}, "x.example", "", true},
		{"previous first match", []Rule{{Domain: "x.example", Outbound: "first"}, not}, "x.example", "first", false},
		{"and false", []Rule{{And: []Rule{proc, {Network: "udp"}}, Outbound: "hit"}}, "x.example", "", false},
		{"or true", []Rule{{Or: []Rule{proc, {Domain: "x.example"}}, Outbound: "hit"}}, "x.example", "hit", false},
		{"and true unknown", []Rule{{And: []Rule{proc, {Network: "tcp"}}, Outbound: "hit"}}, "x.example", "", true},
		{"IP false resolves unknown", []Rule{{And: []Rule{proc, {IPCIDR: "10.0.0.0/8"}}, Outbound: "hit"}}, "x.example", "", false},
		{"IP true keeps unknown", []Rule{{And: []Rule{proc, {IPCIDR: "1.0.0.0/8"}}, Outbound: "hit"}}, "x.example", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := mustEngine(t, Options{Rules: tc.rules}, nil)
			d, err := e.Decide(context.Background(), Metadata{Host: tc.host, Network: "tcp"}, (&fakeDNS{ips: addrs("1.1.1.1")}).resolve)
			var u *ProcessUnavailableError
			if errors.As(err, &u) != tc.unknown {
				t.Fatal(d, err)
			}
			if !tc.unknown && (err != nil || d.Outbound != tc.want) {
				t.Fatal(d, err)
			}
		})
	}
}
func TestProcessRuleSetAndReplacement(t *testing.T) {
	p := writeFile(t, "process.yaml", "payload:\n - PROCESS-NAME,App.EXE\n - DOMAIN,known.example\n")
	e := mustEngine(t, Options{Rules: []Rule{{RuleSet: "s", NoResolve: true, Outbound: "hit"}}, RuleSets: []RuleSetOptions{{Name: "s", Format: "yaml", Behavior: "classical", Path: p}}}, nil)
	if !e.NeedsProcess() {
		t.Fatal("missing dependency")
	}
	for _, m := range []Metadata{{IP: ip("1.1.1.1"), ProcessName: "APP.exe", ProcessStatus: "known"}, {Host: "known.example"}} {
		d, err := e.Decide(context.Background(), m, nil)
		if err != nil || d.Outbound != "hit" {
			t.Fatal(d, err)
		}
	}
	d, err := e.Decide(context.Background(), Metadata{Host: "other.example"}, nil)
	var u *ProcessUnavailableError
	if !errors.As(err, &u) || d.Kind != Reject {
		t.Fatal(d, err)
	}
	// A second flow cannot reuse the previous positive identity. Replacement
	// remains atomic; process dependency is evaluated from current parsed data.
	data, err := parseRuleSetAs("classical", "", []byte("DOMAIN,other.example\n"), 100, fullEnv)
	if err != nil {
		t.Fatal(err)
	}
	e.sets[0].data.Store(data)
	if e.NeedsProcess() {
		t.Fatal("stale dependency")
	}
	d, err = e.Decide(context.Background(), Metadata{Host: "other.example"}, nil)
	if err != nil || d.Outbound != "hit" {
		t.Fatal(d, err)
	}
}
func TestSubscriptionResourceContract(t *testing.T) {
	so := RuleSetOptions{Name: "resource", Format: "yaml", Behavior: "classical"}
	n, err := ValidateSubscriptionSetWithDependencies(so, []byte("# header\npayload:\n - DOMAIN,a_b.example\n - PROCESS-NAME,x.exe\n - IP-ASN,13335,no-resolve\n"), SubscriptionSetDependencies{ASN: true})
	if err != nil || n != 3 {
		t.Fatal(n, err)
	}
	_, err = ValidateSubscriptionSet(so, []byte("payload:\n - IP-ASN,13335\n"), true)
	var v *SubscriptionSetValidationError
	if !errors.As(err, &v) || v.Issues[0].Dependency != "asn" || v.Issues[0].Line != 2 {
		t.Fatal(err)
	}
	_, err = ValidateSubscriptionSetWithDependencies(so, []byte("payload:\n - DOMAIN,bad..domain\n - FOO,x\n - GEOSITE,cn\n"), SubscriptionSetDependencies{})
	if !errors.As(err, &v) || len(v.Issues) != 3 {
		t.Fatal(err)
	}
	for j, code := range []string{"invalid_format", "unsupported_type", "missing_dependency"} {
		if v.Issues[j].Code != code || v.Issues[j].Entry != j+1 || v.Issues[j].Line != j+2 {
			t.Fatal(v.Issues)
		}
	}
}
func TestAuthorizedPublicResources(t *testing.T) {
	dir := os.Getenv("KAT_PROCESS_RESOURCE_DIR")
	if dir == "" {
		t.Skip("private task resources not provided")
	}
	counts := []int{1409, 401, 54, 8, 955, 12662, 7902, 174}
	for j, want := range counts {
		p := filepath.Join(dir, string(rune('0'+j))+".yaml")
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		n, err := ValidateSubscriptionSetWithDependencies(RuleSetOptions{Name: "public-resource", Format: "yaml", Behavior: "classical"}, b, SubscriptionSetDependencies{GeoIP: true, ASN: true})
		if err != nil || n != want {
			t.Fatalf("resource %d entries=%d want=%d: %v", j, n, want, err)
		}
		t.Logf("resource=%d entries=%d strict=passed", j, n)
	}
	for _, name := range []string{"asn.mmdb", "country.mmdb"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		err = ValidateSubscriptionASN(b)
		if name == "asn.mmdb" && err != nil {
			t.Fatal(err)
		}
		if name == "country.mmdb" && err == nil {
			t.Fatal("country DB accepted as ASN")
		}
	}
	// Real ASN lookups, not fabricated data, participate in the same runtime.
	e := mustEngine(t, Options{Rules: []Rule{{IPASN: "13335", Outbound: "asn"}}, ASN: &GeoIPOptions{Path: filepath.Join(dir, "asn.mmdb")}}, nil)
	d, err := e.Decide(context.Background(), Metadata{IP: netip.MustParseAddr("1.1.1.1")}, nil)
	if err != nil || d.Outbound != "asn" {
		t.Fatal(d, err)
	}
}

func TestProcessLazyDoesNotQueryIrrelevantConditions(t *testing.T) {
	for _, rules := range [][]Rule{{{Domain: "known.example", Outbound: "first"}, {ProcessName: "x.exe", Outbound: "process"}}, {{Or: []Rule{{ProcessName: "x.exe"}, {Domain: "known.example"}}, Outbound: "first"}}, {{And: []Rule{{ProcessName: "x.exe"}, {Network: "udp"}}, Outbound: "first"}}} {
		e := mustEngine(t, Options{Rules: rules}, nil)
		calls := 0
		m := Metadata{Host: "known.example", Network: "tcp", ProcessLookup: func() (string, string) { calls++; return "x.exe", "known" }}
		_, _ = e.Decide(context.Background(), m, (&fakeDNS{ips: addrs("1.1.1.1")}).resolve)
		if calls != 0 {
			t.Fatal("irrelevant attribution query", calls)
		}
	}
	e := mustEngine(t, Options{Rules: []Rule{{ProcessName: "x.exe", Outbound: "process"}}}, nil)
	calls := 0
	m := Metadata{IP: ip("1.1.1.1"), ProcessLookup: func() (string, string) { calls++; return "X.EXE", "known" }}
	d, err := e.Decide(context.Background(), m, nil)
	if err != nil || d.Outbound != "process" || calls != 1 {
		t.Fatal(d, err, calls)
	}
}
