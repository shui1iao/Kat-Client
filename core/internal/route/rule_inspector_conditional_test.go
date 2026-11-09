package route

// User URL is only a string. Google resources/processes/policies below are
// representative fixtures, not a capture of the user's unknown installed data.
import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const conditionalTarget = "https://super-bill.ccb233.cn/"

func conditionalExport(t *testing.T, name string, result OfflineResult) {
	t.Helper()
	if dir := os.Getenv("KAT_CONDITIONAL_REPLY_DIR"); dir != "" {
		body, err := json.MarshalIndent(map[string]any{"mode": "rule", "simulation": "rule", "ipv6_enabled": false, "result": result}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(dir, name+".json"), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func conditionalFixture(t *testing.T, tail []Rule) (Options, *Engine) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "Google.list")
	if err := os.WriteFile(p, []byte("DOMAIN-SUFFIX,google.com\nPROCESS-NAME,FixtureGoogleSync.exe\n"), 0600); err != nil {
		t.Fatal(err)
	}
	o := Options{Final: "FixtureFinal", RuleSets: []RuleSetOptions{{Name: "Google", Format: "classical", Path: p}}}
	for i := 0; i < 7; i++ {
		o.Rules = append(o.Rules, Rule{Domain: "previous.invalid", Action: "reject"})
	}
	o.Rules = append(o.Rules, Rule{RuleSet: "Google", Outbound: "FixtureGooglePolicy"})
	o.Rules = append(o.Rules, tail...)
	return o, riEngine(t, o)
}
func TestRuleInspectorConditionalUserExample(t *testing.T) {
	o, e := conditionalFixture(t, nil)
	got := riOffline(t, e, o, OfflineInput{Target: conditionalTarget})
	after := got.ConditionalAfter
	conditionalExport(t, "unknown-final", got)
	if got.Status != "unknown" || got.Policy != "" || got.BlockedRule != 8 || !reflect.DeepEqual(got.Missing, []string{"process_name"}) || after == nil {
		t.Fatal(got)
	}
	if after.Assumption.Rule != 8 || after.Assumption.RuleSet != "Google" || after.Assumption.Condition != "rule_set:Google" || after.Assumption.Matches || after.Status != "final" || after.Rule != 0 || after.DisplayRow != 9 || after.Policy != "FixtureFinal" {
		t.Fatal(after)
	}
	if len(after.Resources) != 0 || len(got.Resources) != 1 {
		t.Fatal("main and conditional resources merged", got)
	}
	for _, process := range []string{"fixture-browser.exe", "FixtureGoogleSync.exe"} {
		got = riOffline(t, e, o, OfflineInput{Target: conditionalTarget, ProcessName: process})
		if got.Status == "unknown" || got.ConditionalAfter != nil {
			t.Fatal("known result has counterfactual", got)
		}
	}
	wire, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err = json.Unmarshal(wire, &object); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"missing", "resources", "resource_warnings"} {
		if list, ok := object[key].([]any); !ok || len(list) != 0 {
			t.Fatal("empty JSON lists must be []", key, object[key])
		}
	}
	if _, nested := object["conditional_after"]; nested {
		t.Fatal("nested branch", string(wire))
	}
}
func TestRuleInspectorConditionalStopsAtNextUnknownOrMatch(t *testing.T) {
	for _, tc := range []struct {
		name           string
		tail           []Rule
		status, policy string
		rule, blocked  int
		missing        []string
	}{
		{"next unknown", []Rule{{Network: "udp", Outbound: "LaterUDP"}}, "unknown", "", 9, 9, []string{"network"}},
		{"next known match", []Rule{{DomainSuffix: "ccb233.cn", Outbound: "LaterDomain"}}, "matched", "LaterDomain", 9, 0, []string{}},
		{"known match after another known false", []Rule{{Domain: "other.invalid", Action: "reject"}, {DomainSuffix: "ccb233.cn", Action: "reject"}}, "matched", "reject", 10, 0, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, e := conditionalFixture(t, tc.tail)
			g := riOffline(t, e, o, OfflineInput{Target: conditionalTarget})
			a := g.ConditionalAfter
			if tc.name == "next unknown" {
				conditionalExport(t, "unknown-next-unknown", g)
			}
			if tc.name == "next known match" {
				conditionalExport(t, "unknown-next-match", g)
			}
			if g.Status != "unknown" || g.Rule != 8 || g.Policy != "" || a == nil || a.Status != tc.status || a.Policy != tc.policy || a.Rule != tc.rule || a.DisplayRow != tc.rule || a.BlockedRule != tc.blocked || !reflect.DeepEqual(a.Missing, tc.missing) {
				t.Fatal(g, a)
			}
		})
	}
}
func TestRuleInspectorConditionalPrimaryLogicUnchanged(t *testing.T) {
	process := Rule{ProcessName: "fixture.exe"}
	for _, tc := range []struct {
		name   string
		rule   Rule
		status string
		branch bool
	}{
		{"AND false", Rule{And: []Rule{{Domain: "other.invalid"}, process}, Action: "reject"}, "final", false},
		{"OR true", Rule{Or: []Rule{{DomainSuffix: "ccb233.cn"}, process}, Action: "reject"}, "matched", false},
		{"NOT unknown", Rule{Not: &process, Action: "reject"}, "unknown", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := Options{Rules: []Rule{tc.rule}, Final: "direct"}
			g := riOffline(t, riEngine(t, o), o, OfflineInput{Target: conditionalTarget})
			if g.Status != tc.status || (g.ConditionalAfter != nil) != tc.branch {
				t.Fatal(g)
			}
			if tc.branch && (g.Policy != "" || g.ConditionalAfter.Assumption.Matches || g.ConditionalAfter.Status != "final") {
				t.Fatal(g)
			}
		})
	}
}
func TestRuleInspectorConditionalFrozenResourcesAndSeparateBounds(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "S.json")
	initial := []byte(`{"version":1,"rules":[{"domain":["super-bill.ccb233.cn"]}]}`)
	if err := os.WriteFile(p, initial, 0600); err != nil {
		t.Fatal(err)
	}
	o := Options{Final: "FixtureFinal", RuleSets: []RuleSetOptions{{Name: "S", Format: "sing-box-json", Path: p}}, Rules: []Rule{{ProcessName: "fixture.exe", Action: "reject"}, {RuleSet: "S", Outbound: "OldSnapshotPolicy"}}}
	e := riEngine(t, o)
	// Read the actual production freeze helper, then publish a different valid
	// live value before the secondary evaluation. There is no test-only hook.
	v, sets := e.freezeOffline()
	conditions := []*cond{compileRule(&o.Rules[0], sets), compileRule(&o.Rules[1], sets)}
	m, known, err := offlineMetadata(OfflineInput{Target: conditionalTarget})
	if err != nil {
		t.Fatal(err)
	}
	seed := OfflineResult{Target: conditionalTarget, Known: known}
	primary := v.evaluateFrom(o, conditions, m, 0, seed)
	v.finish(&primary)
	if err = e.RefreshResourceWith(context.Background(), "rule_set", "S", func(string, int64) ([]byte, error) { return []byte(`{"version":1,"rules":[]}`), nil }, nil); err != nil {
		t.Fatal(err)
	}
	branch := &offlineEvaluation{engine: v.engine, resources: v.resources, used: map[string]bool{}}
	after := branch.evaluateFrom(o, conditions, m, primary.BlockedRule, seed)
	branch.finish(&after)
	if primary.Status != "unknown" || len(primary.Resources) != 0 || after.Status != "matched" || after.Policy != "OldSnapshotPolicy" || after.Resources[0].Entries == nil || *after.Resources[0].Entries != 1 {
		t.Fatal("branch reread live publication or leaked resources", primary, after)
	}
	fresh := riOffline(t, e, o, OfflineInput{Target: conditionalTarget})
	if fresh.ConditionalAfter == nil || fresh.ConditionalAfter.Status != "final" || fresh.ConditionalAfter.Resources[0].Entries == nil || *fresh.ConditionalAfter.Resources[0].Entries != 0 {
		t.Fatal("next call must see the new snapshot", fresh)
	}
	// Independent bounds: main only sees its earlier absent set; the branch sees
	// twenty different absent sets, and must not inherit main warnings/counts.
	o = Options{Final: "direct"}
	o.RuleSets = append(o.RuleSets, RuleSetOptions{Name: "PrimaryMissing", Format: "sing-box-json", Path: filepath.Join(dir, "primary-missing.json")})
	o.Rules = []Rule{{RuleSet: "PrimaryMissing", Action: "reject"}, {ProcessName: "fixture.exe", Action: "reject"}}
	var subs []Rule
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("Tail%02d", i)
		o.RuleSets = append(o.RuleSets, RuleSetOptions{Name: name, Format: "sing-box-json", Path: filepath.Join(dir, name+".json")})
		subs = append(subs, Rule{RuleSet: name})
	}
	o.Rules = append(o.Rules, Rule{Or: subs, Action: "reject"})
	g := riOffline(t, riEngine(t, o), o, OfflineInput{Target: conditionalTarget})
	a := g.ConditionalAfter
	if len(g.Resources) != 1 || len(g.ResourceWarnings) != 1 || g.ResourceWarnings[0].Name != "PrimaryMissing" || a == nil || len(a.Resources) != 16 || a.ResourcesMore != 4 || len(a.ResourceWarnings) != 8 || a.ResourceWarningsMore != 12 {
		t.Fatal(g, a)
	}
	for _, r := range a.ResourceWarnings {
		if r.Name == "PrimaryMissing" {
			t.Fatal("main warning copied into branch", a)
		}
	}
}
