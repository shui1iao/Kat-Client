package route

// Source-only regression fixtures. Resolver callbacks return hand-written IPs;
// no fixture dials a target or starts a DNS server.
import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestTargetSkipsOnlyMissingContextAndKeepsOrder(t *testing.T) {
	e := &Engine{}
	options := Options{Rules: []Rule{{ProcessName: "browser.exe", Outbound: "process"}, {DomainSuffix: "example.com", Outbound: "domain"}}, Final: "direct"}
	calls := 0
	out, err := e.TestTarget(context.Background(), options, OfflineInput{Target: "https://a.example.com/path"}, func(context.Context, string) ([]netip.Addr, error) {
		calls++
		return nil, errors.New("unexpected lookup")
	})
	if err != nil || out.Status != "matched" || out.Rule != 2 || out.Policy != "domain" || calls != 0 {
		t.Fatal(out, err, calls)
	}
	if len(out.Skipped) != 1 || out.Skipped[0].Rule != 1 || !hasTargetMissing(out.Skipped[0].Missing, "process_name") {
		t.Fatal(out.Skipped)
	}
	if out.Known.ProcessName != "" || out.Known.Network != "" || out.DNS.Status != "not_needed" {
		t.Fatal("invented context", out)
	}
}

func TestTargetDNSUsesFirstNonRejectCandidate(t *testing.T) {
	e := &Engine{}
	options := Options{Rules: []Rule{{IPCIDR: "10.0.0.0/8", Action: "reject"}, {DomainSuffix: "example.com", Outbound: "domain"}}, Final: "direct"}
	calls := 0
	out, err := e.TestTarget(context.Background(), options, OfflineInput{Target: "example.com"}, func(_ context.Context, host string) ([]netip.Addr, error) {
		calls++
		if host != "example.com" {
			t.Fatal(host)
		}
		return []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("203.0.113.10")}, nil
	})
	if err != nil || calls != 1 || out.Rule != 2 || out.Policy != "domain" || out.DNS.SelectedIP != "203.0.113.10" || !out.DNS.DifferentRules {
		t.Fatal(out, err, calls)
	}
	if len(out.IPResults) != 2 || out.IPResults[0].Policy != "reject" {
		t.Fatal(out.IPResults)
	}
}

func TestTargetDNSDoesNotReconsiderEarlierNoResolveRules(t *testing.T) {
	e := &Engine{}
	options := Options{Rules: []Rule{{IPCIDR: "192.0.2.0/24", NoResolve: true, Outbound: "earlier"}, {IPCIDR: "0.0.0.0/0", Action: "direct"}}, Final: "reject"}
	out, err := e.TestTarget(context.Background(), options, OfflineInput{Target: "example.com"}, func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
	})
	if err != nil || out.Rule != 2 || out.Policy != "direct" {
		t.Fatal(out, err)
	}
}

func TestTargetUnloadedSetMatchesRuntimeEmptyBehavior(t *testing.T) {
	rs := &ruleSet{src: &source{name: "unloaded"}}
	e := &Engine{sets: []*ruleSet{rs}}
	options := Options{Rules: []Rule{{RuleSet: "unloaded", Outbound: "set"}, {DomainSuffix: "example.com", Outbound: "domain"}}, RuleSets: []RuleSetOptions{{Name: "unloaded", Format: "domain", Path: "not-opened-by-this-api"}}, Final: "direct"}
	out, err := e.TestTarget(context.Background(), options, OfflineInput{Target: "example.com"}, nil)
	if err != nil || out.Rule != 2 || out.Policy != "domain" || out.Status != "matched" {
		t.Fatal(out, err)
	}
	if rs.data.Load() != nil {
		t.Fatal("live unloaded resource mutated")
	}
	if len(out.ResourceWarnings) != 1 || out.ResourceWarnings[0].Warning != "not_loaded" {
		t.Fatal(out.ResourceWarnings)
	}
}

func TestTargetFailedDNSNeverGuessesLaterRule(t *testing.T) {
	e := &Engine{}
	options := Options{Rules: []Rule{{IPCIDR: "192.0.2.0/24", Action: "direct"}}, Final: "fallback"}
	out, err := e.TestTarget(context.Background(), options, OfflineInput{Target: "example.com"}, func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("fixture lookup failure") })
	if err != nil || out.Status != "unknown" || out.DNS.Status != "failed" || out.Policy != "" || out.BlockedRule != 1 || out.ConditionalAfter != nil {
		t.Fatal(out, err)
	}
}

func TestTargetShortCircuitAndIPNeverResolve(t *testing.T) {
	e := &Engine{}
	options := Options{Rules: []Rule{{And: []Rule{{ProcessName: "browser.exe"}, {Domain: "different.example"}}, Outbound: "impossible"}, {IPCIDR: "192.0.2.0/24", Outbound: "ip"}}, Final: "direct"}
	out, err := e.TestTarget(context.Background(), options, OfflineInput{Target: "192.0.2.7"}, func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("IP input must not resolve")
		return nil, nil
	})
	if err != nil || out.Rule != 2 || out.Policy != "ip" || len(out.Skipped) != 0 || out.DNS.Status != "not_needed" {
		t.Fatal(out, err)
	}
	options = Options{Rules: []Rule{{Or: []Rule{{ProcessName: "browser.exe"}, {DomainSuffix: "example.com"}}, Outbound: "known"}}, Final: "direct"}
	out, err = e.TestTarget(context.Background(), options, OfflineInput{Target: "example.com"}, nil)
	if err != nil || out.Rule != 1 || out.Policy != "known" || len(out.Skipped) != 0 {
		t.Fatal(out, err)
	}
}
