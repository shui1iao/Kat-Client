package route

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestParsePreviewTarget(t *testing.T) {
	valid := []struct {
		in   string
		host string
		kind string
		addr []string
	}{
		{"Example.COM.", "example.com", "domain", []string{}},
		{"https://Sub.Example.com:8443/path?a=1", "sub.example.com", "domain", []string{}},
		{"http://1.1.1.1:8080/test", "1.1.1.1", "ip", []string{"1.1.1.1"}},
		{"2001:4860:4860::8888", "2001:4860:4860::8888", "ip", []string{"2001:4860:4860::8888"}},
		{"https://[2606:4700:4700::1111]:443/dns-query", "2606:4700:4700::1111", "ip", []string{"2606:4700:4700::1111"}},
	}
	for _, tc := range valid {
		got, _, err := ParsePreviewTarget(tc.in)
		if err != nil {
			t.Fatalf("ParsePreviewTarget(%q) unexpected error: %v", tc.in, err)
		}
		if got.Host != tc.host || got.Kind != tc.kind || len(got.Addresses) != len(tc.addr) {
			t.Fatalf("ParsePreviewTarget(%q) = %+v, want host=%q kind=%q", tc.in, got, tc.host, tc.kind)
		}
	}

	invalid := []string{
		"",
		"   ",
		"https://user:pass@example.com/",
		"http://user@example.com",
		"socks5://example.com:1080",
		"example.com/path",
		"https://example.com#frag",
		"1.2.3.999",
		"http://2001:db8::1/test",
		"fe80::1%eth0",
	}
	for _, in := range invalid {
		if _, _, err := ParsePreviewTarget(in); err == nil {
			t.Fatalf("ParsePreviewTarget(%q) succeeded, want error", in)
		}
	}
}

func TestPreviewTargetProjectionAndOrder(t *testing.T) {
	dir := t.TempDir()
	rsPath := filepath.Join(dir, "proxy.txt")
	if err := os.WriteFile(rsPath, []byte(".ruleset.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := Options{
		Final: "direct",
		RuleSets: []RuleSetOptions{
			{Name: "ProxySet", Format: FormatDomain, Path: rsPath},
		},
		Rules: []Rule{
			{ProcessName: "curl", Outbound: "proc-out"},
			{And: []Rule{{ProcessName: "chrome"}, {DstPort: "443"}}, Outbound: "empty-and"},
			{And: []Rule{{ProcessName: "chrome"}, {DomainSuffix: "and.example"}}, Outbound: "and-out"},
			{RuleSet: "ProxySet", Outbound: "set-out"},
			{IPCIDR: "203.0.113.0/24", NoResolve: true, Outbound: "nr-ip"},
			{IPCIDR: "203.0.113.0/24", Outbound: "resolved-ip"},
		},
	}
	eng, err := NewReadOnlyEngine(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	dnsCalls := 0
	resolver := func(_ context.Context, host string) ([]netip.Addr, error) {
		dnsCalls++
		return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
	}

	// 1. Combined AND keeps target sub-condition and drops process_name; hits index 3 without DNS.
	res, err := eng.PreviewTarget(context.Background(), opts, "https://sub.and.example/path", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched.Source != "rule" || res.Matched.Index == nil || *res.Matched.Index != 3 || res.Matched.Policy != "and-out" || res.Resolved || dnsCalls != 0 {
		t.Fatalf("unexpected AND preview: %+v (dnsCalls=%d)", res, dnsCalls)
	}

	// 2. Rule-set hits index 4 without DNS.
	res, err = eng.PreviewTarget(context.Background(), opts, "api.ruleset.example", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched.Source != "rule" || res.Matched.Index == nil || *res.Matched.Index != 4 || res.Matched.Type != "RULE-SET" || res.Matched.Payload != "ProxySet" || res.Resolved || dnsCalls != 0 {
		t.Fatalf("unexpected RULE-SET preview: %+v (dnsCalls=%d)", res, dnsCalls)
	}

	// 3. Domain reaching IP rule skips no_resolve rule (index 5) and resolves once for index 6.
	res, err = eng.PreviewTarget(context.Background(), opts, "ip-match.example", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched.Source != "rule" || res.Matched.Index == nil || *res.Matched.Index != 6 || res.Matched.Type != "IP-CIDR" || !res.Resolved || dnsCalls != 1 {
		t.Fatalf("unexpected IP-CIDR preview: %+v (dnsCalls=%d)", res, dnsCalls)
	}

	// 4. Unmatched target falls back to FINAL.
	res, err = eng.PreviewTarget(context.Background(), opts, "198.51.100.1", resolver)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched.Source != "final" || res.Matched.Index != nil || res.Matched.Policy != "direct" || res.Resolved {
		t.Fatalf("unexpected FINAL preview: %+v", res)
	}

	// 5. DNS error surfaces instead of silently returning FINAL.
	_, err = eng.PreviewTarget(context.Background(), opts, "dns-fail.example", func(context.Context, string) ([]netip.Addr, error) {
		return nil, errors.New("lookup failed")
	})
	if err == nil {
		t.Fatal("expected DNS error, got nil")
	}
}
