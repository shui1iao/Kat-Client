package route

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// candidate31ValidateSubscriptionSetBefore is the exact pre-change function,
// renamed only, from resource_check.go SHA256
// 108471d09bddf635d41e7c14d45e68e28f94b4559dac64105030f24884e39d93.
// Test-local oracle: no production hooks, caches, or changed limits.
func candidate31ValidateSubscriptionSetBefore(s RuleSetOptions, b []byte, deps SubscriptionSetDependencies) (int, error) {
	if len(b) > 16<<20 {
		return 0, errTooLarge
	}
	env := parseEnv{geoip: deps.GeoIP, asn: deps.ASN, geosite: deps.Geosite}
	// Preflight line formats with the actual runtime condition parser. Preserve
	// every invalid entry's position rather than allowing parseLines to skip it.
	var lines []string
	var positions []int
	behavior := s.Behavior
	dialect := dialMihom
	switch s.Format {
	case FormatYAML:
		var err error
		lines, err = yamlPayload(b)
		if err != nil {
			return 0, err
		}
		var doc yaml.Node
		if yaml.Unmarshal(b, &doc) == nil && len(doc.Content) > 0 {
			m := doc.Content[0]
			for j := 0; j+1 < len(m.Content); j += 2 {
				if m.Content[j].Value == "payload" {
					for _, n := range m.Content[j+1].Content {
						positions = append(positions, n.Line)
					}
				}
			}
		}
	case FormatDomain, FormatIPCIDR, FormatClassical, FormatSurgeDomainSet, FormatSurgeRuleSet:
		text, err := textOf(b)
		if err != nil {
			return 0, err
		}
		lines = strings.Split(text, "\n")
		for j := range lines {
			positions = append(positions, j+1)
		}
		switch s.Format {
		case FormatDomain:
			behavior = "domain"
			dialect = dialKat
		case FormatIPCIDR:
			behavior = "ipcidr"
			dialect = dialKat
		case FormatClassical:
			behavior = "classical"
		case FormatSurgeDomainSet:
			behavior = "domain"
			dialect = dialSurge
		case FormatSurgeRuleSet:
			behavior = "classical"
			dialect = dialSurge
		}
	}
	var issues []SubscriptionSetIssue
	for j, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		var err error
		typ := ""
		dependency := ""
		switch behavior {
		case "classical":
			typ, _, _ = strings.Cut(line, ",")
			typ = strings.ToUpper(strings.TrimSpace(typ))
			_, err = parseClassical(line, dialect, fullEnv, 0) // Syntax before dependency.
			if err == nil {
				_, err = parseClassical(line, dialect, env, 0)
			}
			if err == nil && !deps.GeoIP {
				dependency = missingCountryDependency(line, dialect)
				if dependency != "" {
					err = unsupported("database dependency")
				}
			}
		case "domain":
			var d domainSet
			if !d.addDomainEntry(line, dialect) {
				err = errMalformed
			}
		case "ipcidr":
			if _, ok := parseCIDR(line, true); !ok {
				err = errMalformed
			}
		}
		if err == nil {
			continue
		}
		code := "invalid_format"
		var u *unsupportedError
		if errors.As(err, &u) {
			code = "unsupported_type"
			switch {
			case strings.Contains(u.msg, "without an asn block"):
				dependency = "asn"
			case strings.Contains(u.msg, "without a geosite block"):
				dependency = "geosite"
			case strings.HasPrefix(u.msg, "option "):
				code = "unsupported_option"
			}
		}
		if dependency != "" {
			code = "missing_dependency"
		}
		n := 0
		if j < len(positions) {
			n = positions[j]
		}
		issues = append(issues, SubscriptionSetIssue{Resource: s.Name, Entry: j + 1, Line: n, RuleType: typ, Code: code, Dependency: dependency})
	}
	if len(issues) > 0 {
		return 0, &SubscriptionSetValidationError{Issues: issues}
	}
	d, err := parseRuleSetAs(s.Format, s.Behavior, b, maxSetEntries, env)
	if err != nil {
		return 0, err
	}
	if d.skipped != 0 {
		return 0, &SubscriptionSetValidationError{Issues: []SubscriptionSetIssue{{Resource: s.Name, Code: "invalid_format"}}}
	}
	return d.entries, nil
}

// candidate31SameResult checks the complete concrete error value (including
// typed issue fields), error text and sentinel matching, not just success/fail.
func candidate31SameResult(t *testing.T, oldN int, oldErr error, newN int, newErr error) {
	t.Helper()
	if oldN != newN || reflect.TypeOf(oldErr) != reflect.TypeOf(newErr) || !reflect.DeepEqual(oldErr, newErr) {
		t.Fatalf("old=(%d,%T,%#v) new=(%d,%T,%#v)", oldN, oldErr, oldErr, newN, newErr, newErr)
	}
	if oldErr != nil && oldErr.Error() != newErr.Error() {
		t.Fatalf("error strings differ: old=%q new=%q", oldErr.Error(), newErr.Error())
	}
	for _, sentinel := range []error{errParse, errLimit, errTooLarge} {
		if errors.Is(oldErr, sentinel) != errors.Is(newErr, sentinel) {
			t.Fatalf("sentinel %v differs", sentinel)
		}
	}
}

func TestSubscriptionYAMLReuseDifferential(t *testing.T) {
	all := SubscriptionSetDependencies{GeoIP: true, ASN: true, Geosite: true}
	type testCase struct {
		name, format, behavior, input string
		deps                          SubscriptionSetDependencies
		want                          int // -1: fixture count is checked against the exact old oracle.
		wantErr                       bool
	}
	cases := []testCase{
		{name: "domain", format: "yaml", behavior: "domain", input: "payload: [a.example, '+.b.example', '.c.example']\n", want: 3},
		{name: "ipcidr", format: "yaml", behavior: "ipcidr", input: "payload: ['203.0.113.0/24', '2001:db8::/32']\n", want: 2},
		{name: "classical", format: "yaml", behavior: "classical", input: "payload:\n - DOMAIN,a.example\n - PROCESS-NAME,x.exe\n - IP-ASN,13335,no-resolve\n", deps: all, want: 3},
		{name: "whitespace-comments", format: "yaml", behavior: "domain", input: "# physical header\npayload:\n - '  a.example  '\n - '# skip'\n - '; skip'\n - '// skip'\n - ''\n - b.example\n", want: 2},
		{name: "empty-payload", format: "yaml", behavior: "domain", input: "payload: []\n", want: 0},
		{name: "duplicate-entry-count", format: "yaml", behavior: "domain", input: "payload: [a.example, a.example]\n", want: 2},
		{name: "bom", format: "yaml", behavior: "domain", input: "\xef\xbb\xbfpayload: [a.example]\n", want: 1},
		{name: "scalar-conversion", format: "yaml", behavior: "domain", input: "payload: [123, true]\n", want: 2},
		{name: "malformed-yaml", format: "yaml", behavior: "domain", input: "payload: [\n", wantErr: true},
		{name: "multiple-documents", format: "yaml", behavior: "domain", input: "payload: [a.example]\n---\npayload: [b.example]\n", wantErr: true},
		{name: "extra-key", format: "yaml", behavior: "domain", input: "payload: [a.example]\nunknown: true\n", wantErr: true},
		{name: "missing-payload", format: "yaml", behavior: "domain", input: "rules: [a.example]\n", wantErr: true},
		{name: "non-scalar-list", format: "yaml", behavior: "domain", input: "payload: [[a.example, b.example]]\n", wantErr: true},
		{name: "non-scalar-map", format: "yaml", behavior: "domain", input: "payload: [{name: a.example}]\n", wantErr: true},
		{name: "null-scalar", format: "yaml", behavior: "domain", input: "payload: [null]\n", wantErr: true},
		{name: "payload-not-sequence", format: "yaml", behavior: "domain", input: "payload: 5\n", wantErr: true},
		{name: "duplicate-key", format: "yaml", behavior: "domain", input: "payload: [a.example]\npayload: [b.example]\n", wantErr: true},
		{name: "invalid-domain", format: "yaml", behavior: "domain", input: "payload: [good.example, bad..example]\n", wantErr: true},
		{name: "invalid-cidr", format: "yaml", behavior: "ipcidr", input: "payload: [not-a-cidr]\n", wantErr: true},
		{name: "unsupported-type", format: "yaml", behavior: "classical", input: "payload: ['FOO,x']\n", wantErr: true},
		{name: "unsupported-option", format: "yaml", behavior: "classical", input: "payload: ['DOMAIN,a.example,unexpected']\n", wantErr: true},
		{name: "empty-behavior", format: "yaml", input: "payload: [a.example]\n", wantErr: true},
		{name: "unknown-behavior", format: "yaml", behavior: "unexpected", input: "payload: [a.example]\n", wantErr: true},
		{name: "missing-geoip", format: "yaml", behavior: "classical", input: "payload: ['GEOIP,CN']\n", wantErr: true},
		{name: "missing-asn", format: "yaml", behavior: "classical", input: "payload: ['IP-ASN,13335']\n", wantErr: true},
		{name: "missing-geosite", format: "yaml", behavior: "classical", input: "payload: ['GEOSITE,cn']\n", wantErr: true},
		{name: "all-dependencies-present", format: "yaml", behavior: "classical", input: "payload: ['GEOIP,CN', 'IP-ASN,13335', 'GEOSITE,cn']\n", deps: all, want: 3},
		{name: "logical-missing-geoip", format: "yaml", behavior: "classical", input: "payload: ['AND,((DOMAIN,a.example),(GEOIP,CN))']\n", wantErr: true},
		{name: "geo-private-no-db", format: "yaml", behavior: "classical", input: "payload: ['GEOIP,private']\n", want: 1},
		{name: "other-domain", format: "domain", input: "a.example\n+.b.example\n", want: 2},
		{name: "other-domain-invalid", format: "domain", input: "bad..example\n", wantErr: true},
		{name: "other-ipcidr", format: "ipcidr", input: "203.0.113.0/24\n", want: 1},
		{name: "other-classical", format: "classical", input: "DOMAIN,a.example\n", want: 1},
		{name: "other-classical-dependency", format: "classical", input: "IP-ASN,13335\n", wantErr: true},
		{name: "other-surge-domain", format: "surge-domain-set", input: ".a.example\nb.example\n", want: 2},
		{name: "other-surge-rule", format: "surge-ruleset", input: "DOMAIN,a.example\n", want: 1},
		{name: "other-json", format: "sing-box-json", input: `{"version":2,"rules":[{"domain":["a.example"]}]}`, want: 1},
		{name: "other-json-invalid", format: "sing-box-json", input: `{"version":9,"rules":[]}`, wantErr: true},
		{name: "other-srs-invalid", format: "srs", input: "bad", wantErr: true},
		{name: "other-mrs-invalid", format: "mrs", behavior: "domain", input: "bad", wantErr: true},
		{name: "other-unknown-format", format: "unexpected", input: "a.example\n", wantErr: true},
		{name: "input-byte-limit", format: "yaml", behavior: "domain", input: strings.Repeat("x", (16<<20)+1), wantErr: true},
	}
	for _, f := range []struct{ file, format, behavior string }{
		{"sb-v1.json", "sing-box-json", ""}, {"sb-v2.srs", "srs", ""},
		{"mrs-domain.mrs", "mrs", "domain"}, {"mrs-ip.mrs", "mrs", "ipcidr"},
	} {
		b, err := os.ReadFile("testdata/" + f.file)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, testCase{name: "other-fixture-" + f.file, format: f.format, behavior: f.behavior, input: string(b), deps: all, want: -1})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := RuleSetOptions{Name: "synthetic-reuse-test", Format: tc.format, Behavior: tc.behavior}
			b := []byte(tc.input)
			oldN, oldErr := candidate31ValidateSubscriptionSetBefore(s, b, tc.deps)
			newN, newErr := ValidateSubscriptionSetWithDependencies(s, b, tc.deps)
			candidate31SameResult(t, oldN, oldErr, newN, newErr)
			if (newErr != nil) != tc.wantErr || (!tc.wantErr && tc.want >= 0 && newN != tc.want) {
				t.Fatalf("unexpected result: entries=%d err=%v", newN, newErr)
			}
		})
	}
	// Independently pin complete typed diagnostics, including physical lines
	// (payload comments/blank rows are not renumbered away).
	t.Run("physical-lines-and-all-dependencies", func(t *testing.T) {
		b := []byte("# header\npayload:\n  # payload comment\n  - DOMAIN,ok.example\n\n  - GEOIP,CN\n  - IP-ASN,13335\n  - GEOSITE,cn\n")
		s := RuleSetOptions{Name: "synthetic-lines", Format: "yaml", Behavior: "classical"}
		oldN, oldErr := candidate31ValidateSubscriptionSetBefore(s, b, SubscriptionSetDependencies{})
		newN, newErr := ValidateSubscriptionSetWithDependencies(s, b, SubscriptionSetDependencies{})
		candidate31SameResult(t, oldN, oldErr, newN, newErr)
		want := &SubscriptionSetValidationError{Issues: []SubscriptionSetIssue{
			{Resource: s.Name, Entry: 2, Line: 6, RuleType: "GEOIP", Code: "missing_dependency", Dependency: "geoip"},
			{Resource: s.Name, Entry: 3, Line: 7, RuleType: "IP-ASN", Code: "missing_dependency", Dependency: "asn"},
			{Resource: s.Name, Entry: 4, Line: 8, RuleType: "GEOSITE", Code: "missing_dependency", Dependency: "geosite"},
		}}
		if !reflect.DeepEqual(newErr, want) {
			t.Fatalf("diagnostics=%#v want=%#v", newErr, want)
		}
	})
}

func TestSubscriptionYAMLReuseTailDifferential(t *testing.T) {
	// Exercise the exact changed terminal dispatch at small explicit limits;
	// production still passes maxSetEntries unchanged. This avoids a million-
	// row YAML AST fixture merely to reach the same parser boundary.
	for _, tc := range []struct {
		name, behavior, input   string
		limit, entries, skipped int
		wantErr                 error
	}{
		{"at-limit", "domain", "payload: [a.example, b.example]\n", 2, 2, 0, nil},
		{"over-limit", "domain", "payload: [a.example, b.example, c.example]\n", 2, 0, 0, errLimit},
		{"zero-limit", "classical", "payload: ['DOMAIN,a.example']\n", 0, 0, 0, errLimit},
		{"ipcidr-limit", "ipcidr", "payload: ['203.0.113.0/24', '2001:db8::/32']\n", 1, 0, 0, errLimit},
		{"skipped-domain", "domain", "payload: [a.example, bad..example]\n", 2, 1, 1, nil},
		{"skipped-classical", "classical", "payload: ['DOMAIN,a.example', broken]\n", 2, 1, 1, nil},
		{"all-skipped", "domain", "payload: [bad..example]\n", 2, 0, 0, errParse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := []byte(tc.input)
			lines, err := yamlPayload(b)
			if err != nil {
				t.Fatal(err)
			}
			oldD, oldErr := parseRuleSetAs(FormatYAML, tc.behavior, b, tc.limit, fullEnv)
			newD, newErr := parseLines(tc.behavior, dialMihom, lines, tc.limit, fullEnv)
			candidate31SameResult(t, 0, oldErr, 0, newErr)
			if !reflect.DeepEqual(oldD, newD) || !errors.Is(newErr, tc.wantErr) {
				t.Fatalf("old data=%#v new data=%#v err=%v want=%v", oldD, newD, newErr, tc.wantErr)
			}
			if newErr == nil && (newD.entries != tc.entries || newD.skipped != tc.skipped) {
				t.Fatalf("entries/skipped=(%d,%d) want=(%d,%d)", newD.entries, newD.skipped, tc.entries, tc.skipped)
			}
		})
	}
}
