package provider

import (
	"os"
	"strings"
	"testing"
)

const fullTestYAML = `proxies:
  - {name: n, type: socks5, server: example.org, port: 1080}
proxy-groups:
  - {name: pick, type: select, proxies: [auto, DIRECT]}
  - {name: auto, type: url-test, include-all: true, filter: '^n$'}
rules:
  - DOMAIN,example.org,pick
  - MATCH,auto
`

func TestFullGenericGroupsRules(t *testing.T) {
	f, e := ParseFull([]byte(fullTestYAML), "https://example.org/204")
	if e != nil {
		t.Fatal(e)
	}
	if len(f.Outbounds) != 1 || len(f.Groups) != 2 || len(f.Rules) != 1 || f.Final != "auto" || !f.Groups[1].IncludeAll || f.Groups[1].Filter != "^n$" || len(f.Groups[1].Members) != 0 || f.Groups[0].Members[1] != "direct" {
		t.Fatal("conversion contract")
	}
}
func TestFullRejectsLossyRulesAndGraphs(t *testing.T) {
	for _, s := range []string{
		strings.Replace(fullTestYAML, "DOMAIN,example.org,pick", "PROCESS-UNSUPPORTED,secret,pick", 1),
		strings.Replace(fullTestYAML, "DOMAIN,example.org,pick", "DOMAIN,example.org,pick,no-resolve", 1),
		strings.Replace(fullTestYAML, "MATCH,auto", "MATCH,auto\n  - DOMAIN,a,pick", 1),
		strings.Replace(fullTestYAML, "type: select", "type: unsupported", 1),
		strings.Replace(fullTestYAML, "filter: '^n$'", "filter: '['", 1),
		strings.Replace(fullTestYAML, "port: 1080", "port: 1080, port: 1081", 1),
		"proxies: &x []\nproxy-groups: *x\n",
	} {
		if _, e := ParseFull([]byte(s), "https://example.org/204"); e == nil {
			t.Fatal("accepted lossy/ambiguous input")
		}
	}
}
func TestFullPreservesViaAndBoundedFilter(t *testing.T) {
	s := strings.Replace(fullTestYAML, "server: example.org", "dialer-proxy: auto, server: example.org", 1)
	f, e := ParseFull([]byte(s), "https://example.org/204")
	if e != nil || f.Outbounds[0].Via != "auto" {
		t.Fatal("via lost")
	}
	if !f.Groups[1].IncludeAll || f.Groups[1].Filter != "^n$" {
		t.Fatal("filtered membership lost")
	}
}
func TestFullRealAuthorizedParse(t *testing.T) {
	path := os.Getenv("KAT_AUTHORIZED_SUBSCRIPTION")
	if path == "" {
		t.Skip("explicit private input path not supplied")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("private input unavailable")
	}
	f, e := ParseFull(b, "https://www.gstatic.com/generate_204")
	if e != nil {
		t.Fatal(e)
	}
	if len(f.Outbounds) != 22 || len(f.Groups) != 9 || len(f.Rules) != 14 || len(f.RuleSets) != 8 || f.Final == "" || !f.NeedsGeoIP {
		t.Fatal("authorized input counts or MATCH/GeoIP mismatch")
	}
	types := map[string]int{}
	for _, g := range f.Groups {
		types[g.Type]++
	}
	if types["select"] != 1 || types["fallback"] != 3 || types["url-test"] != 5 {
		t.Fatal("group types mismatch")
	}
	t.Log("authorized conversion: nodes=22 groups=9 explicit_rules=14 MATCH=1 rule_sets=8; no private content emitted")
}

func TestFullRuleOnlyAndTextSets(t *testing.T) {
	f, e := ParseFull([]byte("proxy-groups: [{name: local, type: select, proxies: [DIRECT]}]\nrules: [MATCH,local]\n"), "https://example.org/204")
	_ = f
	_ = e
	// Quote the comma-separated rule, as in Clash YAML; an unquoted flow-list is
	// multiple rules and must reject, not silently concatenate values.
	if e == nil {
		t.Fatal("ambiguous flow rules accepted")
	}
	f, e = ParseFull([]byte("proxy-groups: [{name: local, type: select, proxies: [DIRECT]}]\nrules: ['MATCH,local']\n"), "https://example.org/204")
	if e != nil || len(f.Outbounds) != 0 || len(f.Groups) != 1 || f.Final != "local" {
		t.Fatal("optional proxies not supported")
	}
	f, e = ParseFull([]byte("proxies: []\nrule-providers:\n  set: {type: http, behavior: classical, format: text, url: https://example.org/rules}\nrules: ['RULE-SET,set,DIRECT,no-resolve']\n"), "https://example.org/204")
	if e != nil || f.RuleSets[0].Format != "classical" || !f.Rules[0].NoResolve {
		t.Fatal("text/classical conversion lost semantics")
	}
}

func TestFullProcessAndASNConversion(t *testing.T) {
	f, e := ParseFull([]byte(strings.Replace(fullTestYAML, "DOMAIN,example.org,pick", "PROCESS-NAME,example.exe,pick", 1)), "https://example.org/204")
	if e != nil || f.Rules[0].ProcessName != "example.exe" {
		t.Fatal("PROCESS-NAME not converted")
	}
	f, e = ParseFull([]byte(strings.Replace(fullTestYAML, "DOMAIN,example.org,pick", "IP-ASN,13335,pick,no-resolve", 1)), "https://example.org/204")
	if e != nil || !f.NeedsASN || !f.Rules[0].NoResolve {
		t.Fatal("ASN dependency/no-resolve lost")
	}
}
