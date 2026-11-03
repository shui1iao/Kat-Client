package clientcore

import (
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/kernel"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestK2IPv6DocumentMigrationAndCompatibility(t *testing.T) {
	for _, format := range []DocumentFormat{FormatJSON, FormatYAML} {
		dir := t.TempDir()
		text := strings.Replace(initialDocument, `,"ipv6":false`, "", 1)
		if format == FormatYAML {
			text = yamlFixture(17890, 17891)
		}
		path := filepath.Join(dir, format.filename())
		if e := os.WriteFile(path, []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
		h, e := Open(dir)
		if e != nil {
			t.Fatal(e)
		}
		if h.doc.client.IPv6 || !h.doc.config.IPv6Disabled() {
			t.Fatal("migration not applied")
		}
		backup, e := os.ReadFile(filepath.Join(dir, "client-before-c16-network."+string(format)))
		if e != nil || string(backup) != text {
			t.Fatal("exact backup", e)
		}
		report, e := os.ReadFile(filepath.Join(dir, "c16-network-migration.json"))
		if e != nil || !strings.Contains(string(report), "client.ipv6=false") {
			t.Fatal("migration report", e)
		}
		root, _ := sourceJSON(h.doc)
		var cl map[string]json.RawMessage
		_ = json.Unmarshal(root["client"], &cl)
		cl["ipv6"] = rawJSON(true)
		root["client"] = rawJSON(cl)
		next, e := renderSubscriptionSource(h.doc, root)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := h.Apply(next, format); e != nil {
			t.Fatal(e)
		}
		h.Close()
		h, e = Open(dir)
		if e != nil {
			t.Fatal(e)
		}
		if !h.doc.client.IPv6 || h.doc.config.IPv6Disabled() {
			t.Fatal("one-time migration reset explicit later choice")
		}
		h.Close()
	}
	for _, value := range []string{"null", `"false"`, "0", "[]", "{}"} {
		text := strings.Replace(initialDocument, `"ipv6":false`, `"ipv6":`+value, 1)
		if _, e := parseDocument(text, t.TempDir()); e == nil {
			t.Fatal("accepted", value)
		}
	}
	if d, e := parseDocument(strings.Replace(initialDocument, `,"ipv6":false`, "", 1), t.TempDir()); e != nil || d.client.IPv6 {
		t.Fatal("old document compatibility", e)
	}
}
func TestK2DownloadPolicyAndClearIPC(t *testing.T) {
	h, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	ctx, done := h.ipContext(context.Background())
	defer done()
	if !ipDisabled(ctx) || ipNetwork(ctx) != "ip4" {
		t.Fatal("default downloads not v4")
	}
	h.setIPPolicy(false)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("old download epoch not canceled")
	}
	if _, e := h.Request(context.Background(), "dns.cache.clear", json.RawMessage(`{}`)); e == nil || e.Code != "core_not_running" {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	v, failure := h.Request(context.Background(), "dns.cache.clear", json.RawMessage(`{}`))
	if failure != nil || v.(map[string]any)["cleared"] != 0 {
		t.Fatal(v, failure)
	}
	if _, e := h.Request(context.Background(), "dns.cache.clear", json.RawMessage(`{"unknown":true}`)); e == nil {
		t.Fatal("invalid clear params")
	}
}

func TestK2YAMLMihomoPolicyRetainsDeclarationOrder(t *testing.T) {
	text := yamlFixture(17890, 17891) + "\n"
	text = strings.Replace(text, "  dns: {server: system}", "  dns:\n    server: system\n    nameserver-policy:\n      +.example.com: 1.1.1.1\n      a.example.com: 8.8.8.8", 1)
	d, e := parseDocument(text, t.TempDir(), FormatYAML)
	if e != nil {
		t.Fatal(e)
	}
	rules, err := kernel.DecodeMihomoDNSPolicy(d.config.DNS.NameserverPolicy)
	if err != nil || len(rules) != 2 || rules[0].Match != "domain_suffix" {
		t.Fatal(rules, err)
	}
	if d.text != text {
		t.Fatal("source rewritten")
	}
}

func TestK2DNSDocumentStyleAndExclusion(t *testing.T) {
	native := strings.Replace(yamlFixture(17890, 17891), "  dns: {server: system}", `  dns:
    server: system
    rules:
      - {match: domain_suffix, domain: example.com, servers: [1.1.1.1, 8.8.8.8]}
      - {match: keyword, domain: internal, servers: [9.9.9.9, 'tcp://1.0.0.1:53']}
      - {match: domain, domain: exact.test, servers: [8.8.4.4]}
    hosts: {'*.local.test': [192.0.2.1, '2001:db8::1']}`, 1)
	projection, err := yamlJSON([]byte(native))
	if err != nil {
		t.Fatal(err)
	}
	h := newHost(t)
	var before []kernel.DNSRule
	for _, f := range []DocumentFormat{FormatJSON, FormatYAML, FormatJSON, FormatYAML} {
		text := native
		if f == FormatJSON {
			text = string(projection)
		}
		if _, failure := h.Apply(text, f); failure != nil {
			t.Fatal(f, failure)
		}
		if h.doc.text != text || h.doc.format != f {
			t.Fatal("source export changed", f)
		}
		if h.doc.config.DNS.NameserverPolicy != nil || len(h.doc.config.DNS.Rules) != 3 || h.doc.config.DNS.Rules[1].Match != "keyword" {
			t.Fatal("keyword was converted", f, h.doc.config.DNS)
		}
		if before != nil && !reflect.DeepEqual(before, h.doc.config.DNS.Rules) {
			t.Fatal("format switch changed keyword rules")
		}
		before = h.doc.config.DNS.Rules
		root, _ := sourceJSON(h.doc)
		var kernelSource map[string]json.RawMessage
		_ = json.Unmarshal(root["kernel"], &kernelSource)
		var dns map[string]json.RawMessage
		_ = json.Unmarshal(kernelSource["dns"], &dns)
		if dns["rules"] == nil || dns["nameserver-policy"] != nil {
			t.Fatal("source representation lost", f)
		}
	}
	policy := strings.Replace(yamlFixture(17890, 17891), "  dns: {server: system}", `  dns:
    server: system
    nameserver-policy:
      +.example.com: [1.1.1.1, 8.8.8.8]
      exact.test: 9.9.9.9`, 1)
	policyJSON, err := yamlJSON([]byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []DocumentFormat{FormatJSON, FormatYAML} {
		text := policy
		if f == FormatJSON {
			text = string(policyJSON)
		}
		if _, failure := h.Apply(text, f); failure != nil {
			t.Fatal(f, failure)
		}
		rules, err := kernel.DecodeMihomoDNSPolicy(h.doc.config.DNS.NameserverPolicy)
		if err != nil || len(rules) != 2 || rules[0].Match != "domain_suffix" || len(rules[0].Servers) != 2 || rules[1].Match != "domain" {
			t.Fatal("policy import", f, rules, err)
		}
		if h.doc.text != text || len(h.doc.config.DNS.Rules) != 0 {
			t.Fatal("policy export spelling changed", f)
		}
	}
	mixed := strings.Replace(native, "    rules:\n", "    nameserver-policy: {'+.example.com': 1.1.1.1}\n    rules:\n", 1)
	mixedJSON, err := yamlJSON([]byte(mixed))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []DocumentFormat{FormatJSON, FormatYAML} {
		text := mixed
		if f == FormatJSON {
			text = string(mixedJSON)
		}
		if _, failure := parseDocument(text, t.TempDir(), f); failure == nil {
			t.Fatal("rules and nameserver-policy both accepted", f)
		}
	}
}
