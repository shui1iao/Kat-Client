package clientcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/provider"
	"net"
	"net/netip"
	"os"
	"path/filepath"

	"strings"
	"testing"

	"github.com/oschwald/maxminddb-golang"
	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/route"
)

const fullFixture = `proxies:
  - {name: n, type: socks5, server: example.org, port: 1080}
proxy-groups:
  - {name: pick, type: select, proxies: [n, DIRECT]}
rules:
  - DOMAIN,example.org,pick
  - MATCH,pick
`

func fullPreview(t *testing.T, h *Host, text string, id string) *subscriptionPreview {
	t.Helper()
	v, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"text": text, "id": id}))
	if e != nil {
		t.Fatal(e)
	}
	p, ok := v.(subscriptionPreview)
	if !ok || len(p.Issues) > 0 || p.Token == "" {
		t.Fatalf("preview rejected: %+v", p.Issues)
	}
	return &p
}
func fullHost(t *testing.T) *Host {
	t.Helper()
	h, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { h.Close() })
	return h
}
func TestFullSubscriptionAcceptRefreshOwnBlock(t *testing.T) {
	h := fullHost(t)
	manual := strings.Replace(initialDocument, `"kernel":{}`, `"kernel":{"outbounds":[{"name":"manual","type":"socks5","server":"manual.invalid","port":9}],"routing":{"rules":[{"domain":"manual.invalid","action":"direct"}],"final":"direct"}}`, 1)
	if _, e := h.Apply(manual); e != nil {
		t.Fatal(e)
	}
	p := fullPreview(t, h, fullFixture, "")
	if !p.NeedsConfirmation {
		t.Fatal("initial precedence change not confirmed")
	}
	if _, e := h.Apply(p.Text, p.Format); e != nil {
		t.Fatal(e)
	}
	if h.fullPending != nil {
		t.Fatal("accepted preview not released")
	}
	q := fullPreview(t, h, strings.Replace(fullFixture, "example.org,pick", "changed.org,pick", 1), p.ID)
	if !q.NeedsConfirmation {
		t.Fatal("changed rules with manual neighbors require confirmation")
	}
	if _, e := h.Apply(q.Text); e != nil {
		t.Fatal(e)
	}
	r := fullPreview(t, h, strings.Replace(fullFixture, "example.org,pick", "changed.org,pick", 1), p.ID)
	if r.NeedsConfirmation {
		t.Fatal("identical owned block unnecessarily prompts")
	}
	if _, e := h.Apply(r.Text); e != nil {
		t.Fatal(e)
	}
	root, _ := sourceJSON(h.doc)
	var k map[string]json.RawMessage
	_ = json.Unmarshal(root["kernel"], &k)
	if len(rawArray(k, "outbounds")) != 2 || len(rawArray(k, "groups")) != 1 {
		t.Fatal("duplicates or lost manual item")
	}
	var routing map[string]json.RawMessage
	_ = json.Unmarshal(k["routing"], &routing)
	a := rawArray(routing, "rules")
	if len(a) != 2 || !strings.Contains(string(a[0]), "manual.invalid") || !strings.Contains(string(a[1]), "changed.org") {
		t.Fatal("manual priority or replacement lost")
	}
	subs, e := subscriptionsOf(root)
	if e != nil || len(subs) != 1 || subs[0].ID != p.ID {
		t.Fatal("ownership not persisted")
	}
}
func TestFullSubscriptionCancelStaleAndManualConflict(t *testing.T) {
	h := fullHost(t)
	p := fullPreview(t, h, fullFixture, "")
	dir := h.fullPending.Dir
	before := h.doc.text
	if _, e := h.cancelSubscription(rawJSON(map[string]any{"token": p.Token})); e != nil {
		t.Fatal(e)
	}
	if h.doc.text != before {
		t.Fatal("cancel changed source")
	}
	if _, e := os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("cancel left staged cache")
	}
	p = fullPreview(t, h, fullFixture, "")
	modified := strings.Replace(h.doc.text, `"global_group":""`, `"global_group":"unused"`, 1)
	if _, e := h.Apply(modified); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Apply(p.Text); e == nil || e.Code != "candidate_expired" {
		t.Fatal("stale candidate overwrote accepted state")
	}
	p = fullPreview(t, h, fullFixture, "")
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	changed := strings.Replace(h.doc.text, `"server": "example.org"`, `"server": "manual-change.invalid"`, 1)
	if changed == h.doc.text {
		t.Fatal("fixture edit did not apply")
	}
	if _, e := h.Apply(changed); e != nil {
		t.Fatal(e)
	}
	_, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"text": fullFixture, "id": p.ID}))
	if e == nil || e.Code != "subscription_conflict" {
		t.Fatal("refresh erased manual edit")
	}
}
func TestFullSubscriptionCollisionNamesAndExternalReference(t *testing.T) {
	h := fullHost(t)
	manual := strings.Replace(initialDocument, `"kernel":{}`, `"kernel":{"outbounds":[{"name":"n","type":"socks5","server":"manual.invalid","port":9}]}`, 1)
	if _, e := h.Apply(manual); e != nil {
		t.Fatal(e)
	}
	p := fullPreview(t, h, fullFixture, "")
	if !p.NeedsConfirmation || !strings.Contains(p.Text, "@") {
		t.Fatal("collision preview missing")
	}
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	var root map[string]json.RawMessage
	_ = json.Unmarshal([]byte(h.doc.text), &root)
	var k map[string]json.RawMessage
	_ = json.Unmarshal(root["kernel"], &k)
	gs := rawArray(k, "groups")
	var owned struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(gs[0], &owned)
	gs = append(gs, rawJSON(map[string]any{"name": "external", "type": "select", "members": []string{owned.Name}}))
	k["groups"] = rawJSON(gs)
	root["kernel"] = rawJSON(k)
	if _, e := h.Apply(string(rawJSON(root))); e != nil {
		t.Fatal(e)
	}
	s := strings.ReplaceAll(fullFixture, "pick", "new-pick")
	_, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"text": s, "id": p.ID}))
	if e == nil || e.Code != "subscription_conflict" {
		t.Fatal("deleted group still referenced externally")
	}
}
func TestFullSubscriptionYAMLPreservesLocalAndComments(t *testing.T) {
	h := fullHost(t)
	yaml := `# user header
schema_version: 1
client:
  mode: rule # preserve mode
  global_group: ''
  probe_url: https://www.gstatic.com/generate_204
  http_port: 7890 # local port
  socks_port: 7891
kernel: {}
`
	if _, e := h.Apply(yaml, FormatYAML); e != nil {
		t.Fatal(e)
	}
	p := fullPreview(t, h, fullFixture, "")
	if p.Format != FormatYAML || !strings.Contains(p.Text, "# user header") || !strings.Contains(p.Text, "# local port") || !strings.Contains(p.Text, "# preserve mode") {
		t.Fatal("format or local comments lost")
	}
	if _, e := h.Apply(p.Text, FormatYAML); e != nil {
		t.Fatal(e)
	}
}
func TestFullSubscriptionFetchFailureKeepsOld(t *testing.T) {
	h := fullHost(t)
	p := fullPreview(t, h, fullFixture, "")
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	before := h.doc.text
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		return nil, errors.New("private must not escape")
	}
	_, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"url": "https://example.org/config"}))
	if e == nil || strings.Contains(e.Error(), "private") || h.doc.text != before {
		t.Fatal("fetch failure lost state or leaked error")
	}
}
func TestFullSubscriptionReopenAndNoDuplicate(t *testing.T) {
	dir := t.TempDir()
	h, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	p := fullPreview(t, h, fullFixture, "")
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	h.Close()
	h, e = Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	q := fullPreview(t, h, fullFixture, p.ID)
	if _, e := h.Apply(q.Text); e != nil {
		t.Fatal(e)
	}
	if len(h.doc.config.Outbounds) != 1 || len(h.doc.config.Groups) != 1 {
		t.Fatal("reopen duplicates")
	}
}
func TestFullRealAuthorizedResources(t *testing.T) {
	path := os.Getenv("KAT_AUTHORIZED_SUBSCRIPTION")
	if path == "" {
		t.Skip("explicit authorized private input not supplied")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("private input unavailable")
	}
	h := fullHost(t)
	if dir := os.Getenv("KAT_RESOURCE_EVIDENCE"); dir != "" {
		f, err := provider.ParseFull(b, h.doc.client.ProbeURL)
		if err != nil {
			t.Fatal("authorized parse failed")
		}
		paths := map[string]string{subscriptionGeoURL: "country.mmdb", subscriptionASNURL: "asn.mmdb"}
		for i, rs := range f.RuleSets {
			paths[rs.URL] = fmt.Sprintf("%d.yaml", i)
		}
		h.fullFetch = func(_ context.Context, url string, _ *clientegress.Policy, _ int64) ([]byte, error) {
			name, ok := paths[url]
			if !ok {
				return nil, errors.New("unexpected resource request")
			}
			return os.ReadFile(filepath.Join(dir, name))
		}
	}
	p := fullPreview(t, h, string(b), "")
	if p.Counts["nodes"] != 22 || p.Counts["groups"] != 9 || p.Counts["rules"] != 14 || p.Counts["match"] != 1 || p.Counts["rule_sets"] != 8 {
		t.Fatal("real input conversion counts mismatch")
	}
	if _, e := h.Apply(p.Text, p.Format); e != nil {
		t.Fatal(e)
	}
	// Reopen the exact accepted real source/cache, not a parser-only fixture.
	fetch := h.fullFetch
	workspace := h.workspace
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(workspace)
	if err != nil {
		t.Fatal("real full source/cache did not reopen")
	}
	t.Cleanup(func() { reopened.Close() })
	h = reopened
	h.fullFetch = fetch
	rootSaved, _ := sourceJSON(h.doc)
	owned, err := subscriptionsOf(rootSaved)
	if err != nil || len(owned) != 1 || owned[0].ID != p.ID {
		t.Fatal("real ownership lost on reopen")
	}
	if h.doc.config.GeoIP == nil {
		t.Fatal("country DB missing")
	}
	geo, e := os.ReadFile(h.doc.config.GeoIP.Path)
	if e != nil {
		t.Fatal("country cache missing")
	}
	db, e := maxminddb.FromBytes(geo)
	if e != nil {
		t.Fatal("country format")
	}
	defer db.Close()
	var rec struct {
		Country struct {
			ISO string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if db.Lookup(net.ParseIP("223.5.5.5"), &rec) != nil || rec.Country.ISO != "CN" {
		t.Fatal("actual CN field lookup mismatch")
	}
	sum := sha256.Sum256(geo)
	t.Logf("actual MMDB: bytes=%d sha256=%s ip_version=%d nodes=%d country.iso_code(223.5.5.5)=CN", len(geo), hex.EncodeToString(sum[:]), db.Metadata.IPVersion, db.Metadata.NodeCount)
	for _, s := range h.doc.config.RuleSets {
		content, e := os.ReadFile(s.Path)
		if e != nil {
			t.Fatal("rule cache missing")
		}
		n, e := route.ValidateSubscriptionSetWithDependencies(route.RuleSetOptions(s), content, route.SubscriptionSetDependencies{GeoIP: true, ASN: true})
		if e != nil {
			t.Fatal("actual rule resource parser rejected")
		}
		if !strings.HasPrefix(s.Path, h.workspace+string(filepath.Separator)) || strings.Contains(s.Path, "../") {
			t.Fatal("untrusted original cache path")
		}
		sum := sha256.Sum256(content)
		t.Logf("actual rule cache: entries=%d bytes=%d sha256=%s", n, len(content), hex.EncodeToString(sum[:]))
	}
	r := route.Options{Rules: []route.Rule{{Domain: "sample.invalid", Action: "reject"}, {GeoIP: "CN", Action: "direct"}}, Final: "reject", GeoIP: &route.GeoIPOptions{Path: h.doc.config.GeoIP.Path}}
	engine, e := route.NewEngine(r, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer engine.Close()
	decision, e := engine.Decide(context.Background(), route.Metadata{Host: "sample.invalid"}, nil)
	if e != nil || decision.Kind != route.Reject || decision.Rule != 1 {
		t.Fatal("ordered domain rule lost")
	}
	decision, e = engine.Decide(context.Background(), route.Metadata{IP: netip.MustParseAddr("223.5.5.5")}, nil)
	if e != nil || decision.Kind != route.Direct || decision.Rule != 2 {
		t.Fatal("actual CN decision lost")
	}
	decision, e = engine.Decide(context.Background(), route.Metadata{IP: netip.MustParseAddr("8.8.8.8")}, nil)
	if e != nil || decision.Kind != route.Reject || decision.Rule != 0 {
		t.Fatal("MATCH final lost")
	}

	if h.doc.config.ASN == nil {
		t.Fatal("required ASN database missing")
	}
	asnBytes, err := os.ReadFile(h.doc.config.ASN.Path)
	if err != nil || route.ValidateSubscriptionASN(asnBytes) != nil {
		t.Fatal("actual ASN runtime format failed")
	}
	// Actual accepted policy: first-match domain route, without any node traffic.
	var opts route.Options
	opts.Final = h.doc.config.Routing.Final
	for _, rr := range h.doc.config.Routing.Rules {
		var rule route.Rule
		if json.Unmarshal(rawJSON(rr), &rule) != nil {
			t.Fatal("actual rule projection failed")
		}
		opts.Rules = append(opts.Rules, rule)
	}
	for _, rs := range h.doc.config.RuleSets {
		opts.RuleSets = append(opts.RuleSets, route.RuleSetOptions(rs))
	}
	opts.GeoIP = &route.GeoIPOptions{Path: h.doc.config.GeoIP.Path}
	opts.ASN = &route.GeoIPOptions{Path: h.doc.config.ASN.Path}
	actual, err := route.NewEngine(opts, nil, nil)
	if err != nil {
		t.Fatal("actual policy engine failed")
	}
	defer actual.Close()
	first := opts.Rules[0]
	host := first.Domain
	if first.DomainKeyword != "" {
		host = "x" + first.DomainKeyword + "x.example"
	}
	if first.DomainSuffix != "" {
		host = "x." + first.DomainSuffix
	}
	if host != "" {
		d, err := actual.Decide(context.Background(), route.Metadata{Host: host, Network: "tcp", Port: 443, ProcessStatus: "known", ProcessName: "subscription-validation.exe"}, func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
		})
		if err != nil || d.Rule != 1 {
			t.Fatalf("actual ordered first-match rule failed: rule=%d kind=%d error_present=%t", d.Rule, d.Kind, err != nil)
		}
		if first.Outbound != "" && d.Outbound != first.Outbound {
			t.Fatal("actual rule target changed")
		}
	}
	// An unchanged full refresh does not append; direct group choices survive.
	choice := ""
	if g := h.doc.config.Groups[0]; g.Type == "select" && len(g.Members) > 0 {
		choice = g.Members[len(g.Members)-1]
		root, _ := sourceJSON(h.doc)
		var k map[string]json.RawMessage
		_ = json.Unmarshal(root["kernel"], &k)
		groups := rawArray(k, "groups")
		var selected map[string]json.RawMessage
		_ = json.Unmarshal(groups[0], &selected)
		selected["selected"] = rawJSON(choice)
		groups[0] = rawJSON(selected)
		k["groups"] = rawJSON(groups)
		root["kernel"] = rawJSON(k)
		if _, err := h.Apply(string(rawJSON(root))); err != nil {
			t.Fatal("imported select not editable")
		}
	}
	q := fullPreview(t, h, string(b), p.ID)
	if q.NeedsConfirmation {
		t.Fatal("unchanged real refresh unexpectedly prompts")
	}
	if _, err := h.Apply(q.Text); err != nil {
		t.Fatal(err)
	}
	if choice != "" && h.doc.config.Groups[0].Selected != choice {
		t.Fatal("manual imported group choice lost during refresh")
	}
	if len(h.doc.config.Outbounds) != 22 || len(h.doc.config.Groups) != 9 || len(h.doc.config.Routing.Rules) != 14 {
		t.Fatal("real refresh duplicated or lost declarations")
	}
	root, _ := sourceJSON(h.doc)
	var client map[string]json.RawMessage
	_ = json.Unmarshal(root["client"], &client)
	client["mode"] = rawJSON("global")
	client["global_group"] = rawJSON(h.doc.config.Groups[0].Name)
	root["client"] = rawJSON(client)
	if _, err := h.Apply(string(rawJSON(root))); err != nil {
		t.Fatal(err)
	}
	if h.doc.config.Routing.Final != h.doc.config.Groups[0].Name || len(h.doc.config.Routing.Rules) != 0 {
		t.Fatal("global mode did not use chosen imported group")
	}
	t.Log("real complete source accepted: 22/9/14+MATCH/8; all required resource bytes validated")
}
