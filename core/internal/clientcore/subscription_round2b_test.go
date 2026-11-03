package clientcore

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/provider"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func bAccept(t *testing.T, h *Host, p *subscriptionPreview) {
	t.Helper()
	if _, e := h.Apply(p.Text, p.Format); e != nil {
		t.Fatal(e)
	}
}
func bSubs(t *testing.T, h *Host) []fullSubscription {
	t.Helper()
	r, _ := sourceJSON(h.doc)
	s, e := subscriptionsOf(r)
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func bEdit(t *testing.T, h *Host, edit func(map[string]json.RawMessage)) {
	t.Helper()
	r, _ := sourceJSON(h.doc)
	edit(r)
	text, e := renderSubscriptionSource(h.doc, r)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
}
func TestRound2BUserInfo(t *testing.T) {
	for _, tc := range []struct {
		header        string
		valid         bool
		total, expire bool
	}{{"upload=100; download=200; total=1000; expire=1", true, true, true}, {"", false, false, false}, {"upload=x; download=2", false, false, false}, {"upload=-1; download=2", false, false, false}, {"upload=1; download=2; total=0", true, false, false}, {"upload=1;download=2;expire=0", true, false, false}, {"upload=1;upload=2;download=3", false, false, false}} {
		t.Run(tc.header, func(t *testing.T) {
			v := parseSubscriptionUserInfo(tc.header)
			if (v != nil) != tc.valid {
				t.Fatalf("%+v", v)
			}
			if v != nil && ((v.Total != nil) != tc.total || (v.Expire != nil) != tc.expire) {
				t.Fatalf("%+v", v)
			}
		})
	}
	h := fullHost(t)
	h.fullFetch = func(ctx context.Context, _ string, _ *clientegress.Policy, _ int64) ([]byte, error) {
		captureSubscriptionHeaders(ctx, http.Header{"Subscription-Userinfo": []string{"upload=100; download=200; total=1000; expire=1"}, "Profile-Update-Interval": []string{"24"}})
		return []byte(fullFixture), nil
	}
	v, e := h.Request(context.Background(), "subscription.preview", rawJSON(map[string]any{"url": "https://source.invalid/private?secret=TEST", "follow_interval": true}))
	if e != nil {
		t.Fatal(e)
	}
	p := v.(subscriptionPreview)
	bAccept(t, h, &p)
	s := bSubs(t, h)[0]
	if s.UserInfo == nil || s.Interval != 86400 || s.UserInfo.Upload != 100 {
		t.Fatalf("%+v", s)
	}
	accepted := h.doc.text
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		return nil, dl("resolve", "dns_failed")
	}
	_, e = h.Request(context.Background(), "subscription.preview", rawJSON(map[string]any{"id": s.ID}))
	if e == nil || e.Reason != "network_dns" || h.doc.text != accepted {
		t.Fatalf("%+v", e)
	}
	statuses := h.subscriptionStatusesLocked()
	if statuses[s.ID].NextDue-statuses[s.ID].Finished != 1800 {
		t.Fatal(statuses)
	}
	b, _ := os.ReadFile(h.workspace + "/subscription-attempts.json")
	if strings.Contains(string(b), "secret") || strings.Contains(string(b), "https://") {
		t.Fatal("unsafe diagnostic")
	}
	_ = h.Close()
	reopened, e2 := Open(h.workspace)
	if e2 != nil {
		t.Fatal(e2)
	}
	defer reopened.Close()
	if bSubs(t, reopened)[0].UserInfo.Upload != 100 || reopened.subscriptionStatusesLocked()[s.ID].Reason != "network_dns" {
		t.Fatal("not persisted")
	}
}
func TestRound2BWeightedDeletion(t *testing.T) {
	h := fullHost(t)
	fixture := strings.Replace(fullFixture, "type: select", "type: url-test", 1)
	p := fullPreview(t, h, fixture, "")
	bAccept(t, h, p)
	bEdit(t, h, func(r map[string]json.RawMessage) {
		k := rawObject(r["kernel"])
		groups := rawArray(k, "groups")
		g := rawObject(groups[0])
		g["priority"] = rawJSON(map[string]float64{"n": 2, "direct": 1.5})
		groups[0] = rawJSON(g)
		k["groups"] = rawJSON(groups)
		r["kernel"] = rawJSON(k)
	})
	updated := strings.Replace(fixture, "proxies: [n, DIRECT]", "proxies: [DIRECT]", 1)
	updated = strings.Replace(updated, "  - {name: n, type: socks5, server: example.org, port: 1080}\n", "", 1)
	updated = strings.Replace(updated, "proxies:\n", "proxies: []\n", 1)
	q := fullPreview(t, h, updated, p.ID)
	bAccept(t, h, q)
	var g map[string]any
	_ = json.Unmarshal(rawArrayMust(func() []byte { r, _ := sourceJSON(h.doc); return r["kernel"] }(), "groups")[0], &g)
	if strings.Contains(string(rawJSON(g["priority"])), "\"n\"") {
		t.Fatal(g)
	}
}
func TestRound2BMultipleProfiles(t *testing.T) {
	h := fullHost(t)
	p := fullPreview(t, h, fullFixture, "")
	bAccept(t, h, p)
	q := fullPreview(t, h, strings.ReplaceAll(fullFixture, "pick", "other"), "")
	bAccept(t, h, q)
	if len(h.doc.config.Groups) != 1 || h.doc.config.Groups[0].Name != "pick" || subActive(bSubs(t, h)[1]) {
		t.Fatal("inactive import changed runtime")
	}
	bEdit(t, h, func(r map[string]json.RawMessage) {
		k := rawObject(r["kernel"])
		gs := rawArray(k, "groups")
		g := rawObject(gs[0])
		g["selected"] = rawJSON("direct")
		gs[0] = rawJSON(g)
		k["groups"] = rawJSON(gs)
		r["kernel"] = rawJSON(k)
	})
	v, e := h.selectSubscription(rawJSON(map[string]any{"id": q.ID}))
	if e != nil {
		t.Fatal(e)
	}
	switchTo := v.(subscriptionPreview)
	bAccept(t, h, &switchTo)
	if h.doc.config.Groups[0].Name != "other" {
		t.Fatal("switch failed")
	}
	v, e = h.selectSubscription(rawJSON(map[string]any{"id": p.ID}))
	if e != nil {
		t.Fatal(e)
	}
	switchTo = v.(subscriptionPreview)
	bAccept(t, h, &switchTo)
	if h.doc.config.Groups[0].Selected != "direct" {
		t.Fatal("selection not isolated")
	}
	// A manual reference into the current profile makes an incompatible switch
	// fail validation, without modifying accepted bytes.
	bEdit(t, h, func(r map[string]json.RawMessage) {
		k := rawObject(r["kernel"])
		gs := rawArray(k, "groups")
		gs = append(gs, rawJSON(map[string]any{"name": "manual", "type": "select", "members": []string{"pick"}}))
		k["groups"] = rawJSON(gs)
		r["kernel"] = rawJSON(k)
	})
	before := h.doc.text
	_, e = h.selectSubscription(rawJSON(map[string]any{"id": q.ID}))
	if e == nil || h.doc.text != before {
		t.Fatal("failed switch did not preserve active")
	}
}
func TestRound2BOverlayRefreshRestore(t *testing.T) {
	h := fullHost(t)
	p := fullPreview(t, h, fullFixture, "")
	bAccept(t, h, p)
	bEdit(t, h, func(r map[string]json.RawMessage) {
		k := rawObject(r["kernel"])
		gs := rawArray(k, "groups")
		g := rawObject(gs[0])
		g["icon"] = rawJSON("https://example.org/icon")
		gs[0] = rawJSON(g)
		k["groups"] = rawJSON(gs)
		routing := rawObject(k["routing"])
		rules := rawArray(routing, "rules")
		rules = append([]json.RawMessage{rawJSON(map[string]any{"domain": "local.invalid", "action": "direct"})}, rules...)
		routing["rules"] = rawJSON(rules)
		k["routing"] = rawJSON(routing)
		r["kernel"] = rawJSON(k)
	})
	s := bSubs(t, h)[0]
	if s.Overlay.Groups["pick"]["icon"] == nil {
		t.Fatal("missing overlay")
	}
	if strings.Contains(string(rawJSON(s.Snapshot.Groups)), "icon") {
		t.Fatal("remote snapshot edited")
	}
	q := fullPreview(t, h, fullFixture, p.ID)
	bAccept(t, h, q)
	if len(h.doc.config.Routing.Rules) != 2 || h.doc.config.Groups[0].Icon == "" {
		t.Fatal("overlay lost")
	}
	v, e := h.selectSubscription(rawJSON(map[string]any{"id": p.ID, "restore_group": "pick", "restore_rules": true}))
	if e != nil {
		t.Fatal(e)
	}
	restored := v.(subscriptionPreview)
	bAccept(t, h, &restored)
	if h.doc.config.Groups[0].Icon != "" || len(h.doc.config.Routing.Rules) != 2 {
		t.Fatal("restore failed")
	}
	// References missing in a new snapshot are skipped, not fatal.
	s = bSubs(t, h)[0]
	s.Overlay.Groups = map[string]map[string]json.RawMessage{"pick": {"members": rawJSON([]string{"gone"})}, "gone": {"icon": rawJSON("x")}}
	s.Overlay.Rules = []subscriptionRulePatch{{Value: rawJSON(map[string]string{"domain": "x", "action": "gone"}), Position: 0}}
	effective := effectiveSubscription(&s, map[string]json.RawMessage{})
	if len(s.Overlay.Invalid) != 3 || len(effective.Rules) != 1 {
		t.Fatalf("invalids=%v", s.Overlay.Invalid)
	}
}
func TestRound2BRuleOverlayOperations(t *testing.T) {
	a := rawJSON(map[string]string{"domain": "a", "action": "direct"})
	b := rawJSON(map[string]string{"domain": "b", "action": "direct"})
	c := rawJSON(map[string]string{"domain": "c", "action": "direct"})
	s := fullSubscription{Snapshot: fullSnapshot{Rules: []json.RawMessage{a, b, c}}, Overlay: subscriptionOverlay{Rules: []subscriptionRulePatch{{Original: a, Disabled: true}, {Original: b, Value: b, Position: 2}, {Original: c, Value: c, Position: 0}, {Value: rawJSON(map[string]string{"domain": "new", "action": "direct"}), Position: 1}}}}
	got := effectiveSubscription(&s, map[string]json.RawMessage{})
	if len(got.Rules) != 3 || !sameJSON(got.Rules[0], c) || !strings.Contains(string(got.Rules[1]), "new") || !sameJSON(got.Rules[2], b) {
		t.Fatalf("%s", rawJSON(got.Rules))
	}
}
func TestRound2BLegacyMigration(t *testing.T) {
	h := fullHost(t)
	p := fullPreview(t, h, fullFixture, "")
	bAccept(t, h, p)
	root, _ := sourceJSON(h.doc)
	subs, _ := subscriptionsOf(root)
	subs[0].Model = 0
	subs[0].Active = nil
	subs[0].DownloadMode = ""
	root["subscriptions"] = rawJSON(subs)
	k := rawObject(root["kernel"])
	gs := rawArray(k, "groups")
	g := rawObject(gs[0])
	g["icon"] = rawJSON("https://example.org/local")
	gs[0] = rawJSON(g)
	k["groups"] = rawJSON(gs)
	root["kernel"] = rawJSON(k)
	migrated, e := prepareSubscriptionModel(root, subs)
	if e != nil {
		t.Fatal(e)
	}
	if migrated[0].Model != 2 || migrated[0].DownloadMode != "auto" || len(migrated[0].Overlay.Groups["pick"]) == 0 {
		t.Fatal("legacy diff not captured")
	}
}
func TestRound2BCandidatesIndependent(t *testing.T) {
	h := fullHost(t)
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		return []byte("payload: [example.org]"), nil
	}
	fixture := fullFixture + "rule-providers:\n  list:\n    type: http\n    behavior: domain\n    format: yaml\n    url: https://example.org/rules\n"
	p := fullPreview(t, h, fixture, "")
	first := h.fullPending.Dir
	if first == "" {
		t.Fatal("no resource")
	}
	q := fullPreview(t, h, strings.ReplaceAll(fixture, "example.org/rules", "example.org/other"), "")
	if len(h.fullCandidates) != 2 {
		t.Fatal("candidate overwritten")
	}
	if _, e := os.Stat(first); e != nil {
		t.Fatal("other candidate removed resources")
	}
	bAccept(t, h, q)
	if _, e := h.Apply(p.Text, p.Format); e == nil || e.Code != "candidate_expired" {
		t.Fatalf("%+v", e)
	}
}
func TestRound2BDownloadChainAndRedirect(t *testing.T) {
	h := fullHost(t)
	h.server = &kernel.Server{}
	defer func() { h.server = nil }()
	routes := []string{}
	h.fullFetch = func(ctx context.Context, _ string, _ *clientegress.Policy, _ int64) ([]byte, error) {
		r := resourceRoute(ctx)
		routes = append(routes, r)
		if r == "kernel_rules" {
			return []byte("ok"), nil
		}
		return nil, dl("connect", "connect_failed")
	}
	b, route, e := h.fetchMainSubscription(context.Background(), "https://example.org/file", nil, 100, "auto", "", nil)
	if e != nil || string(b) != "ok" || route != "kernel_rules" || strings.Join(routes, ",") != "direct,kernel_rules" {
		t.Fatalf("%s %v", route, e)
	}
	for _, target := range []string{"https://127.0.0.1/private", "https://10.0.0.1/private", "http://8.8.8.8/down"} {
		req, _ := http.NewRequest("GET", target, nil)
		from, _ := http.NewRequest("GET", "https://8.8.8.8/", nil)
		if subscriptionRedirect(req, []*http.Request{from}) == nil {
			t.Fatal("unsafe redirect")
		}
	}
	req, _ := http.NewRequest("GET", "https://8.8.4.4/path", nil)
	req.Header.Set("Authorization", "TEST")
	from, _ := http.NewRequest("GET", "https://8.8.8.8/", nil)
	if e := subscriptionRedirect(req, []*http.Request{from}); e != nil || req.Header.Get("Authorization") != "" {
		t.Fatal("allowed redirect rejected or sensitive header retained")
	}
	if subscriptionRedirect(req, []*http.Request{from, from, from, from, from, from}) == nil {
		t.Fatal("hop ceiling")
	}
}
func TestRound2BProbeIntervalNotSerialized(t *testing.T) {
	fixture := strings.Replace(fullFixture, "type: select", "type: url-test", 1)
	f, e := provider.ParseFull([]byte(fixture), "https://example.org/probe")
	if e != nil {
		t.Fatal(e)
	}
	if f.Groups[0].Probe.Interval != 0 {
		t.Fatal("parser materialized default")
	}
	h := fullHost(t)
	p := fullPreview(t, h, fixture, "")
	bAccept(t, h, p)
	s := bSubs(t, h)[0]
	if strings.Contains(string(rawJSON(s.Snapshot.Groups)), "interval") {
		t.Fatal("interval written back")
	}
	if time.Duration(h.doc.config.Groups[0].Probe.Interval) != time.Minute {
		t.Fatal("missing runtime default")
	}
}

func TestRound2BManualRulesRemainAcrossSwitch(t *testing.T) {
	h := fullHost(t)
	p := fullPreview(t, h, fullFixture, "")
	bAccept(t, h, p)
	q := fullPreview(t, h, strings.ReplaceAll(fullFixture, "pick", "other"), "")
	bAccept(t, h, q)
	bEdit(t, h, func(r map[string]json.RawMessage) {
		k := rawObject(r["kernel"])
		routing := rawObject(k["routing"])
		rules := rawArray(routing, "rules")
		rules = append([]json.RawMessage{rawJSON(map[string]string{"domain": "manual.invalid", "action": "direct"})}, rules...)
		routing["rules"] = rawJSON(rules)
		k["routing"] = rawJSON(routing)
		r["kernel"] = rawJSON(k)
	})
	if len(bSubs(t, h)[0].Overlay.Rules) != 0 {
		t.Fatal("self-created manual rule incorrectly became profile-local")
	}
	v, e := h.selectSubscription(rawJSON(map[string]string{"id": q.ID}))
	if e != nil {
		t.Fatal(e)
	}
	switchTo := v.(subscriptionPreview)
	bAccept(t, h, &switchTo)
	if len(h.doc.config.Routing.Rules) != 2 || !strings.Contains(string(rawJSON(h.doc.config.Routing.Rules)), "manual.invalid") {
		t.Fatal("manual rule lost")
	}
}
func TestRound2BFixedPerProfileAndDeleteInactive(t *testing.T) {
	h := fullHost(t)
	fixture := strings.Replace(fullFixture, "type: select", "type: url-test", 1)
	p := fullPreview(t, h, fixture, "")
	bAccept(t, h, p)
	q := fullPreview(t, h, strings.ReplaceAll(fixture, "pick", "other"), "")
	bAccept(t, h, q)
	bEdit(t, h, func(r map[string]json.RawMessage) {
		k := rawObject(r["kernel"])
		groups := rawArray(k, "groups")
		g := rawObject(groups[0])
		g["fixed"] = rawJSON("n")
		g["priority"] = rawJSON(map[string]float64{"n": 1.5})
		groups[0] = rawJSON(g)
		k["groups"] = rawJSON(groups)
		r["kernel"] = rawJSON(k)
	})
	for _, id := range []string{q.ID, p.ID} {
		v, e := h.selectSubscription(rawJSON(map[string]string{"id": id}))
		if e != nil {
			t.Fatal(e)
		}
		s := v.(subscriptionPreview)
		bAccept(t, h, &s)
		if id == q.ID && h.doc.config.Groups[0].Fixed != "" {
			t.Fatal("fixed leaked across profiles")
		}
	}
	if h.doc.config.Groups[0].Fixed != "n" || h.doc.config.Groups[0].Priority["n"] != 1.5 {
		t.Fatal("per-profile fixed/weights lost")
	}
	v, e := h.selectSubscription(rawJSON(map[string]any{"id": q.ID, "delete_id": q.ID}))
	if e != nil {
		t.Fatal(e)
	}
	deleted := v.(subscriptionPreview)
	bAccept(t, h, &deleted)
	if len(bSubs(t, h)) != 1 || h.doc.config.Groups[0].Fixed != "n" {
		t.Fatal("inactive delete affected active")
	}
	v, e = h.selectSubscription(rawJSON(map[string]any{"id": p.ID, "delete_id": p.ID}))
	if e != nil {
		t.Fatal(e)
	}
	deleted = v.(subscriptionPreview)
	bAccept(t, h, &deleted)
	if len(bSubs(t, h)) != 0 || len(h.doc.config.Groups) != 0 {
		t.Fatal("active delete did not become manual-only")
	}
}
func TestRound2BExplicitRuleOverlaySaveAndInvalidRetention(t *testing.T) {
	h := fullHost(t)
	p := fullPreview(t, h, fullFixture, "")
	bAccept(t, h, p)
	bEdit(t, h, func(r map[string]json.RawMessage) {
		subs, _ := subscriptionsOf(r)
		rule := rawJSON(map[string]string{"domain": "subscription-local.invalid", "action": "direct"})
		subs[0].Overlay.Rules = []subscriptionRulePatch{{Value: rule, Position: 0}}
		k := rawObject(r["kernel"])
		snap := subs[0].Snapshot
		if _, e := detachSubscription(k, snap, subs[0].PriorFinal); e != nil {
			t.Fatal(e)
		}
		attachSubscription(k, effectiveSubscription(&subs[0], k), 0)
		r["kernel"] = rawJSON(k)
		r["subscriptions"] = rawJSON(subs)
	})
	q := fullPreview(t, h, fullFixture, p.ID)
	bAccept(t, h, q)
	if len(bSubs(t, h)[0].Overlay.Rules) != 1 || len(h.doc.config.Routing.Rules) != 2 {
		t.Fatal("explicit overlay addition lost")
	}
	s := bSubs(t, h)[0]
	s.Overlay.Rules = append(s.Overlay.Rules, subscriptionRulePatch{Value: rawJSON(map[string]string{"domain": "invalid", "action": "missing"})})
	k := map[string]json.RawMessage{}
	_ = effectiveSubscription(&s, k)
	captureSubscriptionLocal(&s, rawObject(func() json.RawMessage { r, _ := sourceJSON(h.doc); return r["kernel"] }()), nil)
	if len(s.Overlay.Rules) < 2 {
		t.Fatal("invalid overlay silently discarded")
	}
}
func TestRound2BLiveSwitchAndApplyRollback(t *testing.T) {
	h := fullHost(t)
	if _, e := h.Apply(fixture(t, map[string]any{})); e != nil {
		t.Fatal(e)
	}
	p := fullPreview(t, h, fullFixture, "")
	bAccept(t, h, p)
	q := fullPreview(t, h, strings.ReplaceAll(fullFixture, "pick", "other"), "")
	bAccept(t, h, q)
	if _, e := h.Request(context.Background(), "core.start", rawJSON(map[string]any{})); e != nil {
		t.Fatal(e)
	}
	v, e := h.selectSubscription(rawJSON(map[string]string{"id": q.ID}))
	if e != nil {
		t.Fatal(e)
	}
	selected := v.(subscriptionPreview)
	bAccept(t, h, &selected)
	if h.server.CurrentConfig().Groups[0].Name != "other" {
		t.Fatal("running generation not switched")
	}
	v, e = h.selectSubscription(rawJSON(map[string]string{"id": p.ID}))
	if e != nil {
		t.Fatal(e)
	}
	selected = v.(subscriptionPreview)
	// Force a host apply-stage failure after valid switch preview using a busy
	// HTTP listener. The same transaction must restore bytes and running profile.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	root := map[string]json.RawMessage{}
	_ = json.Unmarshal([]byte(selected.Text), &root)
	client := rawObject(root["client"])
	client["http_port"] = rawJSON(listener.Addr().(*net.TCPAddr).Port)
	root["client"] = rawJSON(client)
	selected.Text = string(rawJSON(root))
	h.fullPending.Text = selected.Text
	before := h.doc.text
	if _, e := h.Apply(selected.Text); e == nil || e.Code != "apply_failed" {
		t.Fatalf("%+v", e)
	}
	if h.doc.text != before || h.server.CurrentConfig().Groups[0].Name != "other" {
		t.Fatal("failed switch did not rollback")
	}
}
func TestRound2BTransportHeadersRedirectAndFailure(t *testing.T) {
	for _, tc := range []struct {
		name, location string
		hops           int
		denied         bool
	}{{"allowed", "https://8.8.4.4/final", 1, false}, {"private", "https://127.0.0.1/private", 1, true}, {"too_many", "https://8.8.4.4/again", 6, true}} {
		t.Run(tc.name, func(t *testing.T) {
			meta := &subscriptionHeaders{}
			ctx := context.WithValue(context.Background(), subscriptionHeadersKey{}, meta)
			calls := 0
			b, e := fetchImportBounded(ctx, "https://8.8.8.8/initial?token=TEST", nil, func(*http.Transport) http.RoundTripper {
				return roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					header := http.Header{}
					status := 200
					body := fullFixture
					if calls <= tc.hops {
						status = 302
						header.Set("Location", tc.location)
						header.Set("subscription-userinfo", "upload=999;download=999")
					} else {
						header.Set("subscription-userinfo", "upload=1;download=2;total=100")
						header.Set("profile-update-interval", "12")
					}
					return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
				})
			}, provider.MaxSize)
			if tc.denied {
				if e == nil {
					t.Fatal("unsafe redirect accepted")
				}
				detail := resourceError(ctx, "subscription", 0, "download", "connect", "unknown", e)
				if detail.Reason != "redirect_denied" || strings.Contains(string(rawJSON(detail)), "TEST") {
					t.Fatalf("%+v", detail)
				}
			} else {
				if e != nil || string(b) != fullFixture || parseSubscriptionUserInfo(meta.userinfo).Upload != 1 || parseSubscriptionInterval(meta.updateInterval) != 43200 {
					t.Fatal("final response metadata missing")
				}
			}
		})
	}
}
func TestRound2BStartupMigrationBackup(t *testing.T) {
	h := fullHost(t)
	p := fullPreview(t, h, fullFixture, "")
	bAccept(t, h, p)
	root, _ := sourceJSON(h.doc)
	subs, _ := subscriptionsOf(root)
	subs[0].Model = 0
	subs[0].Active = nil
	subs[0].DownloadMode = ""
	root["subscriptions"] = rawJSON(subs)
	text, _ := renderSubscriptionSource(h.doc, root)
	path, workspace := h.path, h.workspace
	_ = h.Close()
	if e := atomicWrite(path, []byte(text)); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(workspace)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if bSubs(t, reopened)[0].Model != 2 {
		t.Fatal("startup did not upgrade")
	}
	backup, e := os.ReadFile(workspace + "/subscription-v1-before-upgrade.json")
	if e != nil || string(backup) != text {
		t.Fatal("rollback source missing or changed")
	}
}

func TestRound2BGroupFieldPatchAndMemberDeltas(t *testing.T) {
	old := rawJSON(map[string]any{"name": "g", "type": "url-test", "members": []string{"a", "b"}, "probe": map[string]any{"url": "https://example.org/old", "interval": "5m"}})
	local := rawJSON(map[string]any{"name": "g", "type": "url-test", "members": []string{"b", "direct"}, "probe": map[string]any{"url": "https://example.org/local", "interval": "5m"}})
	patch := groupDiff(old, local)
	if len(rawObject(patch["probe"])) != 1 || patch["members_remove"] == nil || patch["members_add"] == nil {
		t.Fatalf("not field-level: %s", rawJSON(patch))
	}
	remote := rawJSON(map[string]any{"name": "g", "type": "url-test", "members": []string{"a", "b", "new"}, "probe": map[string]any{"url": "https://example.org/changed", "interval": "10m"}})
	s := fullSubscription{Snapshot: fullSnapshot{Outbounds: []json.RawMessage{rawJSON(map[string]string{"name": "a"}), rawJSON(map[string]string{"name": "b"}), rawJSON(map[string]string{"name": "new"})}, Groups: []json.RawMessage{remote}}, Overlay: subscriptionOverlay{Groups: map[string]map[string]json.RawMessage{"g": patch}}}
	got := effectiveSubscription(&s, map[string]json.RawMessage{})
	g := rawObject(got.Groups[0])
	if !strings.Contains(string(g["members"]), "new") || strings.Contains(string(g["members"]), "\"a\"") || !strings.Contains(string(g["probe"]), "10m") || !strings.Contains(string(g["probe"]), "local") {
		t.Fatalf("lost remote changes: %s", rawJSON(g))
	}
}
func TestRound2BInactiveUpdateDoesNotApplyRunningGeneration(t *testing.T) {
	h := fullHost(t)
	if _, e := h.Apply(fixture(t, map[string]any{})); e != nil {
		t.Fatal(e)
	}
	p := fullPreview(t, h, fullFixture, "")
	bAccept(t, h, p)
	q := fullPreview(t, h, strings.ReplaceAll(fullFixture, "pick", "other"), "")
	bAccept(t, h, q)
	if _, e := h.Request(context.Background(), "core.start", rawJSON(map[string]any{})); e != nil {
		t.Fatal(e)
	}
	epoch := h.manualCtx
	updated := fullPreview(t, h, strings.ReplaceAll(strings.ReplaceAll(fullFixture, "pick", "other"), "example.org,pick", "changed.invalid,pick"), q.ID)
	bAccept(t, h, updated)
	if h.manualCtx != epoch || h.server.CurrentConfig().Groups[0].Name != "pick" {
		t.Fatal("inactive refresh reapplied active generation")
	}
}
func TestRound2BReplaceSameCandidateExpiresExplicitly(t *testing.T) {
	h := fullHost(t)
	p := fullPreview(t, h, fullFixture, "")
	bAccept(t, h, p)
	old := fullPreview(t, h, fullFixture, p.ID)
	_ = fullPreview(t, h, strings.ReplaceAll(fullFixture, "example.org,pick", "changed.invalid,pick"), p.ID)
	if _, e := h.Apply(old.Text); e == nil || e.Code != "candidate_expired" {
		t.Fatalf("%+v", e)
	}
}
func TestRound2BManualRuleInterleavingRefresh(t *testing.T) {
	h := fullHost(t)
	fixture := strings.Replace(fullFixture, "  - MATCH,pick", "  - DOMAIN,second.invalid,pick\n  - MATCH,pick", 1)
	p := fullPreview(t, h, fixture, "")
	bAccept(t, h, p)
	bEdit(t, h, func(r map[string]json.RawMessage) {
		k := rawObject(r["kernel"])
		routing := rawObject(k["routing"])
		rules := rawArray(routing, "rules")
		rules = append([]json.RawMessage{rules[0], rawJSON(map[string]string{"domain": "manual-middle.invalid", "action": "direct"})}, rules[1:]...)
		routing["rules"] = rawJSON(rules)
		k["routing"] = rawJSON(routing)
		r["kernel"] = rawJSON(k)
	})
	q := fullPreview(t, h, fixture, p.ID)
	bAccept(t, h, q)
	rules := h.doc.config.Routing.Rules
	if len(rules) != 3 || !strings.Contains(string(rawJSON(rules[1])), "manual-middle.invalid") {
		t.Fatalf("manual position changed: %s", rawJSON(rules))
	}
}
func TestRound2BAllDownloadRoutesFailPreservesSource(t *testing.T) {
	h := fullHost(t)
	p := fullPreview(t, h, fullFixture, "")
	bAccept(t, h, p)
	bEdit(t, h, func(r map[string]json.RawMessage) {
		subs, _ := subscriptionsOf(r)
		subs[0].URL = "https://example.org/fixture?token=TEST"
		subs[0].UserInfo = &subscriptionUserInfo{Upload: 10, Download: 20}
		r["subscriptions"] = rawJSON(subs)
	})
	before := h.doc.text
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		return nil, dl("tls", "tls_certificate")
	}
	_, e := h.Request(context.Background(), "subscription.preview", rawJSON(map[string]any{"id": p.ID}))
	if e == nil || e.Reason != "tls" || h.doc.text != before || bSubs(t, h)[0].UserInfo.Download != 20 {
		t.Fatal("all-failed attempt changed accepted source")
	}
}

func TestRound2BRuleObjectEditDisableRestoreAtomic(t *testing.T) {
	h := fullHost(t)
	p := fullPreview(t, h, fullFixture, "")
	bAccept(t, h, p)
	v, e := h.selectSubscription(rawJSON(map[string]any{"id": p.ID, "edit_rule": 0, "rule_value": map[string]string{"domain": "local-change.invalid", "action": "direct"}, "disable_edited": true, "edit_only": true}))
	if e != nil {
		t.Fatal(e)
	}
	edited := v.(subscriptionPreview)
	bAccept(t, h, &edited)
	s := bSubs(t, h)[0]
	if len(s.Overlay.Rules) != 1 || !s.Overlay.Rules[0].Disabled || len(h.doc.config.Routing.Rules) != 0 {
		t.Fatal("edit+disable not one overlay transaction")
	}
	q := fullPreview(t, h, fullFixture, p.ID)
	bAccept(t, h, q)
	if len(h.doc.config.Routing.Rules) != 0 || !bSubs(t, h)[0].Overlay.Rules[0].Disabled {
		t.Fatal("disabled rule did not survive refresh")
	}
	v, e = h.selectSubscription(rawJSON(map[string]any{"id": p.ID, "toggle_rule": 0, "edit_only": true}))
	if e != nil {
		t.Fatal(e)
	}
	edited = v.(subscriptionPreview)
	bAccept(t, h, &edited)
	if !strings.Contains(string(rawJSON(h.doc.config.Routing.Rules)), "local-change.invalid") {
		t.Fatal("enable lost edited rule")
	}
	v, e = h.selectSubscription(rawJSON(map[string]any{"id": p.ID, "restore_rule": 0, "edit_only": true}))
	if e != nil {
		t.Fatal(e)
	}
	edited = v.(subscriptionPreview)
	bAccept(t, h, &edited)
	if len(bSubs(t, h)[0].Overlay.Rules) != 0 || !strings.Contains(string(rawJSON(h.doc.config.Routing.Rules)), "example.org") {
		t.Fatal("restore object did not restore remote")
	}
}

func TestRound2BMainHeadersNotResourceAndMetadataReset(t *testing.T) {
	h := fullHost(t)
	main := fullFixture + "rule-providers:\n  external: {type: http, behavior: domain, format: yaml, url: https://example.org/resource}\n"
	header := "upload=1;download=2;total=100;expire=1"
	h.fullFetch = func(ctx context.Context, url string, _ *clientegress.Policy, _ int64) ([]byte, error) {
		if strings.Contains(url, "resource") {
			captureSubscriptionHeaders(ctx, http.Header{"Subscription-Userinfo": []string{"upload=999;download=999"}})
			return []byte("payload: [example.org]"), nil
		}
		captureSubscriptionHeaders(ctx, http.Header{"Subscription-Userinfo": []string{header}, "Profile-Update-Interval": []string{"12"}})
		return []byte(main), nil
	}
	v, e := h.Request(context.Background(), "subscription.preview", rawJSON(map[string]any{"url": "https://example.org/main", "interval": 3600, "follow_interval": false}))
	if e != nil {
		t.Fatal(e)
	}
	p := v.(subscriptionPreview)
	bAccept(t, h, &p)
	if bSubs(t, h)[0].UserInfo.Upload != 1 || bSubs(t, h)[0].Interval != 3600 {
		t.Fatal("resource overwrote main metadata or header overrode user interval")
	}
	for _, value := range []string{"", "upload=illegal;download=2"} {
		header = value
		v, e = h.Request(context.Background(), "subscription.preview", rawJSON(map[string]any{"id": p.ID}))
		if e != nil {
			t.Fatal(e)
		}
		p = v.(subscriptionPreview)
		bAccept(t, h, &p)
		if bSubs(t, h)[0].UserInfo != nil {
			t.Fatal("missing/invalid successful header fabricated metadata")
		}
	}
}
func TestRound2BDownloadLastRouteFirstAndDedup(t *testing.T) {
	h := fullHost(t)
	routes := []string{}
	h.fullFetch = func(ctx context.Context, _ string, _ *clientegress.Policy, _ int64) ([]byte, error) {
		routes = append(routes, resourceRoute(ctx))
		return nil, dl("connect", "connect_failed")
	}
	_, _, _ = h.fetchMainSubscription(context.Background(), "https://example.org/file", nil, 1024, "auto", "windows_static_http", &bootstrapProxy{Host: "127.0.0.1", Port: 18888})
	if strings.Join(routes, ",") != "windows_static_http,direct" {
		t.Fatal(routes)
	}
	routes = nil
	_, _, _ = h.fetchMainSubscription(context.Background(), "https://example.org/file", nil, 1024, "direct", "windows_static_http", &bootstrapProxy{Host: "127.0.0.1", Port: 18888})
	if strings.Join(routes, ",") != "direct" {
		t.Fatal(routes)
	}
}

func TestRound2BSwitchDoesNotPretendToRefresh(t *testing.T) {
	h := fullHost(t)
	p := fullPreview(t, h, fullFixture, "")
	bAccept(t, h, p)
	q := fullPreview(t, h, strings.ReplaceAll(fullFixture, "pick", "other"), "")
	bAccept(t, h, q)
	bEdit(t, h, func(r map[string]json.RawMessage) {
		subs, _ := subscriptionsOf(r)
		subs[1].Updated = 100
		r["subscriptions"] = rawJSON(subs)
	})
	h.recordSubscriptionStatusLocked(q.ID, fail("subscription_fetch_failed", "subscription", "safe"))
	before := h.subscriptionStatusesLocked()[q.ID]
	v, e := h.selectSubscription(rawJSON(map[string]string{"id": q.ID}))
	if e != nil {
		t.Fatal(e)
	}
	selected := v.(subscriptionPreview)
	bAccept(t, h, &selected)
	after := h.subscriptionStatusesLocked()[q.ID]
	if after.Success || after.Finished != before.Finished || bSubs(t, h)[1].Updated != 100 {
		t.Fatal("switch hid last download failure or rescheduled update")
	}
}

func TestRound2BLegacyRuleFieldDifferenceBecomesOverlay(t *testing.T) {
	h := fullHost(t)
	p := fullPreview(t, h, fullFixture, "")
	bAccept(t, h, p)
	root, _ := sourceJSON(h.doc)
	subs, _ := subscriptionsOf(root)
	subs[0].Model = 0
	subs[0].Active = nil
	subs[0].Overlay = subscriptionOverlay{}
	k := rawObject(root["kernel"])
	routing := rawObject(k["routing"])
	rules := rawArray(routing, "rules")
	rule := rawObject(rules[0])
	rule["action"] = rawJSON("direct")
	rules[0] = rawJSON(rule)
	routing["rules"] = rawJSON(rules)
	k["routing"] = rawJSON(routing)
	root["kernel"] = rawJSON(k)
	migrated, e := prepareSubscriptionModel(root, subs)
	if e != nil {
		t.Fatal(e)
	}
	if len(migrated[0].Overlay.Rules) != 1 || migrated[0].Overlay.Rules[0].Deleted || len(migrated[0].Overlay.Rules[0].Value) == 0 {
		t.Fatal("legacy field edit was not converted")
	}
}

func TestRound2BMigrationBackupRetainsOldResources(t *testing.T) {
	h := fullHost(t)
	fixture, version := cacheFixture(t, h)
	p := fullPreview(t, h, fixture, "")
	bAccept(t, h, p)
	path := h.doc.config.RuleSets[0].Path
	prior, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e := exclusiveDocumentWrite(h.workspace+"/subscription-v1-before-upgrade.json", []byte(h.doc.text)); e != nil {
		t.Fatal(e)
	}
	for i := 1; i <= 4; i++ {
		*version = i
		next := fullPreview(t, h, strings.Replace(fixture, "https://example.invalid/set", fmt.Sprintf("https://example.invalid/set/new%d", i), 1), p.ID)
		bAccept(t, h, next)
	}
	after, e := os.ReadFile(path)
	if e != nil || string(after) != string(prior) {
		t.Fatal("rollback source resource collected")
	}
}
