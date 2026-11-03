package clientcore

import (
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/clientegress"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestR11ResourceRouteMainSavedModeDependenciesRunningKernel(t *testing.T) {
	for _, running := range []bool{false, true} {
		for _, proxy := range []bool{false, true} {
			h := fullHost(t)
			if _, e := h.Apply(fixture(t, map[string]any{})); e != nil {
				t.Fatal(e)
			}
			if running {
				if _, e := h.Start(); e != nil {
					t.Fatal(e)
				}
			}
			var main, resources int
			h.fullFetch = func(ctx context.Context, url string, _ *clientegress.Policy, _ int64) ([]byte, error) {
				k, _ := ctx.Value(resourceKernelKey{}).(bool)
				if strings.Contains(url, "main.yaml") {
					main++
					if k || bootstrapFrom(ctx) != nil {
						t.Error("main ignored saved route")
					}
					return []byte(strings.Replace(fullFixture, "rules:\n", "rule-providers:\n  r: {type: http, behavior: domain, url: 'https://example.org/rules.yaml'}\nrules:\n  - RULE-SET,r,pick\n", 1)), nil
				}
				resources++
				if k != running {
					t.Error("resource wrong route")
				}
				if !running && ((bootstrapFrom(ctx) != nil) != proxy) {
					t.Error("stopped resource ignored saved route")
				}
				return []byte("payload:\n - example.org\n"), nil
			}
			p := map[string]any{"url": "https://example.org/main.yaml"}
			if proxy {
				p["_system_proxy"] = &bootstrapProxy{Host: "127.0.0.1", Port: 7890}
				p["_egress"] = &bootstrapEgress{}
			}
			_, e := h.previewSubscription(context.Background(), rawJSON(p))
			if e != nil || main != 1 || resources != 1 {
				t.Fatal("routes not fully exercised", e, main, resources)
			}
		}
	}
}
func TestR11RuntimeResourceRealRegisteredSOCKSAndRouteFailure(t *testing.T) {
	h := fullHost(t)
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, "payload: [example.org]")
	}))
	defer target.Close()
	doc := fixture(t, map[string]any{"security": map[string]any{"allow_loopback": true}, "routing": map[string]any{"final": "reject"}})
	if _, e := h.Apply(doc); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	ctx := context.WithValue(context.Background(), resourceKernelKey{}, true)
	_, err := h.fetchFull(ctx, target.URL, nil, 1024)
	if err == nil || calls.Load() != 0 {
		t.Fatal("resource silently bypassed kernel rules")
	}
	e := resourceError(ctx, "rule_set", 2, "download", "connect", "unknown", err)
	b, _ := json.Marshal(e)
	if !strings.Contains(string(b), "kernel_rules") {
		t.Fatal("actual route missing")
	}
	if _, e := h.Stop(); e != nil {
		t.Fatal(e)
	}
	_, err = h.fetchFull(ctx, target.URL, nil, 1024)
	if err == nil {
		t.Fatal("lost runtime silently fell back")
	}
	doc = fixture(t, map[string]any{"security": map[string]any{"allow_loopback": true}, "routing": map[string]any{"final": "direct"}})
	if _, e := h.Apply(doc); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	out, err := h.fetchFull(ctx, target.URL, nil, 1024)
	if err != nil || string(out) != "payload: [example.org]" || calls.Load() != 1 {
		t.Fatal("no TUN direct rule SOCKS route failed", err)
	}
	if h.egress != nil {
		t.Fatal("test unexpectedly depended on TUN")
	}
}
func TestR11IconFailureLogNoTunAndStageGroupSurvives(t *testing.T) {
	h := fullHost(t)
	doc := fixture(t, map[string]any{"groups": []any{map[string]any{"name": "HK", "type": "select", "members": []string{"direct"}}}})
	if _, e := h.Apply(doc); e != nil {
		t.Fatal(e)
	}
	h.iconFetch = func(context.Context, string) ([]byte, error) { return nil, dl("connect", "timeout") }
	h.getIcon(context.Background(), rawJSON(map[string]any{"url": "https://example.org/icon?token=SECRET", "group": "HK"}))
	b, _ := json.Marshal(h.logs.read(0, 500))
	if !strings.Contains(string(b), "HK") || !strings.Contains(string(b), "icon_connect_failed") || !strings.Contains(string(b), "timeout") || strings.Contains(string(b), "SECRET") {
		t.Fatal("missing private-safe exported failure")
	}
}

func TestR11LocalResourcesFreshSkipAndExpiredOfflineKeepAccepted(t *testing.T) {
	h := fullHost(t)
	config := strings.Replace(fullFixture, "rules:\n", "rule-providers:\n  r: {type: http, behavior: domain, url: 'https://example.org/rules.yaml', interval: 3600}\nrules:\n  - RULE-SET,r,pick\n", 1)
	calls := 0
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		calls++
		return []byte("payload: [example.org]"), nil
	}
	p := fullPreview(t, h, config, "")
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	if calls != 1 {
		t.Fatal(calls)
	}
	root, _ := sourceJSON(h.doc)
	owners, _ := subscriptionsOf(root)
	id := owners[0].ID
	if len(owners[0].Resources) != 1 {
		t.Fatal("not persisted")
	}
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		calls++
		return nil, dl("connect", "timeout")
	}
	p = fullPreview(t, h, config, id)
	if calls != 1 {
		t.Fatal("fresh local resource fetched again")
	}
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	root, _ = sourceJSON(h.doc)
	owners, _ = subscriptionsOf(root)
	for key, v := range owners[0].Resources {
		v.Updated -= 7200
		owners[0].Resources[key] = v
	}
	root["subscriptions"] = rawJSON(owners)
	text := string(rawJSON(root))
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	p = fullPreview(t, h, config, id)
	if calls != 2 {
		t.Fatal("expired resource not retried")
	}
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal("offline refresh discarded old valid resource", e)
	}
	workspace := h.workspace
	h.Close()
	fresh, e := Open(workspace)
	if e != nil {
		t.Fatal("offline restart cannot load local rule", e)
	}
	defer fresh.Close()
	if len(fresh.doc.config.RuleSets) == 0 {
		t.Fatal("local rules missing")
	}
}
