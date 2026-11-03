package clientcore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/clientegress"
	"strings"
	"testing"
)

func TestR12ResourceFallbackRoutes(t *testing.T) {
	for _, tc := range []struct {
		name                               string
		running, savedProxy, optionalProxy bool
		failFirst                          bool
		want                               []string
	}{
		{"kernel fails direct succeeds", true, false, false, true, []string{"kernel_rules", "direct"}},
		{"direct timeout avoided kernel succeeds", true, false, false, false, []string{"kernel_rules"}},
		{"kernel fails saved static succeeds", true, true, false, true, []string{"kernel_rules", "windows_static_http"}},
		{"stopped direct fails static succeeds", false, false, true, true, []string{"direct", "windows_static_http"}},
		{"stopped direct succeeds", false, false, true, false, []string{"direct"}},
		{"stopped saved proxy succeeds no duplicate", false, true, true, false, []string{"windows_static_http"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := fullHost(t)
			ctx := context.WithValue(context.Background(), resourceKernelKey{}, tc.running)
			proxy := &bootstrapProxy{Host: "127.0.0.1", Port: 7890}
			if tc.savedProxy {
				ctx = context.WithValue(ctx, bootstrapKey{}, proxy)
			}
			if tc.optionalProxy {
				ctx = context.WithValue(ctx, resourceProxyKey{}, proxy)
			}
			got := []string{}
			h.fullFetch = func(c context.Context, _ string, _ *clientegress.Policy, _ int64) ([]byte, error) {
				got = append(got, resourceRoute(c))
				if tc.failFirst && len(got) == 1 {
					return nil, dl("connect", "timeout")
				}
				if !tc.failFirst && tc.running && resourceRoute(c) != "kernel_rules" {
					return nil, dl("connect", "timeout")
				}
				return []byte("payload: [example.org]"), nil
			}
			b, _, e := h.subscriptionResource(ctx, nil, "https://example.org/rules", 0, nil, 1024)
			if e != nil || len(b) == 0 || strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("wrong fallback: %v %v", got, e)
			}
		})
	}
}
func TestR12AllResourceRoutesFailPreservesAcceptedAndReportsBoth(t *testing.T) {
	h := fullHost(t)
	if _, e := h.Apply(fixture(t, map[string]any{})); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	before := h.doc.text
	calls := []string{}
	h.fullFetch = func(ctx context.Context, _ string, _ *clientegress.Policy, _ int64) ([]byte, error) {
		calls = append(calls, resourceRoute(ctx))
		if resourceRoute(ctx) == "kernel_rules" {
			return nil, dl("connect", "connect_failed")
		}
		return nil, dl("connect", "timeout")
	}
	text := strings.Replace(fullFixture, "rules:\n", "rule-providers:\n  r: {type: http, behavior: domain, url: 'https://example.org/rules.yaml'}\nrules:\n  - RULE-SET,r,pick\n", 1)
	_, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"text": text}))
	if e == nil || e.Code != "subscription_resource_failed" || h.doc.text != before || h.fullPending != nil {
		t.Fatal("failure did not preserve accepted", e)
	}
	d := e.Detail
	if d.Route != "direct" || d.Category != "timeout" || d.FirstAttempt == nil || d.FirstAttempt.Route != "kernel_rules" || d.FirstAttempt.Category != "connect_failed" {
		t.Fatalf("wrong actual error routes: %+v", d)
	}
	if strings.Join(calls, ",") != "kernel_rules,direct" {
		t.Fatal(calls)
	}
	b, _ := json.Marshal(e)
	if strings.Contains(string(b), "https://") || strings.Contains(string(b), "rules.yaml") {
		t.Fatal("private transport fields leaked")
	}
}
func TestR12ResourcesFallbackIndependentlyAndMainRetainsSavedRoute(t *testing.T) {
	h := fullHost(t)
	if _, e := h.Apply(fixture(t, map[string]any{})); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	calls := map[string][]string{}
	text := strings.Replace(fullFixture, "rules:\n", "rule-providers:\n  r: {type: http, behavior: domain, url: 'https://example.org/r.yaml'}\n  s: {type: http, behavior: domain, url: 'https://example.org/s.yaml'}\nrules:\n  - RULE-SET,r,pick\n", 1)
	h.fullFetch = func(ctx context.Context, u string, _ *clientegress.Policy, _ int64) ([]byte, error) {
		calls[u] = append(calls[u], resourceRoute(ctx))
		if strings.Contains(u, "main") {
			return []byte(text), nil
		}
		if strings.Contains(u, "r.yaml") && resourceRoute(ctx) == "kernel_rules" {
			return nil, dl("connect", "connect_failed")
		}
		return []byte("payload: [example.org]"), nil
	}
	_, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"url": "https://example.org/main.yaml"}))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Join(calls["https://example.org/main.yaml"], ",") != "direct" || strings.Join(calls["https://example.org/r.yaml"], ",") != "kernel_rules,direct" || strings.Join(calls["https://example.org/s.yaml"], ",") != "kernel_rules" {
		t.Fatal(calls)
	}
}
func TestR12ResourceFallbackNeverResurrectsCanceledPreview(t *testing.T) {
	h := fullHost(t)
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, resourceKernelKey{}, true)
	calls := 0
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		calls++
		cancel()
		return nil, context.Canceled
	}
	_, e := h.fetchSubscriptionResource(ctx, "https://example.org/r", nil, 1024)
	if !errors.Is(e, context.Canceled) || calls != 1 {
		t.Fatal("canceled request retried", e, calls)
	}
}
func TestR12StoppedUnavailableStaticDoesNotRetrySameRoute(t *testing.T) {
	for _, savedProxy := range []bool{false, true} {
		h := fullHost(t)
		ctx := context.Background()
		if savedProxy {
			ctx = context.WithValue(ctx, bootstrapKey{}, &bootstrapProxy{Host: "127.0.0.1", Port: 7890})
			ctx = context.WithValue(ctx, resourceProxyKey{}, bootstrapFrom(ctx))
		}
		calls := 0
		h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
			calls++
			return nil, dl("connect", "timeout")
		}
		_, e := h.fetchSubscriptionResource(ctx, "https://example.org/r", nil, 1024)
		if e == nil || calls != 1 {
			t.Fatal("missing/duplicate static retried", calls)
		}
	}
}
