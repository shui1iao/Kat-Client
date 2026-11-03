package clientcore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/kernel"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func legacyHost(t *testing.T, k map[string]any) *Host {
	t.Helper()
	workspace := t.TempDir()
	text := fixture(t, k)
	if e := os.WriteFile(filepath.Join(workspace, "kat-client.json"), []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
	h, e := Open(workspace)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { h.Close() })
	return h
}
func migratePreview(t *testing.T, h *Host, name string) subscriptionPreview {
	t.Helper()
	v, e := h.Request(context.Background(), "subscription.migrate", rawJSON(map[string]any{"name": name}))
	if e != nil {
		t.Fatal(e)
	}
	p, ok := v.(subscriptionPreview)
	if !ok || len(p.Issues) > 0 || p.Token == "" {
		t.Fatalf("bad migration %+v", v)
	}
	return p
}

const legacyNodes = "proxies:\n - {name: keep-a, type: socks5, server: example.org, port: 1080}\n - {name: drop-b, type: socks5, server: example.org, port: 1081}\n"

func TestR4LegacyMigrationHTTPFileFilterAndUse(t *testing.T) {
	for _, kind := range []string{"http", "file"} {
		for _, withUse := range []bool{true, false} {
			for _, filtered := range []bool{true, false} {
				t.Run(kind+"/"+uiJSON([]bool{withUse, filtered}), func(t *testing.T) {
					p := map[string]any{"name": "old", "type": kind}
					path := filepath.Join(t.TempDir(), "nodes")
					os.WriteFile(path, []byte(legacyNodes), 0600)
					if kind == "http" {
						p["url"] = "https://migration.invalid/sub"
						p["headers"] = map[string]string{"X-Source": "private"}
						p["interval"] = "2h"
						p["user_agent"] = "original-agent"
						p["timeout"] = "9s"
					} else {
						p["path"] = path
					}
					if filtered {
						p["filter"] = "keep"
						p["exclude_filter"] = "drop"
						p["exclude_type"] = "trojan"
					}
					k := map[string]any{"providers": []any{p}, "groups": []any{map[string]any{"name": "manual", "type": "select", "members": []string{"direct"}}}}
					if withUse {
						k["groups"].([]any)[0].(map[string]any)["use"] = []string{"old"}
					}
					h := legacyHost(t, k)
					h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
						return []byte(legacyNodes), nil
					}
					before := h.doc.text
					candidate := migratePreview(t, h, "old")
					if h.doc.text != before {
						t.Fatal("preview mutated accepted source")
					}
					if _, e := h.Apply(candidate.Text, candidate.Format); e != nil {
						t.Fatal(e)
					}
					root, _ := sourceJSON(h.doc)
					var kernel map[string]json.RawMessage
					json.Unmarshal(root["kernel"], &kernel)
					if len(rawArray(kernel, "providers")) != 0 {
						t.Fatal("provider survived success")
					}
					subs, e := subscriptionsOf(root)
					if e != nil || len(subs) != 1 || subs[0].Name != "old" {
						t.Fatal(subs, e)
					}
					want := 2
					if filtered {
						want = 1
					}
					if len(subs[0].Snapshot.Outbounds) != want {
						t.Fatal("filter changed", subs)
					}
					if kind == "http" && (subs[0].URL != p["url"] || subs[0].Interval != 7200 || subs[0].SourceOptions.Headers["X-Source"] != "private" || subs[0].SourceOptions.UserAgent != "original-agent") {
						t.Fatal("request settings lost")
					}
					g := map[string]json.RawMessage{}
					json.Unmarshal(rawArray(kernel, "groups")[0], &g)
					if g["use"] != nil {
						t.Fatal("use survived")
					}
					ms := []string{}
					json.Unmarshal(g["members"], &ms)
					expected := 1
					if withUse {
						expected += want
					}
					if len(ms) != expected || ms[0] != "direct" {
						t.Fatal("manual order/use changed", ms)
					}
					// Refresh migrated HTTP content uses the complete ownership path, not providers.
					if kind == "http" {
						v, e := h.previewSubscription(context.Background(), rawJSON(map[string]string{"id": subs[0].ID}))
						if e != nil {
							t.Fatal(e)
						}
						q := v.(subscriptionPreview)
						if len(q.Issues) > 0 {
							t.Fatal(q.Issues)
						}
						if _, e := h.Apply(q.Text); e != nil {
							t.Fatal(e)
						}
					}
				})
			}
		}
	}
}
func TestR4MigrationFailureRetainsBytesAndCanRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	h := legacyHost(t, map[string]any{"providers": []any{map[string]any{"name": "old", "type": "file", "path": path}}, "groups": []any{map[string]any{"name": "g", "type": "select", "use": []string{"old"}}}})
	before := h.doc.text
	if _, e := h.previewLegacy(context.Background(), rawJSON(map[string]string{"name": "old"})); e == nil {
		t.Fatal("missing file succeeded")
	}
	b, _ := os.ReadFile(h.path)
	if string(b) != before || h.doc.text != before {
		t.Fatal("failure mutated document")
	}
	os.WriteFile(path, []byte("not a subscription"), 0600)
	if v, e := h.previewLegacy(context.Background(), rawJSON(map[string]string{"name": "old"})); e == nil && v.(subscriptionPreview).Token != "" {
		t.Fatal("invalid file accepted")
	}
	os.WriteFile(path, []byte(legacyNodes), 0600)
	p := migratePreview(t, h, "old")
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
}
func TestR4HTTPMigrationFailureAndAtomicStale(t *testing.T) {
	h := legacyHost(t, map[string]any{"providers": []any{map[string]any{"name": "old", "type": "http", "url": "https://migration.invalid/sub"}}})
	before := h.doc.text
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		return nil, errors.New("secret https://private.invalid/token")
	}
	if _, e := h.previewLegacy(context.Background(), rawJSON(map[string]string{"name": "old"})); e == nil || strings.Contains(e.Error(), "private.invalid") {
		t.Fatal(e)
	}
	if h.doc.text != before {
		t.Fatal("changed on network failure")
	}
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		return []byte(legacyNodes), nil
	}
	p := migratePreview(t, h, "old")
	next := strings.Replace(before, `"mode":"rule"`, `"mode":"direct"`, 1)
	if _, e := h.Apply(next); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Apply(p.Text); e == nil || e.Code != "candidate_expired" {
		t.Fatal("stale migration not rejected", e)
	}
}
func TestR4NoProviderNoOperationAndNewProviderRejected(t *testing.T) {
	h := newHost(t)
	before := h.doc.text
	b, _ := os.ReadFile(h.path)
	root, _ := sourceJSON(h.doc)
	var k map[string]json.RawMessage
	json.Unmarshal(root["kernel"], &k)
	if len(rawArray(k, "providers")) != 0 {
		t.Fatal("fixture")
	}
	// Calling an absent named conversion also cannot change source or stage data.
	if _, e := h.previewLegacy(context.Background(), rawJSON(map[string]string{"name": "absent"})); e == nil {
		t.Fatal("absent converted")
	}
	after, _ := os.ReadFile(h.path)
	if !reflect.DeepEqual(b, after) || h.doc.text != before {
		t.Fatal("no-op rewrote bytes")
	}
	text := strings.Replace(before, `"kernel":{}`, `"kernel":{"providers":[{"name":"new","type":"http","url":"https://migration.invalid/sub"}]}`, 1)
	for _, method := range []string{"document.validate", "document.apply"} {
		if _, e := h.Request(context.Background(), method, rawJSON(map[string]string{"text": text})); e == nil || e.Code != "legacy_provider_unsupported" || e.Message != "节点订阅已不再支持，请使用完整订阅" || e.Detail != nil {
			t.Fatal(method, e)
		}
	}
	if _, e := h.Request(context.Background(), "provider.refresh", rawJSON(map[string]string{"name": "new"})); e == nil || e.Code != "unknown_method" {
		t.Fatal(e)
	}
}
func TestR4LegacyUseCannotBeAddedOrEdited(t *testing.T) {
	h := legacyHost(t, map[string]any{"providers": []any{map[string]any{"name": "old", "type": "http", "url": "https://migration.invalid/sub"}}, "groups": []any{map[string]any{"name": "g", "type": "select", "members": []string{"direct"}}}})
	next := strings.Replace(h.doc.text, `"members":["direct"]`, `"members":["direct"],"use":["old"]`, 1)
	if e := h.Validate(next); e == nil || e.Code != "legacy_provider_unsupported" {
		t.Fatal(e)
	}
}
func TestR4ProbeAllIndependentBudgetsConcurrencyAndStopped(t *testing.T) {
	// Three waves at concurrency two must outlive ONE round budget, while
	// every individual target has ample local handshake/scheduling margin.
	// This distinguishes per-job budgets from a shared whole-batch deadline;
	// merely enlarging the old 80ms/100ms fixture would not establish that.
	const responseDelay = 1250 * time.Millisecond
	const roundBudget = 3 * time.Second
	var in, max atomic.Int32
	var traceMu sync.Mutex
	type requestTime struct{ Start, End time.Time }
	trace := []requestTime{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		n := in.Add(1)
		defer func() {
			in.Add(-1)
			traceMu.Lock()
			trace = append(trace, requestTime{start, time.Now()})
			traceMu.Unlock()
		}()
		for {
			m := max.Load()
			if n <= m || max.CompareAndSwap(m, n) {
				break
			}
		}
		select {
		case <-r.Context().Done():
		case <-time.After(responseDelay):
			w.WriteHeader(204)
		}
	}))
	defer target.Close()
	k := settingsKernel(t)
	o := k["outbounds"].([]any)[0].(map[string]any)
	outs := []any{}
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		q := map[string]any{}
		for k, v := range o {
			q[k] = v
		}
		q["name"] = n
		outs = append(outs, q)
	}
	k["outbounds"] = outs
	delete(k, "groups")
	// Exactly one HEAD per job: connection reuse is not the budget contract
	// under test and must not add a second timed server wait to this fixture.
	h, _ := startSettings(t, k, map[string]any{"probe_url": target.URL, "probe_timeout": "2s", "probe_round_timeout": "3s", "probe_concurrency": 2, "unified_delay": false})
	before := time.Now()
	round := beginAllProbeTest(t, h, context.Background())
	waitAllProbeTest(t, round)
	elapsed := time.Since(before)
	_, projected := round.projection()
	for _, r := range projected {
		t.Logf("node=%q code=%q stage=%q at=%s result=%+v", r.Name, r.ErrorCode, r.ErrorStage, r.At.Format(time.RFC3339Nano), r)
	}
	traceMu.Lock()
	times := append([]requestTime(nil), trace...)
	traceMu.Unlock()
	for i, r := range times {
		t.Logf("request=%d queue_plus_connect=%s start=%s end=%s duration=%s", i, r.Start.Sub(before), r.Start.Format(time.RFC3339Nano), r.End.Format(time.RFC3339Nano), r.End.Sub(r.Start))
	}
	if elapsed <= roundBudget || elapsed > 12*time.Second || max.Load() != 2 {
		t.Fatal("independent-wave budget/concurrency", elapsed, max.Load())
	}
	if len(projected) != 5 || len(times) != 5 {
		t.Fatal("missing/duplicate job or unexpected second measurement", projected, times)
	}
	seen := map[string]bool{}
	for _, r := range projected {
		if seen[r.Name] || r.At.IsZero() || r.ProbeMS == nil || r.ErrorCode != "" {
			t.Fatalf("queued node lost its own budget or result identity: %+v", r)
		}
		seen[r.Name] = true
	}
	if _, e := h.Stop(); e != nil {
		t.Fatal(e)
	}
	if _, e := h.probeAll(context.Background(), nil); e == nil || e.Code != "core_not_running" {
		t.Fatal(e)
	}
}

func TestR4MigrationIndependentAndYAMLNoOperation(t *testing.T) {
	for _, format := range []DocumentFormat{FormatYAML, FormatYML} {
		workspace := t.TempDir()
		before := yamlFixture(17890, 17891) + "# keep exact trailing comment\n"
		path := filepath.Join(workspace, format.filename())
		os.WriteFile(path, []byte(before), 0600)
		h, e := Open(workspace)
		if e != nil {
			t.Fatal(e)
		}
		// c16 explicitly migrates IPv6 once; no-provider reads thereafter stay exact.
		original, _ := os.ReadFile(filepath.Join(workspace, "client-before-c16-network."+string(format)))
		if string(original) != before {
			t.Fatal("c16 exact pre-migration backup")
		}
		before = h.doc.text
		h.Document()
		b, _ := os.ReadFile(path)
		if string(b) != before || h.doc.text != before {
			t.Fatal("no-provider YAML changed")
		}
		h.Close()
	}
	good := filepath.Join(t.TempDir(), "nodes")
	os.WriteFile(good, []byte(legacyNodes), 0600)
	h := legacyHost(t, map[string]any{"providers": []any{map[string]any{"name": "bad", "type": "file", "path": good + "-missing"}, map[string]any{"name": "good", "type": "file", "path": good}}, "groups": []any{map[string]any{"name": "g", "type": "select", "members": []string{"direct"}, "use": []string{"bad", "good"}}}})
	if _, e := h.previewLegacy(context.Background(), rawJSON(map[string]string{"name": "bad"})); e == nil {
		t.Fatal("missing provider accepted")
	}
	p := migratePreview(t, h, "good")
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	if len(h.doc.config.Providers) != 1 || h.doc.config.Providers[0].Name != "bad" {
		t.Fatal("independent failure lost")
	}
	if !reflect.DeepEqual(h.doc.config.Groups[0].Use, []string{"bad"}) {
		t.Fatal("pending reference changed")
	}
}
func TestR4MigrationRequestHeadersAndShorterTimeout(t *testing.T) {
	ctx := context.WithValue(context.Background(), legacyKey{}, &legacyConversion{Config: kernel.ProviderConfig{Headers: map[string]string{"X-Original": "keep"}, UserAgent: "original", Timeout: kernel.Duration(time.Second)}})
	_, e := fetchImportBounded(ctx, "https://migration.invalid/sub", nil, func(*http.Transport) http.RoundTripper {
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("X-Original") != "keep" || req.Header.Get("User-Agent") != "original" {
				t.Fatal("headers not preserved")
			}
			deadline, ok := req.Context().Deadline()
			if !ok || time.Until(deadline) > time.Second {
				t.Fatal("timeout enlarged")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(legacyNodes)), Header: http.Header{}}, nil
		})
	}, 1024)
	if e != nil {
		t.Fatal(e)
	}
}
func TestR4ProbeAllStopCancelsWithoutLateStatus(t *testing.T) {
	entered := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer target.Close()
	k := settingsKernel(t)
	delete(k, "groups")
	h, _ := startSettings(t, k, map[string]any{"probe_url": target.URL, "probe_timeout": "5s", "probe_round_timeout": "10s", "probe_concurrency": 1})
	round := beginAllProbeTest(t, h, context.Background())
	waitSignal(t, entered)
	before := time.Now()
	if _, e := h.Stop(); e != nil {
		t.Fatal(e)
	}
	waitAllProbeTest(t, round)
	if time.Since(before) > time.Second {
		t.Fatal("Stop blocked on all-probe")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.probes) != 0 || h.allRound != nil {
		t.Fatal("canceled round published stale results")
	}
}
func TestR4CloseAPIExactParametersAndMissingIDs(t *testing.T) {
	h := newHost(t)
	for _, raw := range []string{`{}`, `{"ids":null}`, `{"ids":[0]}`, `{"ids":[-1]}`, `{"ids":[1.5]}`, `{"ids":[9007199254740992]}`, `{"ids":[1],"all":true}`} {
		if _, e := h.Request(context.Background(), "connections.close", json.RawMessage(raw)); e == nil || e.Code != "invalid_params" {
			t.Fatal(raw, e)
		}
	}
	for _, raw := range []string{`{"ids":[]}`, `{"ids":[1,1,42]}`} {
		v, e := h.Request(context.Background(), "connections.close", json.RawMessage(raw))
		if e != nil || v.(map[string]int)["closed"] != 0 {
			t.Fatal(v, e)
		}
	}
}
