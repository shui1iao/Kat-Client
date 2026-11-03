package clientcore

// Contract fixtures only: NOTRUN, including test compilation in this package.
import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shui1iao/Kat/internal/clientegress"
)

func TestManualResourceSubscriptionExactSingleItemAndFutureCache(t *testing.T) {
	h := fullHost(t)
	if _, e := h.Apply(fixture(t, map[string]any{})); e != nil {
		t.Fatal(e)
	}
	imported, _ := cacheFixture(t, h)
	preview := fullPreview(t, h, imported, "")
	bAccept(t, h, preview)
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	beforeRoot, _ := sourceJSON(h.doc)
	beforeKernel := rawObject(beforeRoot["kernel"])
	oldPath := h.doc.config.RuleSets[0].Path
	oldBytes, e := readSubscriptionResource(oldPath, 16<<20)
	if e != nil {
		t.Fatal(e)
	}
	calls := []string{}
	fresh := []byte("payload: ['DOMAIN,fresh.invalid']\n")
	h.fullFetch = func(_ context.Context, url string, _ *clientegress.Policy, _ int64) ([]byte, error) {
		calls = append(calls, url)
		return fresh, nil
	}
	name := h.doc.config.RuleSets[0].Name
	result, failure := h.refreshResource(context.Background(), rawJSON(map[string]string{"kind": "rule_set", "name": name}))
	if failure != nil {
		t.Fatal(failure)
	}
	if len(calls) != 1 || calls[0] != "https://example.invalid/set" {
		t.Fatalf("not a single resource fetch: %v", calls)
	}
	if result.(map[string]any)["action"] != "downloaded" {
		t.Fatal(result)
	}
	afterRoot, _ := sourceJSON(h.doc)
	afterKernel := rawObject(afterRoot["kernel"])
	for _, key := range []string{"outbounds", "groups", "routing"} {
		if !sameJSON(beforeKernel[key], afterKernel[key]) {
			t.Fatalf("unrelated %s changed", key)
		}
	}
	if !sameJSON(beforeRoot["client"], afterRoot["client"]) {
		t.Fatal("client preferences changed")
	}
	path := h.doc.config.RuleSets[0].Path
	if path == oldPath {
		t.Fatal("original cache overwritten")
	}
	retained, e := os.ReadFile(oldPath)
	if e != nil || string(retained) != string(oldBytes) {
		t.Fatal("old cache changed", e)
	}
	subs := bSubs(t, h)
	local, updated := h.subscriptionLocalBytes(&subs[0], calls[0], 16<<20)
	if string(local) != string(fresh) || updated == 0 {
		t.Fatal("single refresh did not update reusable SHA/Updated cache")
	}
	if !sameJSON(subs[0].Snapshot.RuleSets[0], rawArray(afterKernel, "rule_sets")[0]) {
		t.Fatal("snapshot no longer matches active declaration")
	}
	if subs[0].Resources[calls[0]].Interval != 86400 {
		t.Fatal("interval changed")
	}
	if views := h.server.ResourceViews(); len(views) != 1 || views[0].State != "ok" || views[0].Entries == nil || *views[0].Entries != 1 {
		t.Fatal("new generation did not load target", views)
	}
	// A bad download must retain the accepted source and running generation.
	accepted, gen := h.doc.text, h.server.GenerationID()
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		return []byte("<html>not rules</html>"), nil
	}
	if _, failure = h.refreshResource(context.Background(), rawJSON(map[string]string{"kind": "rule_set", "name": name})); failure == nil {
		t.Fatal("bad resource accepted")
	}
	if h.doc.text != accepted || h.server.GenerationID() != gen {
		t.Fatal("failure changed source/generation")
	}
	// An in-flight result must not publish over an explicit intervening reload.
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		if _, failure := h.Reload(); failure != nil {
			t.Fatal(failure)
		}
		return fresh, nil
	}
	if _, failure = h.refreshResource(context.Background(), rawJSON(map[string]string{"kind": "rule_set", "name": name})); failure == nil {
		t.Fatal("obsolete result accepted")
	}
	if h.doc.text != accepted {
		t.Fatal("stale result changed source")
	}
}

func TestManualResourcePureLocalReloadIsReadOnlyAndInvalidKeepsData(t *testing.T) {
	h := newHost(t)
	path := filepath.Join(t.TempDir(), "shared.txt")
	if e := os.WriteFile(path, []byte("+.old.invalid\n"), 0644); e != nil {
		t.Fatal(e)
	}
	text := fixture(t, map[string]any{"rule_sets": []any{map[string]any{"name": "local", "format": "domain", "path": path}}})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	fresh := []byte("+.fresh.invalid\n+.second.invalid\n")
	if e := os.WriteFile(path, fresh, 0644); e != nil {
		t.Fatal(e)
	}
	before, _ := os.Stat(path)
	accepted, gen := h.doc.text, h.server.GenerationID()
	reply, failure := h.refreshResource(context.Background(), rawJSON(map[string]string{"kind": "rule_set", "name": "local"}))
	if failure != nil {
		t.Fatal(failure)
	}
	if reply.(map[string]any)["action"] != "reloaded" || h.doc.text != accepted || h.server.GenerationID() != gen {
		t.Fatal("local reload claimed a remote/source change")
	}
	after, _ := os.Stat(path)
	content, _ := os.ReadFile(path)
	if !os.SameFile(before, after) || before.Mode() != after.Mode() || string(content) != string(fresh) {
		t.Fatal("local reload wrote or changed file permissions")
	}
	if views := h.server.ResourceViews(); views[0].Entries == nil || *views[0].Entries != 2 {
		t.Fatal("local bytes not active", views)
	}
	if e := os.WriteFile(path, []byte("<html>bad</html>"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, failure = h.refreshResource(context.Background(), rawJSON(map[string]string{"kind": "rule_set", "name": "local"})); failure == nil {
		t.Fatal("bad local bytes accepted")
	}
	if views := h.server.ResourceViews(); views[0].Entries == nil || *views[0].Entries != 2 {
		t.Fatal("bad reload lost old active data", views)
	}
}

func TestResourceScalarPatchPreservesUnrelatedJSONAndYAMLBytes(t *testing.T) {
	for _, tc := range []struct {
		format     DocumentFormat
		text, want string
	}{
		{FormatJSON, " { \"kernel\" : {\"geoip\":{\"path\":\"old\"}},\"keep\": 1e0 }\n", " { \"kernel\" : {\"geoip\":{\"path\":\"new\"}},\"keep\": 1e0 }\n"},
		{FormatYAML, "# header\r\nkernel: {geoip: {path: 'old'}} # untouched\r\nkeep: 1e0\r\n", "# header\r\nkernel: {geoip: {path: \"new\"}} # untouched\r\nkeep: 1e0\r\n"},
	} {
		got, e := patchResourceSource(document{text: tc.text, format: tc.format}, []resourceScalarPatch{{[]string{"kernel", "geoip", "path"}, "old", "new"}})
		if e != nil || got != tc.want {
			t.Fatalf("patch changed unrelated bytes: %q %v", got, e)
		}
	}
}

func TestManualResourceRejectsStaleSHAAndIgnoresInactiveSameName(t *testing.T) {
	h := fullHost(t)
	imported, _ := cacheFixture(t, h)
	p := fullPreview(t, h, imported, "")
	bAccept(t, h, p)
	root, _ := sourceJSON(h.doc)
	subs := bSubs(t, h)
	name := h.doc.config.RuleSets[0].Name
	for url, meta := range subs[0].Resources {
		meta.SHA256 = strings.Repeat("0", 64)
		subs[0].Resources[url] = meta
	}
	root["subscriptions"] = rawJSON(subs)
	text, e := renderSubscriptionSource(h.doc, root)
	if e != nil {
		t.Fatal(e)
	}
	d, de := parseDocument(text, h.workspace, h.doc.format)
	if de != nil {
		t.Fatal(de)
	}
	h.mu.Lock()
	_, failure := h.manualResourceLocked(d, "rule_set", name)
	h.mu.Unlock()
	if failure == nil || failure.Code != "resource_source_changed" {
		t.Fatal("stale SHA trusted", failure)
	}
	subs[0].Active = boolRef(false)
	root["subscriptions"] = rawJSON(subs)
	text, e = renderSubscriptionSource(h.doc, root)
	if e != nil {
		t.Fatal(e)
	}
	d, de = parseDocument(text, h.workspace, h.doc.format)
	if de != nil {
		t.Fatal(de)
	}
	h.mu.Lock()
	target, failure := h.manualResourceLocked(d, "rule_set", name)
	h.mu.Unlock()
	if failure != nil || target.owner != nil || target.url != "" {
		t.Fatal("inactive name granted provenance", failure)
	}
	// Current declarations with a local manual edit are not rebound by display name.
	var projection map[string]json.RawMessage
	_ = json.Unmarshal(root["kernel"], &projection)
	sets := rawArray(projection, "rule_sets")
	set := rawObject(sets[0])
	set["max_bytes"] = rawJSON(1024)
	sets[0] = rawJSON(set)
	projection["rule_sets"] = rawJSON(sets)
	root["kernel"] = rawJSON(projection)
	subs[0].Active = boolRef(true)
	root["subscriptions"] = rawJSON(subs)
	text, e = renderSubscriptionSource(h.doc, root)
	if e != nil {
		t.Fatal(e)
	}
	d, de = parseDocument(text, h.workspace, h.doc.format)
	if de != nil {
		t.Fatal(de)
	}
	h.mu.Lock()
	target, failure = h.manualResourceLocked(d, "rule_set", name)
	h.mu.Unlock()
	if failure != nil || target.owner != nil {
		t.Fatal("edited declaration rebound by name", failure)
	}
}

// Updating one remote source cannot silently reload another local source that
// the user has replaced on disk. Even an invalid unrelated replacement must
// keep its previously loaded bytes and original metadata, not block this item.
func TestManualResourceRemoteDoesNotReloadUnrelatedLocalFile(t *testing.T) {
	h := fullHost(t)
	path := filepath.Join(t.TempDir(), "unrelated.txt")
	if err := os.WriteFile(path, []byte("+.untouched.invalid\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Apply(fixture(t, map[string]any{"rule_sets": []any{map[string]any{"name": "untouched", "format": "domain", "path": path}}})); err != nil {
		t.Fatal(err)
	}
	imported, _ := cacheFixture(t, h)
	p := fullPreview(t, h, imported, "")
	bAccept(t, h, p)
	if _, err := h.Start(); err != nil {
		t.Fatal(err)
	}
	subs := bSubs(t, h)
	target := rawName(subs[0].Snapshot.RuleSets[0])
	var before json.RawMessage
	for _, view := range h.server.ResourceViews() {
		if view.Name == "untouched" {
			before = rawJSON(view)
		}
	}
	if len(before) == 0 {
		t.Fatal("missing unrelated resource")
	}
	if err := os.WriteFile(path, []byte("<html>invalid replacement</html>"), 0644); err != nil {
		t.Fatal(err)
	}
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		return []byte("payload: ['DOMAIN,target-new.invalid']\n"), nil
	}
	if _, err := h.refreshResource(context.Background(), rawJSON(map[string]string{"kind": "rule_set", "name": target})); err != nil {
		t.Fatal(err)
	}
	for _, view := range h.server.ResourceViews() {
		if view.Name == "untouched" && !sameJSON(before, rawJSON(view)) {
			t.Fatal("single-item update reloaded unrelated local file", view)
		}
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "<html>invalid replacement</html>" {
		t.Fatal("unrelated file written", err)
	}
}
