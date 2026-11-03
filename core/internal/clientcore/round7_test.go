package clientcore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestR7SelectNestedIndependentHEADAndStatus(t *testing.T) {
	var calls, gets atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "HEAD" {
			gets.Add(1)
		}
		select {
		case <-time.After(70 * time.Millisecond):
			w.WriteHeader(204)
		case <-r.Context().Done():
		}
	}))
	defer target.Close()
	k := batchKernel(t, 7)
	k["groups"] = []any{map[string]any{"name": "nested", "type": "select", "members": []string{"n00"}, "selected": "n00"}, map[string]any{"name": "Proxy", "type": "select", "members": []string{"n00", "n01", "n02", "n03", "n04", "n05", "n06", "nested"}}}
	h, _ := startSettings(t, k, map[string]any{"probe_url": target.URL, "probe_timeout": "100ms", "probe_round_timeout": "100ms", "probe_concurrency": 2})
	before := time.Now()
	v, e := h.Request(context.Background(), "probe.group", rawJSON(map[string]any{"name": "Proxy"}))
	if e != nil || v.(map[string]any)["started"] != true {
		t.Fatal(v, e)
	}
	h.mu.Lock()
	round := h.groupRounds["Proxy"]
	h.mu.Unlock()
	waitAllProbeTest(t, round)
	if time.Since(before) < 250*time.Millisecond || calls.Load() != 8 || gets.Load() != 0 {
		t.Fatal("shared budget or non-HEAD", time.Since(before), calls.Load(), gets.Load())
	}
	s := h.Status().(map[string]any)
	var members []any
	for _, g := range s["groups"].([]any) {
		if g.(map[string]any)["name"] == "Proxy" {
			members = g.(map[string]any)["members"].([]any)
		}
	}
	if len(members) != 8 {
		t.Fatal("members missing")
	}
	for _, m := range members {
		p := m.(map[string]any)
		if p["probe_ms"] == nil || p["probe_error"] != "" || p["probe_at"] == nil {
			t.Fatal("select manual result lost", p)
		}
	}
	// Probing nested member means its selected route, NOT measuring every child.
	if _, e = h.probe(context.Background(), false, "nested", target.URL); e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 9 {
		t.Fatal("nested fanned out", calls.Load())
	}
}
func TestR7HEADFallbackSharesTargetDeadline(t *testing.T) {
	methods := []string{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		if r.Method == "HEAD" {
			w.WriteHeader(405)
		} else {
			w.WriteHeader(204)
		}
	}))
	defer target.Close()
	h, _ := startSettings(t, batchKernel(t, 1), map[string]any{"probe_url": target.URL})
	r, e := h.probe(context.Background(), false, "n00", "")
	if e != nil || r.(kernel.ProbeResult).ProbeMS == nil || strings.Join(methods, ",") != "HEAD,GET" {
		t.Fatal(r, e, methods)
	}
}
func TestR7FilterPreviewExactRuntimeAndDynamicImport(t *testing.T) {
	h := fullHost(t)
	fixture := strings.Replace(fullFixture, "{name: pick, type: select, proxies: [n, DIRECT]}", "{name: pick, type: select, proxies: [DIRECT], include-all: true, filter: '(?i)n', exclude-filter: 'expired', icon: 'https://example.org/icon.png'}", 1)
	p := fullPreview(t, h, fixture, "")
	if _, e := h.Apply(p.Text, p.Format); e != nil {
		t.Fatal(e)
	}
	cfg := h.doc.config.Groups[0]
	if !cfg.IncludeAll || cfg.Filter != "(?i)n" || cfg.Icon != "https://example.org/icon.png" || len(cfg.Members) != 1 {
		t.Fatal("dynamic metadata lost", cfg)
	}
	var root map[string]any
	_ = json.Unmarshal([]byte(h.doc.text), &root)
	k := root["kernel"].(map[string]any)
	k["outbounds"] = append(k["outbounds"].([]any), map[string]any{"name": "NEW", "type": "socks5", "server": "example.org", "port": 1080})
	k["groups"].([]any)[0].(map[string]any)["selected"] = "NEW"
	bb, _ := json.Marshal(root)
	text := string(bb)
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ inc, exc string }{{"(?i)n", "expired"}, {"^(?!.*(expired)).*$", "NEW"}, {"[", ""}} {
		v, e := h.filterPreview(rawJSON(map[string]any{"filter": tc.inc, "exclude_filter": tc.exc}))
		if e != nil {
			t.Fatal(e)
		}
		out := v.(map[string]any)
		match, err := group.MemberFilter(group.Options{Filter: tc.inc, ExcludeFilter: tc.exc})
		if err != nil {
			if out["error"] == nil || len(out["names"].([]string)) != 0 {
				t.Fatal(out)
			}
			continue
		}
		want := []string{}
		for _, o := range h.doc.config.Outbounds {
			if match(o.Name, o.Type) {
				want = append(want, o.Name)
			}
		}
		a, _ := json.Marshal(want)
		b, _ := json.Marshal(out["names"])
		if string(a) != string(b) {
			t.Fatal(string(a), string(b))
		}
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	for _, g := range h.server.GroupSnapshots() {
		if g.Name == "pick" && len(g.Members) != 3 {
			t.Fatal("new manual matching node not dynamically joined", len(g.Members))
		}
	}
	// Refresh updates icon and retains dynamic fields rather than a frozen list.
	next := fullPreview(t, h, strings.Replace(fixture, "icon.png", "new.svg", 1), p.ID)
	if _, e := h.Apply(next.Text, next.Format); e != nil {
		t.Fatal(e)
	}
	if h.doc.config.Groups[0].Icon != "https://example.org/new.svg" || !h.doc.config.Groups[0].IncludeAll || h.doc.config.Groups[0].Selected != "NEW" {
		t.Fatal("refresh lost metadata")
	}
}
func TestR7IconTypesLimitsCacheStaleFailureAndStoppedSSRF(t *testing.T) {
	h := fullHost(t)
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><path d="M0 0h16v16H0z"/></svg>`)
	var calls atomic.Int32
	var fail atomic.Bool
	h.iconFetch = func(context.Context, string) ([]byte, error) {
		calls.Add(1)
		if fail.Load() {
			return nil, errors.New("private upstream failure")
		}
		return svg, nil
	}
	get := func(url string) string {
		t.Helper()
		v, e := h.getIcon(context.Background(), rawJSON(map[string]any{"url": url}))
		if e != nil {
			t.Fatal(e)
		}
		return v.(map[string]any)["data_uri"].(string)
	}
	if !strings.HasPrefix(get("https://example.org/icon.svg"), "data:image/svg+xml;base64,") {
		t.Fatal("icon not returned")
	}
	get("https://example.org/icon.svg")
	if calls.Load() != 1 {
		t.Fatal("fresh cache re-fetched")
	}
	files, _ := filepath.Glob(filepath.Join(h.workspace, "icons", "*.img"))
	if len(files) != 1 {
		t.Fatal(files)
	}
	old := time.Now().Add(-8 * 24 * time.Hour)
	os.Chtimes(files[0], old, old)
	fail.Store(true)
	if get("https://example.org/icon.svg") == "" {
		t.Fatal("stale icon disappeared")
	}
	h.iconWG.Wait()
	if calls.Load() != 2 {
		t.Fatal("stale not refreshed")
	}
	if get("https://example.org/icon.svg") == "" {
		t.Fatal("failure erased cache")
	}
	h.iconWG.Wait()
	for _, url := range []string{"file:///etc/passwd", "data:image/svg+xml,hello", "https://user:pass@example.org/icon", "https://example.org/" + strings.Repeat("x", 2048)} {
		if get(url) != "" {
			t.Fatal("unsupported icon source")
		}
	}
	if get(string(svg)) == "" {
		t.Fatal("inline SVG failed")
	}
	for _, b := range [][]byte{[]byte("<html>secret</html>"), make([]byte, maxIconBytes+1)} {
		if _, e := iconData(b); e == nil {
			t.Fatal("type/size accepted")
		}
	}
	for _, b := range [][]byte{{0, 0, 1, 0, 0, 0}, []byte("GIF89a"), []byte("\x89PNG\r\n\x1a\n"), []byte("RIFF\x00\x00\x00\x00WEBPVP8 "), []byte("\xff\xd8\xff")} {
		if _, e := iconData(b); e != nil {
			t.Fatal("supported format rejected")
		}
	}
	h.iconFetch = nil
	_, e := h.fetchIcon(context.Background(), "http://127.0.0.1/icon.png")
	if e == nil {
		t.Fatal("stopped direct SSRF not refused")
	}
	for _, icon := range []string{"javascript:alert(1)", strings.Repeat("x", 2049), "<svg" + strings.Repeat(" ", 64<<10) + ">"} {
		if group.ValidIcon(icon) {
			t.Fatal("invalid field accepted")
		}
	}
}
func TestR7IconRunningUsesKernelRouting(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("GIF89a")) }))
	defer target.Close()
	h := newHost(t)
	if _, e := h.Apply(fixture(t, map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}})); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	v, e := h.getIcon(context.Background(), rawJSON(map[string]any{"url": target.URL}))
	if e != nil || v.(map[string]any)["data_uri"] == "" {
		t.Fatal("kernel route image failed", e)
	}
}

func TestR7IconFieldValidationAndRejectRedirectSizeSpoof(t *testing.T) {
	h := fullHost(t)
	before := h.doc.text
	for _, icon := range []string{"javascript:alert(1)", "https://example.org/" + strings.Repeat("x", 2048), "<svg" + strings.Repeat(" ", 64<<10) + ">"} {
		text := fixture(t, map[string]any{"groups": []any{map[string]any{"name": "g", "type": "select", "members": []string{"direct"}, "icon": icon}}})
		if _, e := h.Apply(text); e == nil {
			t.Fatal("bad icon accepted by document validation")
		}
		if h.doc.text != before {
			t.Fatal("bad metadata changed source")
		}
	}
	if _, e := h.filterPreview(rawJSON(map[string]any{"filter": strings.Repeat("a", 4097)})); e == nil {
		t.Fatal("unbounded preview")
	}
	var followed atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/image", 302)
		case "/image":
			followed.Add(1)
			w.Write([]byte("GIF89a"))
		case "/spoof":
			w.Header().Set("Content-Type", "image/png")
			w.Write([]byte("<html>not an image</html>"))
		case "/big":
			w.Write([]byte("GIF89a" + strings.Repeat("x", maxIconBytes)))
		}
	}))
	defer target.Close()
	if _, e := h.Apply(fixture(t, map[string]any{"security": map[string]any{"allow_loopback": true}, "dns": map[string]any{"server": "system"}})); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/redirect", "/spoof", "/big"} {
		v, e := h.getIcon(context.Background(), rawJSON(map[string]any{"url": target.URL + path}))
		if e != nil || v.(map[string]any)["data_uri"] != "" {
			t.Fatal("unsafe response became icon", path)
		}
	}
	if followed.Load() != 0 {
		t.Fatal("icon followed redirect")
	}
}

func TestR7OriginalRegexMatchesImportedNameAfterSafeIDNormalization(t *testing.T) {
	h := fullHost(t)
	text := strings.Replace(fullFixture, "name: n,", "name: Hong Kong,", 1)
	text = strings.Replace(text, "proxies: [n, DIRECT]", "proxies: [DIRECT], include-all: true, filter: '^Hong Kong$'", 1)
	p := fullPreview(t, h, text, "")
	if _, e := h.Apply(p.Text, p.Format); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	out := h.doc.config.Outbounds[0]
	if out.Name != "Hong_Kong" || out.FilterName != "Hong Kong" {
		t.Fatal("original matching label lost")
	}
	v, e := h.filterPreview(rawJSON(map[string]any{"filter": "^Hong Kong$"}))
	if e != nil || uiJSON(v.(map[string]any)["names"]) != `["Hong_Kong"]` {
		t.Fatal("preview/runtime mismatch", v, e)
	}
	for _, g := range h.server.GroupSnapshots() {
		if g.Name == "pick" && (len(g.Members) != 2 || g.Members[1].Name != "Hong_Kong") {
			t.Fatal("original regex failed after safe normalization")
		}
	}
}
