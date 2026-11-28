package clientcore

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
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

// Regression for the actual production call site, not just an unused helper.
// The previous raw net.Dialer fails this on Linux too; Windows behavioral
// coverage separately verifies real OS attribution with process-name routing.
func TestR8IconRuntimeSocketUsesPrivateOriginalFlow(t *testing.T) {
	b, e := os.ReadFile("presentation.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	if !strings.Contains(s, `proxy.SOCKS5("tcp", portAddress(port), nil, &iconSOCKSForward{})`) {
		t.Fatal("BERO-006: core-owned SOCKS origin is not privately registered; Windows process rules reject it")
	}
	if !strings.Contains(s, `procattr.RegisterHTTP(c, procattr.NewOrigin(c.LocalAddr(), c.RemoteAddr()))`) {
		t.Fatal("BERO-006: real original tuple must be used, never an asserted process name")
	}
}
func TestR8IconFailureEventsAreBoundedPrivateAndKeepPlaceholder(t *testing.T) {
	h := fullHost(t)
	h.iconFetch = func(context.Context, string) ([]byte, error) {
		return nil, errors.New("https://private.invalid/?token=SECRET password=hidden")
	}
	v, e := h.getIcon(context.Background(), rawJSON(map[string]any{"url": "https://private.invalid/icon?token=SECRET"}))
	if e != nil || v.(map[string]any)["data_uri"] != "" {
		t.Fatal("failure must stay silent")
	}
	logs := h.logs.read(0, 500)
	if len(logs.Entries) != 1 || logs.Entries[0].Event != "icon_connect_failed" || logs.Entries[0].Code != "connect_failed" {
		t.Fatal("missing finite stage/category", logs)
	}
	b, _ := json.Marshal(logs)
	for _, x := range []string{"private.invalid", "token", "SECRET", "password", "hidden"} {
		if strings.Contains(string(b), x) {
			t.Fatal("private cause escaped")
		}
	}
	// Unrecognized stage/category must not enter the log ring.
	h.iconFailure("https://secret", "unknown")
	h.iconFailure("connect", "SECRET")
	if len(h.logs.read(0, 500).Entries) != 1 {
		t.Fatal("free text admitted")
	}
}
func TestR8IconFailureStagesCacheTypeHTTPAndBody(t *testing.T) {
	for _, tc := range []struct {
		name, stage, category string
		fetch                 func(context.Context, string) ([]byte, error)
	}{
		{"dns", "resolve", "fake_ip", func(context.Context, string) ([]byte, error) { return nil, dl("resolve", "fake_ip") }},
		{"tls", "tls", "tls_certificate", func(context.Context, string) ([]byte, error) { return nil, dl("tls", "tls_certificate") }},
		{"redirect", "http_status", "redirect_refused", func(context.Context, string) ([]byte, error) { return nil, dl("http_status", "redirect_refused") }},
		{"large", "body_read", "size_limit", func(context.Context, string) ([]byte, error) { return nil, dl("body_read", "size_limit") }},
		{"type", "content_type", "invalid_format", func(context.Context, string) ([]byte, error) { return []byte("<html>not image</html>"), nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := fullHost(t)
			h.iconFetch = tc.fetch
			h.getIcon(context.Background(), rawJSON(map[string]any{"url": "https://example.org/icon"}))
			l := h.logs.read(0, 500)
			if len(l.Entries) != 1 || l.Entries[0].Event != "icon_"+tc.stage+"_failed" || l.Entries[0].Code != tc.category {
				t.Fatal(l)
			}
		})
	}
	h := fullHost(t)
	os.WriteFile(filepath.Join(h.workspace, "icons"), []byte("not a directory"), 0600)
	h.getIcon(context.Background(), rawJSON(map[string]any{"url": "https://example.org/icon"}))
	l := h.logs.read(0, 500)
	if len(l.Entries) != 1 || l.Entries[0].Event != "icon_cache_directory_failed" {
		t.Fatal(l)
	}
}
func TestR8RealIconSocketRegisteredAndClosed(t *testing.T) {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := ln.Accept()
		if e == nil {
			defer c.Close()
			b := make([]byte, 1)
			c.Read(b)
		}
	}()
	c, e := (&iconSOCKSForward{}).DialContext(context.Background(), "tcp", ln.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	if reflect.TypeOf(c).String() != "*procattr.httpConn" {
		t.Fatal("unregistered internal connection", reflect.TypeOf(c))
	}
	if c.LocalAddr() == nil || c.RemoteAddr() == nil {
		t.Fatal("no actual tuple")
	}
	c.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection not closed")
	}
	// Negative control for the old implementation, which has no registry proof.
	raw, e := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	if reflect.TypeOf(raw).String() == "*procattr.httpConn" {
		t.Fatal("ordinary socket must not imply internal proof")
	}
}
func TestR8IconRunningRealSOCKSFailureClassified(t *testing.T) {
	h := fullHost(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/other", 302) }))
	defer target.Close()
	if _, e := h.Apply(fixture(t, map[string]any{"security": map[string]any{"allow_loopback": true}, "dns": map[string]any{"server": "system"}})); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	v, e := h.getIcon(context.Background(), rawJSON(map[string]any{"url": target.URL + "/icon?token=SECRET"}))
	if e != nil || v.(map[string]any)["data_uri"] != "" {
		t.Fatal("redirect escaped")
	}
	found := false
	for _, l := range h.logs.read(0, 500).Entries {
		if l.Event == "icon_http_status_failed" && l.Code == "redirect_refused" {
			found = true
		}
	}
	if !found {
		t.Fatal("network failure not diagnosed")
	}
}

func TestR11DiskIconStartupTableNoNetworkAndStaleOfflinePreserved(t *testing.T) {
	h := fullHost(t)
	url := "https://example.org/icon.png"
	text := fixture(t, map[string]any{"groups": []any{map[string]any{"name": "HK", "type": "select", "members": []string{"direct"}, "icon": url}}})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	h.iconFetch = func(context.Context, string) ([]byte, error) {
		return []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="2" height="2"/>`), nil
	}
	v, e := h.getIcon(context.Background(), rawJSON(map[string]any{"url": url, "group": "HK"}))
	if e != nil || v.(map[string]any)["data_uri"] == "" {
		t.Fatal(e)
	}
	workspace := h.workspace
	h.Close()
	fresh, er := Open(workspace)
	if er != nil {
		t.Fatal(er)
	}
	defer fresh.Close()
	calls := 0
	fresh.iconFetch = func(context.Context, string) ([]byte, error) { calls++; return nil, dl("connect", "timeout") }
	table := fresh.cachedIcons()
	if len(table) != 1 || table[url] != v.(map[string]any)["data_uri"] || calls != 0 {
		t.Fatal("cache hydration fetched/blanked icon")
	}
	path := filepath.Join(workspace, "icons", fmt.Sprintf("%x", sha256.Sum256([]byte(url)))+".img")
	at := time.Now().Add(-8 * 24 * time.Hour)
	os.Chtimes(path, at, at)
	got, ee := fresh.getIcon(context.Background(), rawJSON(map[string]any{"url": url, "group": "HK"}))
	if ee != nil || got.(map[string]any)["data_uri"] != table[url] {
		t.Fatal("stale icon not returned immediately")
	}
	fresh.iconWG.Wait()
	if calls != 1 || fresh.cachedIcons()[url] != table[url] {
		t.Fatal("refresh failure discarded local icon")
	}
}
func TestR11AutomaticProbeFailureNotUnknownAndNewestWins(t *testing.T) {
	h := fullHost(t)
	text := fixture(t, map[string]any{"security": map[string]any{"allow_loopback": true}, "outbounds": []any{map[string]any{"name": "dead", "type": "socks5", "server": "127.0.0.1", "port": freePort(t)}}, "groups": []any{map[string]any{"name": "U", "type": "url-test", "members": []string{"dead"}, "probe": map[string]any{"url": "http://example.org/204", "timeout": "100ms"}}}})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(time.Second)
	for {
		st := h.Status().(map[string]any)
		groups := st["groups"].([]any)
		members := groups[0].(map[string]any)["members"].([]any)
		m := members[0].(map[string]any)
		if m["probe_error"] == "PROBE_FAILED" {
			nodes := st["nodes"].([]any)
			if nodes[0].(map[string]any)["probe_error"] != "PROBE_FAILED" {
				t.Fatal("node table swallowed health failure")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("real completed failure became unmeasured")
		}
		time.Sleep(time.Millisecond)
	}
}
