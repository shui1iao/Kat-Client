package clientcore

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/kernel"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestR9OriginalLabelsStableIDsRefreshPreservesEverything(t *testing.T) {
	h := fullHost(t)
	text := strings.ReplaceAll(fullFixture, "name: n,", "name: '🇭🇰 Flower',")
	text = strings.ReplaceAll(text, "[n, DIRECT]", "['🇭🇰 Flower', DIRECT]")
	text += ""
	p := fullPreview(t, h, text, "")
	if _, e := h.Apply(p.Text, p.Format); e != nil {
		t.Fatal(e)
	}
	root, _ := sourceJSON(h.doc)
	subs, _ := subscriptionsOf(root)
	id := subs[0].Names["🇭🇰 Flower"]
	if id == "" || id == "🇭🇰 Flower" {
		t.Fatal("stable safe ID required")
	}
	var d map[string]any
	json.Unmarshal([]byte(h.doc.text), &d)
	k := d["kernel"].(map[string]any)
	g := k["groups"].([]any)[0].(map[string]any)
	g["selected"] = id
	k["outbounds"] = append(k["outbounds"].([]any), map[string]any{"name": "manual", "type": "socks5", "server": "manual.invalid", "port": 9})
	k["routing"].(map[string]any)["rules"] = append(k["routing"].(map[string]any)["rules"].([]any), map[string]any{"domain": "manual.invalid", "outbound": id})
	b, _ := json.Marshal(d)
	if _, e := h.Apply(string(b)); e != nil {
		t.Fatal(e)
	}
	ms := 31.0
	h.probes[id] = kernel.ProbeResult{Name: id, ProbeMS: &ms, At: time.Now()}
	next := fullPreview(t, h, text, p.ID)
	if _, e := h.Apply(next.Text, next.Format); e != nil {
		t.Fatal(e)
	}
	if h.doc.config.Groups[0].Selected != id || func() bool {
		label, manual := false, false
		for _, o := range h.doc.config.Outbounds {
			label = label || o.FilterName == "🇭🇰 Flower"
			manual = manual || o.Name == "manual"
		}
		return !label || !manual
	}() || h.probes[id].ProbeMS == nil {
		t.Fatal("refresh lost original label/selection/manual/history", h.doc.config.Groups[0], h.probes)
	}
	found := false
	for _, r := range h.doc.config.Routing.Rules {
		if r.Domain == "manual.invalid" && r.Outbound == id {
			found = true
		}
	}
	if !found {
		t.Fatal("manual rule reference changed")
	}
	out, e := h.filterPreview(rawJSON(map[string]any{"filter": "(?i)^🇭🇰 Flower$"}))
	if e != nil || len(out.(map[string]any)["names"].([]string)) != 1 || out.(map[string]any)["names"].([]string)[0] != id {
		t.Fatal("regex must use exact original", out, e)
	}
}
func TestR9OriginalFixedAndWeightsSurviveRefresh(t *testing.T) {
	h := fullHost(t)
	text := strings.Replace(fullFixture, "type: select, proxies: [n, DIRECT]", "type: url-test, proxies: [n, DIRECT], url: https://example.org/204", 1)
	p := fullPreview(t, h, text, "")
	if _, e := h.Apply(p.Text, p.Format); e != nil {
		t.Fatal(e)
	}
	root, _ := sourceJSON(h.doc)
	var k map[string]json.RawMessage
	json.Unmarshal(root["kernel"], &k)
	a := rawArray(k, "groups")
	var g map[string]any
	json.Unmarshal(a[0], &g)
	g["fixed"] = "n"
	g["priority"] = map[string]float64{"n": 1.5}
	a[0] = rawJSON(g)
	k["groups"] = rawJSON(a)
	root["kernel"] = rawJSON(k)
	if _, e := h.Apply(string(rawJSON(root))); e != nil {
		t.Fatal(e)
	}
	next := fullPreview(t, h, text, p.ID)
	if _, e := h.Apply(next.Text, next.Format); e != nil {
		t.Fatal(e)
	}
	g2 := h.doc.config.Groups[0]
	if g2.Fixed != "n" || g2.Priority["n"] != 1.5 {
		t.Fatal("fixed/weight lost", g2)
	}
}
func TestR9MetadataTitleOrderAndPrivacyBounds(t *testing.T) {
	for _, tc := range []struct{ title, disposition, url, want string }{{"base64:" + base64.StdEncoding.EncodeToString([]byte("我的订阅")), `attachment; filename="file.yaml"`, "https://example.org/sub.yaml?token=SECRET", "我的订阅"}, {"", `attachment; filename*=UTF-8''%E8%AE%A2%E9%98%85.yaml`, "https://example.org/path?token=SECRET", "订阅.yaml"}, {"", "", "https://example.org/a/sub.yaml?token=SECRET", "sub.yaml"}, {"", "", "https://example.org/?token=SECRET", "example.org"}, {"bad\nname", "", "https://example.org/", "example.org"}} {
		ctx := context.WithValue(context.Background(), subscriptionHeadersKey{}, &subscriptionHeaders{title: tc.title, disposition: tc.disposition})
		if got := subscriptionName(ctx, tc.url); got != tc.want {
			t.Fatal(got, tc.want)
		}
	}
	meta := &subscriptionHeaders{}
	ctx := context.WithValue(context.Background(), subscriptionHeadersKey{}, meta)
	_, e := fetchImportBounded(ctx, "https://example.org/config", nil, func(*http.Transport) http.RoundTripper {
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Profile-Title": []string{"recognized"}}, Body: io.NopCloser(strings.NewReader("ok"))}, nil
		})
	}, 1024)
	if e != nil || meta.title != "recognized" {
		t.Fatal(meta, e)
	}
}
func TestR9SubscriptionRouteAndAutoUpdatePersistWithAutomaticRename(t *testing.T) {
	h := fullHost(t)
	h.fullFetch = func(ctx context.Context, _ string, _ *clientegress.Policy, _ int64) ([]byte, error) {
		if m, ok := ctx.Value(subscriptionHeadersKey{}).(*subscriptionHeaders); ok {
			m.title = "识别订阅"
		}
		return []byte(fullFixture), nil
	}
	v, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"url": "https://example.org/config?token=SECRET", "use_system_proxy": true, "auto_update": false}))
	if e != nil {
		t.Fatal(e)
	}
	p := v.(subscriptionPreview)
	if _, e = h.Apply(p.Text, p.Format); e != nil {
		t.Fatal(e)
	}
	root, _ := sourceJSON(h.doc)
	subs, _ := subscriptionsOf(root)
	if subs[0].Name != "识别订阅" || !subs[0].UseSystemProxy || subs[0].AutoUpdate == nil || *subs[0].AutoUpdate {
		t.Fatal(subs[0].Name)
	}
	// Legacy automatic name is upgraded, user-authored name preserved.
	for _, tc := range []struct{ old, want string }{{"完整配置 abcdef", "识别订阅"}, {"我自己起的名", "我自己起的名"}} {
		subs[0].Name = tc.old
		root["subscriptions"] = rawJSON(subs)
		if _, e = h.Apply(string(rawJSON(root))); e != nil {
			t.Fatal(e)
		}
		q, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"id": p.ID}))
		if e != nil {
			t.Fatal(e)
		}
		next := q.(subscriptionPreview)
		if _, e = h.Apply(next.Text, next.Format); e != nil {
			t.Fatal(e)
		}
		root, _ = sourceJSON(h.doc)
		subs, _ = subscriptionsOf(root)
		if subs[0].Name != tc.want || !subs[0].UseSystemProxy {
			t.Fatal("metadata refresh lost saved route/name")
		}
	}
}
func TestR9DesktopDNSAndUnifiedDefaultsOnlyProjection(t *testing.T) {
	d, e := parseDocument(initialDocument, t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if d.config.DNS == nil || d.config.DNS.Server != "system" || strings.Contains(d.text, "unified_delay") {
		t.Fatal("desktop defaults not projected")
	}
	custom := strings.Replace(initialDocument, `"kernel":{}`, `"kernel":{"dns":{"servers":["8.8.8.8","1.1.1.1"]}}`, 1)
	d, e = parseDocument(custom, t.TempDir())
	if e != nil || len(d.config.DNS.Servers) != 2 {
		t.Fatal("explicit user DNS lost", e)
	}
	for _, raw := range []string{`null`, `"true"`, `1`} {
		text := strings.Replace(initialDocument, `"mode":"rule"`, `"mode":"rule","unified_delay":`+raw, 1)
		if _, e := parseDocument(text, t.TempDir()); e == nil {
			t.Fatal("invalid unified accepted", raw)
		}
	}
}
func TestR9StoppedIconProxyThenDirectAndGroupLog(t *testing.T) {
	for _, mode := range []string{"proxy", "direct", "fallback"} {
		t.Run(mode, func(t *testing.T) {
			h := fullHost(t)
			var routes []bool
			h.iconTransport = func(tr *http.Transport) http.RoundTripper {
				return roundTripFunc(func(req *http.Request) (*http.Response, error) {
					proxied := bootstrapFrom(req.Context()) != nil
					routes = append(routes, proxied)
					if proxied && mode == "fallback" {
						return nil, dl("proxy_connect", "proxy_http")
					}
					return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`<svg xmlns="http://www.w3.org/2000/svg"/>`))}, nil
				})
			}
			p := map[string]any{"url": "https://raw.githubusercontent.com/public/icon.png?token=SECRET"}
			if mode != "direct" {
				p["_system_proxy"] = bootstrapProxy{Host: "127.0.0.1", Port: 7890}
				p["_egress"] = bootstrapEgress{Generation: 0, Enabled: false}
			}
			v, e := h.getIcon(context.Background(), rawJSON(p))
			if e != nil || !strings.HasPrefix(v.(map[string]any)["data_uri"].(string), "data:image/svg+xml;") {
				t.Fatal("route did not return image", e)
			}
			if mode == "proxy" && (len(routes) != 1 || !routes[0]) || mode == "direct" && (len(routes) != 1 || routes[0]) || mode == "fallback" && (len(routes) != 2 || !routes[0] || routes[1]) {
				t.Fatal("wrong priority", routes)
			}
			if mode == "fallback" {
				l := h.logs.read(0, 500)
				if len(l.Entries) != 1 || l.Entries[0].Code != "proxy_http" {
					t.Fatal("proxy failure invisible", l)
				}
			}
		})
	}
	h := fullHost(t)
	p := fullPreview(t, h, fullFixture, "")
	h.Apply(p.Text, p.Format)
	h.iconFetch = func(context.Context, string) ([]byte, error) { return nil, errors.New("https://secret/?token=SECRET") }
	h.getIcon(context.Background(), rawJSON(map[string]any{"url": "https://example.org/icon", "group": "pick"}))
	l := h.logs.read(0, 500)
	if len(l.Entries) != 1 || l.Entries[0].Group != "pick" {
		t.Fatal("group missing", l)
	}
	b, _ := json.Marshal(l)
	if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "https:") {
		t.Fatal("private data escaped")
	}
}
func TestR9IconProxySeamStillSendsHostnameCONNECTWithoutLocalResolve(t *testing.T) {
	h := fullHost(t)
	calls := 0
	h.iconTransport = func(tr *http.Transport) http.RoundTripper {
		tr.DialContext = func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialBootstrapIO(ctx, address, bootstrapFrom(ctx), nil, func(context.Context, string) ([]netip.Addr, error) {
				t.Error("target resolver called")
				return []netip.Addr{netip.MustParseAddr("198.18.1.1")}, nil
			}, nil, func(context.Context, *net.Dialer, string) (net.Conn, error) {
				a, b := net.Pipe()
				go func() {
					defer b.Close()
					reader := bufio.NewReader(b)
					req, e := http.ReadRequest(reader)
					if e != nil {
						return
					}
					if req.Method != "CONNECT" || req.Host != "icons.example.org:80" {
						t.Error("hostname not delegated")
					}
					calls++
					io.WriteString(b, "HTTP/1.1 200 Connection established\r\n\r\n")
					req, e = http.ReadRequest(reader)
					if e == nil {
						body := `<svg xmlns="http://www.w3.org/2000/svg"/>`
						io.WriteString(b, "HTTP/1.1 200 OK\r\nContent-Length: "+fmt.Sprint(len(body))+"\r\nConnection: close\r\n\r\n"+body)
					}
				}()
				return a, nil
			}, func(net.Conn) error { return nil })
		}
		return tr
	}
	v, e := h.getIcon(context.Background(), rawJSON(map[string]any{"url": "http://icons.example.org/icon", "_system_proxy": bootstrapProxy{Host: "127.0.0.1", Port: 7890}, "_egress": bootstrapEgress{}}))
	if e != nil || v.(map[string]any)["data_uri"] == "" || calls != 1 {
		t.Fatal("real HTTP tunnel failed", calls, e)
	}
}

func TestR9UnifiedDefaultAndExplicitOffManualAndHealth(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			var calls atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "HEAD" {
					t.Error("client health must use HEAD")
				}
				calls.Add(1)
				w.WriteHeader(204)
			}))
			defer target.Close()
			h := fullHost(t)
			k := map[string]any{"security": map[string]any{"allow_loopback": true}, "groups": []any{map[string]any{"name": "auto", "type": "url-test", "members": []string{"direct"}, "lazy": false, "probe": map[string]any{"url": target.URL, "interval": "1h"}}}}
			text := fixture(t, k)
			if !enabled {
				text = settingsText(t, text, map[string]any{"unified_delay": false})
			}
			if _, e := h.Apply(text); e != nil {
				t.Fatal(e)
			}
			if _, e := h.Start(); e != nil {
				t.Fatal(e)
			}
			want := int32(1)
			if enabled {
				want = 2
			}
			deadline := time.Now().Add(2 * time.Second)
			for calls.Load() < want && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if calls.Load() != want {
				t.Fatal("health semantics", calls.Load(), want)
			}
			if _, e := h.probe(context.Background(), false, "direct", target.URL); e != nil {
				t.Fatal(e)
			}
			if calls.Load() != 2*want {
				t.Fatal("manual semantics differs from health", calls.Load(), want)
			}
		})
	}
}
