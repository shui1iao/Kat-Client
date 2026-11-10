package clientcore

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"github.com/shui1iao/Kat/internal/kernel"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func fixture(t *testing.T, k any) string {
	t.Helper()
	hp, sp := freePort(t), freePort(t)
	for sp == hp {
		sp = freePort(t)
	}
	b, e := json.Marshal(map[string]any{"schema_version": 1, "client": Client{Mode: "rule", ProbeURL: "http://127.0.0.1:1/probe", HTTPPort: hp, SOCKSPort: sp}, "kernel": k})
	if e != nil {
		t.Fatal(e)
	}
	return string(b) + "\n"
}
func newHost(t *testing.T) *Host {
	t.Helper()
	h, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}
func TestDocumentPreservationAndFailedApply(t *testing.T) {
	h := newHost(t)
	text := fixture(t, map[string]any{"security": map[string]any{"allow_loopback": true}, "dns": map[string]any{"cache_entries": 0}, "limits": map[string]any{"connections": 33}, "routing": map[string]any{"rules": []any{map[string]any{"domain": "unreachable.invalid", "action": "reject"}}, "final": "direct"}})
	text = " \n" + text
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	before := h.server.GenerationID()
	for _, bad := range []string{`{`, strings.Replace(text, `"connections":33`, `"unrecognized":33`, 1), strings.Replace(text, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)} {
		if _, e := h.Apply(bad); e == nil {
			t.Fatal("bad document accepted")
		}
	}
	l, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	var raw map[string]any
	json.Unmarshal([]byte(text), &raw)
	raw["client"].(map[string]any)["socks_port"] = l.Addr().(*net.TCPAddr).Port
	b, _ := json.Marshal(raw)
	if _, e := h.Apply(string(b)); e == nil {
		t.Fatal("busy listener accepted")
	}
	saved, e := os.ReadFile(h.path)
	if e != nil || string(saved) != text || h.doc.text != text {
		t.Fatal("raw changed on failed apply")
	}
	if h.server.GenerationID() != before {
		t.Fatal("failed apply changed generation")
	}
	if st, e := os.Stat(h.path); e != nil || st.Mode().Perm()&0077 != 0 {
		t.Fatal("private file mode")
	}
	// Valid direct/global projections never rewrite original routing or order.
	raw["client"].(map[string]any)["socks_port"] = h.doc.client.SOCKSPort
	raw["client"].(map[string]any)["mode"] = "direct"
	b, _ = json.Marshal(raw)
	if _, e := h.Apply(string(b)); e != nil {
		t.Fatal(e)
	}
	if len(h.server.CurrentConfig().Routing.Rules) != 0 || !strings.Contains(h.doc.text, "unreachable.invalid") {
		t.Fatal("mode projection corrupted raw")
	}
	if _, e := h.Reload(); e != nil {
		t.Fatal(e)
	}
}
func TestRealHTTPAndCONNECTViaSameKatSOCKS(t *testing.T) {
	up, e := kernel.Start(kernel.Config{Inbounds: []kernel.Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0"}}, Security: &kernel.SecurityOptions{AllowLoopback: true}})
	if e != nil {
		t.Fatal(e)
	}
	defer up.Close(context.Background())
	port := up.Addresses()[0].(*net.TCPAddr).Port
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "real-kat-traffic") }))
	defer target.Close()
	h := newHost(t)
	text := fixture(t, map[string]any{"security": map[string]any{"allow_loopback": true}, "outbounds": []any{map[string]any{"name": "local-node", "type": "socks5", "server": "127.0.0.1", "port": port}}, "groups": []any{map[string]any{"name": "pick", "type": "select", "members": []string{"local-node"}}}, "routing": map[string]any{"final": "pick"}})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	proxyURL, _ := url.Parse("http://" + portAddress(h.doc.client.HTTPPort))
	tr := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	r, e := client.Get(target.URL)
	if e != nil {
		t.Fatal(e)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if string(b) != "real-kat-traffic" {
		t.Fatal("ordinary HTTP bridge")
	}
	c, e := net.Dial("tcp4", portAddress(h.doc.client.HTTPPort))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(4 * time.Second))
	dst := strings.TrimPrefix(target.URL, "http://")
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dst, dst)
	br := bufio.NewReader(c)
	r, e = http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if e != nil || r.StatusCode != 200 {
		t.Fatal("CONNECT response")
	}
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", dst)
	r, e = http.ReadResponse(br, nil)
	if e != nil {
		t.Fatal(e)
	}
	b, _ = io.ReadAll(r.Body)
	r.Body.Close()
	if string(b) != "real-kat-traffic" {
		t.Fatal("CONNECT bridge data")
	}
	if up.Stats().Accepted < 2 {
		t.Fatal("bypassed configured Kat outbound")
	}
	c.Close()
	tr.CloseIdleConnections()
	time.Sleep(20 * time.Millisecond)
	h.mu.Lock()
	h.sampleLocked(time.Now())
	total := h.history.TotalUp + h.history.TotalDown
	h.mu.Unlock()
	if total == 0 {
		t.Fatal("no actual traffic counted")
	}
	st := h.Status().(map[string]any)
	gs := st["traffic"].(map[string]any)["groups"].([]any)
	found := false
	for _, g := range gs {
		v := g.(map[string]any)
		if v["name"] == "pick" {
			if v["up"].(uint64)+v["down"].(uint64) == 0 {
				t.Fatal("group cumulative missing actual traffic")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("group cumulative not exposed")
	}

}
func TestWorkspaceIsolationAndNoFakeDefaults(t *testing.T) {
	dir := t.TempDir()
	h, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	if _, e = Open(dir); e == nil {
		t.Fatal("duplicate workspace owner")
	}
	s := h.Status().(map[string]any)
	if len(s["nodes"].([]any)) != 0 || len(s["groups"].([]any)) != 0 || len(h.history.Daily) != 0 {
		t.Fatal("fake initial state")
	}
	if _, e := os.Stat(filepath.Join(dir, "traffic-history.json")); !os.IsNotExist(e) {
		t.Fatal("fabricated history file")
	}
}

func TestDocumentReloadChangedHTTPPortKeepsExistingCONNECT(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "old-flow-still-alive") }))
	defer target.Close()
	h := newHost(t)
	text := fixture(t, map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	c, e := net.Dial("tcp4", portAddress(h.doc.client.HTTPPort))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	dst := strings.TrimPrefix(target.URL, "http://")
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dst, dst)
	br := bufio.NewReader(c)
	r, e := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if e != nil || r.StatusCode != 200 {
		t.Fatal("CONNECT")
	}
	var raw map[string]any
	json.Unmarshal([]byte(text), &raw)
	raw["client"].(map[string]any)["http_port"] = freePort(t)
	b, _ := json.Marshal(raw)
	if _, e := h.Apply(string(b)); e != nil {
		t.Fatal(e)
	}
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", dst)
	r, e = http.ReadResponse(br, nil)
	if e != nil {
		t.Fatal("reload cut established flow")
	}
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if string(body) != "old-flow-still-alive" {
		t.Fatal("reload changed existing flow")
	}
}
