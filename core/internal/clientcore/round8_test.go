package clientcore

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

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
