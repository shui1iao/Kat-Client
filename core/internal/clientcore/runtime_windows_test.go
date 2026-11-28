//go:build windows

package clientcore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Before BERO-006: the own-PID SOCKS connection has no original tuple entry,
// procattr.Lookup returns unknown and the process rule fails closed. This
// exercises the real Windows owner table/handle proof, never a claimed name.
func TestR8WindowsIconWithActualProcessRule(t *testing.T) {
	exe, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	name := strings.ToLower(filepath.Base(exe))
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg" width="2" height="2"/>`))
	}))
	defer target.Close()
	h := fullHost(t)
	doc := fixture(t, map[string]any{"security": map[string]any{"allow_loopback": true}, "dns": map[string]any{"server": "system"}, "routing": map[string]any{"rules": []any{map[string]any{"process_name": name, "action": "direct"}}, "final": "reject"}})
	if _, e := h.Apply(doc); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	v, er := h.getIcon(context.Background(), rawJSON(map[string]any{"url": target.URL + "/actual-owner.svg"}))
	if er != nil || !strings.HasPrefix(v.(map[string]any)["data_uri"].(string), "data:image/svg+xml;base64,") {
		t.Fatal("BERO-006: actual own process rule not honored")
	}
}
