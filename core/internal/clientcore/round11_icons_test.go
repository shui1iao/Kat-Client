package clientcore

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
