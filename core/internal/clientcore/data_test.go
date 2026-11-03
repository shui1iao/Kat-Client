package clientcore

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/outbound"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestImportParseDoesNotFetchAndSkipsUnknown(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); fmt.Fprint(w, "not fetched") }))
	defer s.Close()
	h := newHost(t)
	b, _ := json.Marshal(map[string]any{"text": s.URL})
	_, _ = h.Request(context.Background(), "import.parse", b)
	if calls.Load() != 0 {
		t.Fatal("import fetched URL")
	}
	b, _ = json.Marshal(map[string]any{"text": "socks5://test-user:test-secret@127.0.0.1:1234#local\nunsupported://x#skip"})
	r, e := h.Request(context.Background(), "import.parse", b)
	if e != nil {
		t.Fatal(e)
	}
	out := r.(map[string]any)
	if len(out["outbounds"].([]outbound.Options)) != 1 || len(out["skipped"].([]any)) != 1 {
		t.Fatal("supported import/unknown skip")
	}
}
func TestRealProviderRefreshPreservesRawAndLastGood(t *testing.T) {
	up, e := kernel.Start(kernel.Config{Inbounds: []kernel.Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0"}}, DNS: &kernel.DNSOptions{Server: "system"}, Security: &kernel.SecurityOptions{AllowLoopback: true}})
	if e != nil {
		t.Fatal(e)
	}
	defer up.Close(context.Background())
	port := up.Addresses()[0].(*net.TCPAddr).Port
	var mu sync.Mutex
	body := fmt.Sprintf("socks5://127.0.0.1:%d#first", port)
	status := 200
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	defer provider.Close()
	h := newHost(t)
	text := fixture(t, map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}, "providers": []any{map[string]any{"name": "local", "type": "http", "url": provider.URL, "interval": "1h"}}, "groups": []any{map[string]any{"name": "pick", "type": "select", "use": []string{"local"}}}, "routing": map[string]any{"final": "pick"}})
	if _, e := applyLegacyFixture(h, text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	if _, e := h.server.RefreshProvider(context.Background(), "local"); e != nil {
		t.Fatal(e)
	}
	mu.Lock()
	body = fmt.Sprintf("socks5://127.0.0.1:%d#second", port)
	mu.Unlock()
	if _, e := h.server.RefreshProvider(context.Background(), "local"); e != nil {
		t.Fatal(e)
	}
	cfg := h.server.CurrentConfig()
	found := false
	for _, o := range cfg.Outbounds {
		if o.Name == "second" {
			found = true
		}
	}
	if !found {
		t.Fatal("provider nodes not installed")
	}
	mu.Lock()
	status = 503
	mu.Unlock()
	if _, e := h.server.RefreshProvider(context.Background(), "local"); e == nil {
		t.Fatal("provider failure hidden")
	}
	found = false
	for _, o := range h.server.CurrentConfig().Outbounds {
		if o.Name == "second" {
			found = true
		}
	}
	if !found {
		t.Fatal("failed refresh lost old nodes")
	}
	b, _ := os.ReadFile(h.path)
	if string(b) != text || h.doc.text != text {
		t.Fatal("provider expansion rewrote raw")
	}
	cache, e := os.ReadFile(filepath.Join(h.workspace, "providers", "local.cache"))
	if e != nil || !strings.Contains(string(cache), "second") {
		t.Fatal("failed refresh replaced cache")
	}
}
func TestTrafficHistoryRestartResetAndBoundedDays(t *testing.T) {
	var h history
	h.Daily = []daily{}
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.Local)
	h.add(now, 100, 200)
	h.add(now, 100, 200)
	if h.TotalUp != 100 || h.TotalDown != 200 || len(h.Daily) != 1 {
		t.Fatal("duplicate sample counted")
	}
	h.add(now, 5, 10)
	if h.TotalUp != 105 || h.TotalDown != 210 {
		t.Fatal("reset delta")
	}
	h.resetBaseline()
	h.add(now, 7, 8)
	if h.TotalUp != 112 || h.TotalDown != 218 {
		t.Fatal("restart delta")
	}
	for i := 1; i < 40; i++ {
		h.add(now.AddDate(0, 0, i), uint64(i+7), uint64(i+8))
	}
	if len(h.Daily) > 31 {
		t.Fatal("unbounded history")
	}
	dir := t.TempDir()
	host, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	host.mu.Lock()
	host.history.add(time.Now(), 20, 30)
	if e = host.saveHistory(); e != nil {
		t.Fatal(e)
	}
	host.mu.Unlock()
	host.Close()
	host, e = Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer host.Close()
	if host.history.TotalUp != 20 || host.history.TotalDown != 30 {
		t.Fatal("history did not survive process restart")
	}
	if host.history.lastUp != 0 {
		t.Fatal("old sample baseline reused")
	}
}
func TestSlowProbeDoesNotBlockStatusStop(t *testing.T) {
	started := make(chan struct{}, 4)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { started <- struct{}{}; <-r.Context().Done() }))
	defer target.Close()
	h := newHost(t)
	text := fixture(t, map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}})
	if _, e := applyLegacyFixture(h, text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = h.probe(context.Background(), false, "direct", target.URL) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("probe not running")
	}
	begin := time.Now()
	_ = h.Status()
	if time.Since(begin) > 200*time.Millisecond {
		t.Fatal("status blocked")
	}
	if _, e := h.Stop(); e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stop leaked probe")
	}
}
