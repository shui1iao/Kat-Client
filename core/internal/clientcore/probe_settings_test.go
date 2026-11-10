package clientcore

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/kernel"
)

func settingsText(t *testing.T, text string, patch map[string]any) string {
	t.Helper()
	var root map[string]any
	if e := json.Unmarshal([]byte(text), &root); e != nil {
		t.Fatal(e)
	}
	for k, v := range patch {
		root["client"].(map[string]any)[k] = v
	}
	b, e := json.MarshalIndent(root, "", " ")
	if e != nil {
		t.Fatal(e)
	}
	return string(b) + "\n"
}
func settingsKernel(t *testing.T) map[string]any {
	t.Helper()
	// One real loopback Kat SOCKS hop for the second member; no new protocol.
	up, e := kernel.Start(kernel.Config{Inbounds: []kernel.Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0"}}, DNS: &kernel.DNSOptions{Server: "system"}, Security: &kernel.SecurityOptions{AllowLoopback: true}, Log: &kernel.LogOptions{Level: "error"}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { up.Close(context.Background()) })
	return map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}, "outbounds": []any{map[string]any{"name": "p", "type": "socks5", "server": "127.0.0.1", "port": up.Addresses()[0].(*net.TCPAddr).Port}}, "groups": []any{map[string]any{"name": "auto", "type": "smart", "members": []string{"direct", "p"}, "fixed": "direct", "lazy": true, "priority": map[string]float64{"p": 0.25}, "probe": map[string]any{"url": "http://127.0.0.1:1/background", "timeout": "1s", "interval": "1h"}}}}
}
func startSettings(t *testing.T, k map[string]any, patch map[string]any) (*Host, string) {
	t.Helper()
	// Existing budget/cancellation fixtures explicitly exercise full-delay mode.
	if patch == nil {
		patch = map[string]any{}
	}
	if _, ok := patch["unified_delay"]; !ok {
		patch["unified_delay"] = false
	}
	h := newHost(t)
	text := settingsText(t, fixture(t, k), patch)
	if _, e := applyLegacyFixture(h, text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	return h, text
}
func waitSignal(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(2 * time.Second):
		t.Fatal("real HTTP request did not arrive")
	}
}
func checkNoProbeHealth(t *testing.T, h *Host) {
	t.Helper()
	for _, g := range h.server.GroupSnapshots() {
		for _, m := range g.Members {
			if m.Probed {
				t.Fatal("incomplete/old round updated health")
			}
		}
		if g.Name == "auto" && g.Current != "direct" {
			t.Fatal("fixed moved")
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.probes) != 0 {
		t.Fatal("late/incomplete results updated node timestamps")
	}
}

func TestProbeSettingsValidationAndPreservation(t *testing.T) {
	h := newHost(t)
	text := fixture(t, map[string]any{"dns": map[string]any{"server": "system"}})
	d, e := parseDocument(text, h.workspace)
	if e != nil {
		t.Fatal(e)
	}
	if d.text != text || d.client.ProbeTimeout != kernel.Duration(5*time.Second) || d.client.ProbeRoundTimeout != kernel.Duration(10*time.Second) || d.client.ProbeConcurrency != 50 {
		t.Fatal("omitted defaults changed")
	}
	if _, e := applyLegacyFixture(h, text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	gen := h.server.GenerationID()
	for _, patch := range []map[string]any{
		{"probe_timeout": nil}, {"probe_round_timeout": nil}, {"probe_concurrency": nil},
		{"probe_timeout": "0s"}, {"probe_timeout": "99ms"}, {"probe_timeout": "60.001s"}, {"probe_timeout": 5}, {"probe_timeout": "NaN"},
		{"probe_round_timeout": "99ms"}, {"probe_round_timeout": "301s"}, {"probe_round_timeout": "4s"}, {"probe_round_timeout": true},
		{"probe_concurrency": 0}, {"probe_concurrency": 51}, {"probe_concurrency": -1}, {"probe_concurrency": 1.5}, {"probe_concurrency": "2"},
	} {
		if _, e := applyLegacyFixture(h, settingsText(t, text, patch)); e == nil {
			t.Fatal("invalid probe setting accepted")
		}
	}
	if b, _ := os.ReadFile(h.path); string(b) != text || h.server.GenerationID() != gen {
		t.Fatal("bad document changed file/runtime")
	}
	for _, patch := range []map[string]any{{"probe_timeout": "100ms", "probe_round_timeout": "100ms", "probe_concurrency": 1}, {"probe_timeout": "60s", "probe_round_timeout": "300s", "probe_concurrency": 4}} {
		next := settingsText(t, text, patch)
		if _, e := applyLegacyFixture(h, next); e != nil {
			t.Fatal(e)
		}
		if b, _ := os.ReadFile(h.path); string(b) != next {
			t.Fatal("settings normalized saved source")
		}
	}
	// Group background settings are not overwritten by global manual values.
	bg := settingsText(t, fixture(t, settingsKernel(t)), map[string]any{"probe_timeout": "200ms", "probe_round_timeout": "2s", "probe_concurrency": 1})
	if _, e := applyLegacyFixture(h, bg); e != nil {
		t.Fatal(e)
	}
	if time.Duration(h.doc.config.Groups[0].Probe.Timeout) != time.Second {
		t.Fatal("background group probe inherited manual policy")
	}
}

func TestProbeSettingsRealTimeoutAndTimestamp(t *testing.T) {
	entered := make(chan struct{}, 4)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			entered <- struct{}{}
			<-r.Context().Done()
			return
		}
		w.WriteHeader(204)
	}))
	defer target.Close()
	h, _ := startSettings(t, settingsKernel(t), map[string]any{"probe_url": target.URL + "/slow", "probe_timeout": "100ms", "probe_round_timeout": "600ms", "probe_concurrency": 1})
	nodes := h.Status().(map[string]any)["nodes"].([]any)
	if nodes[0].(map[string]any)["probe_at"] != nil {
		t.Fatal("unmeasured node has timestamp")
	}
	before := time.Now()
	r, e := h.probe(context.Background(), false, "p", "")
	elapsed := time.Since(before)
	p := r.(kernel.ProbeResult)
	if e != nil || p.ProbeMS != nil || p.Error == "" || elapsed < 80*time.Millisecond || elapsed > time.Second || p.At.Before(before) {
		t.Fatal("real node timeout/timestamp not honored")
	}
	waitSignal(t, entered)
	node := h.Status().(map[string]any)["nodes"].([]any)[0].(map[string]any)
	if !node["probe_at"].(time.Time).Equal(p.At) || node["probe_ms"].(*float64) != nil {
		t.Fatal("status did not use exact actual failed probe time")
	}
	// Explicit URL overrides the slow default, without writing the source.
	r, e = h.probe(context.Background(), false, "p", target.URL+"/ok")
	p = r.(kernel.ProbeResult)
	if e != nil || p.ProbeMS == nil || p.Error != "" {
		t.Fatal("explicit IPC URL not used")
	}
	for _, g := range h.server.GroupSnapshots() {
		for _, m := range g.Members {
			if m.Probed {
				t.Fatal("single-node probe propagated to groups")
			}
		}
	}

	// Individual HTTP timeouts are genuine failed samples in a complete round,
	// not a reason to fabricate success or discard the whole healthy-state round.
	if _, e := h.probe(context.Background(), true, "auto", target.URL+"/slow"); e != nil {
		t.Fatal(e)
	}
	snap := h.server.GroupSnapshots()[0]
	if snap.Fixed != "direct" {
		t.Fatal("fixed preference lost")
	}
	for _, m := range snap.Members {
		if m.Probed {
			t.Fatal("different URL must remain diagnostic, not overwrite comparable prior")
		}
	}

}

func TestProbeSettingsSharedPermitsAndQueueBudget(t *testing.T) {
	var active, peak atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		select {
		case <-time.After(70 * time.Millisecond):
			w.WriteHeader(204)
		case <-r.Context().Done():
		}
	}))
	defer target.Close()
	k := settingsKernel(t)
	k["groups"].([]any)[0].(map[string]any)["probe"].(map[string]any)["url"] = target.URL
	h, _ := startSettings(t, k, map[string]any{"probe_timeout": "150ms", "probe_round_timeout": "800ms", "probe_concurrency": 1})
	type answer struct {
		r any
		e *Error
	}
	done := make(chan answer, 3)
	for _, item := range []struct {
		g    bool
		name string
	}{{false, "direct"}, {true, "auto"}, {false, "p"}} {
		go func(g bool, name string) {
			r, e := h.probe(context.Background(), g, name, target.URL)
			done <- answer{r, e}
		}(item.g, item.name)
	}
	for range 3 {
		select {
		case a := <-done:
			if a.e != nil {
				t.Fatal(a.e)
			}
			switch r := a.r.(type) {
			case kernel.ProbeResult:
				if r.ProbeMS == nil {
					t.Fatal("queue consumed per-node timeout")
				}
			case map[string]any:
				for _, p := range r["members"].([]kernel.ProbeResult) {
					if p.ProbeMS == nil {
						t.Fatal("group queue consumed per-node timeout")
					}
				}
			}
		case <-time.After(2 * time.Second):
			t.Fatal("shared permit leaked")
		}
	}
	if peak.Load() != 1 {
		t.Fatal("node+group did not share concurrency=1")
	}
	snap := h.server.GroupSnapshots()[0]
	if snap.Current != "direct" || snap.Fixed != "direct" {
		t.Fatal("fixed migrated after complete round")
	}
	for _, m := range snap.Members {
		if !m.ProbeOK || m.ProbeAt.IsZero() {
			t.Fatal("complete round not committed")
		}
	}
}

func TestProbeSettingsRoundCancellationAndApply(t *testing.T) {
	for _, action := range []string{"round", "cancel", "stop", "settings", "reload"} {
		t.Run(action, func(t *testing.T) {
			entered := make(chan struct{}, 4)
			var calls atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					w.WriteHeader(204)
					return
				}
				entered <- struct{}{}
				<-r.Context().Done()
			}))
			defer target.Close()
			h, text := startSettings(t, settingsKernel(t), map[string]any{"probe_timeout": "250ms", "probe_round_timeout": "250ms", "probe_concurrency": 1})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() { defer close(done); h.probe(ctx, true, "auto", target.URL) }()
			waitSignal(t, entered)
			start := time.Now()
			_ = h.Status()
			if time.Since(start) > time.Second {
				t.Fatal("status blocked behind probe")
			}
			switch action {
			case "cancel":
				cancel()
			case "stop":
				if _, e := h.Stop(); e != nil {
					t.Fatal(e)
				}
			case "settings":
				if _, e := applyLegacyFixture(h, settingsText(t, text, map[string]any{"probe_timeout": "100ms", "probe_round_timeout": "600ms", "probe_concurrency": 2})); e != nil {
					t.Fatal(e)
				}
			case "reload":
				if _, e := h.Reload(); e != nil {
					t.Fatal(e)
				}
			}
			waitSignal(t, done)
			if action == "stop" {
				if time.Since(start) > time.Second {
					t.Fatal("stop blocked behind probe")
				}
				h.mu.Lock()
				if len(h.probes) > 0 {
					t.Error("stop accepted late probe")
				}
				h.mu.Unlock()
			} else if action == "round" {
				// R7: each member got its own budget. The genuine completed timeout is
				// a failed sample, not a canceled shared whole-group deadline.
				h.mu.Lock()
				if len(h.probes) == 0 {
					t.Error("completed independent round lost results")
				}
				h.mu.Unlock()
			} else {
				checkNoProbeHealth(t, h)
			}
			// New requests still acquire all permits after cancellation/reconfiguration.
			quick := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
			defer quick.Close()
			if action == "stop" {
				if _, e := h.Start(); e != nil {
					t.Fatal(e)
				}
			}
			r, e := h.probe(context.Background(), false, "p", quick.URL)
			if e != nil || r.(kernel.ProbeResult).ProbeMS == nil {
				t.Fatal("cancel/round/settings leaked permit")
			}
		})
	}
}

func TestProbeSettingsInstancesDoNotShareLimit(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	defer close(release)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hold" {
			entered <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(204)
	}))
	defer target.Close()
	k := map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}}
	h, _ := startSettings(t, k, map[string]any{"probe_timeout": "2s", "probe_round_timeout": "2s", "probe_concurrency": 1})
	other, _ := startSettings(t, k, map[string]any{"probe_timeout": "100ms", "probe_round_timeout": "300ms", "probe_concurrency": 1})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { h.probe(ctx, false, "direct", target.URL+"/hold"); close(done) }()
	waitSignal(t, entered)
	r, e := other.probe(context.Background(), false, "direct", target.URL+"/ok")
	if e != nil || r.(kernel.ProbeResult).ProbeMS == nil {
		t.Fatal("another client consumed this client's permit")
	}
	cancel()
	waitSignal(t, done)
}

func TestProviderRefreshConfiguredBudgetAndRealRequest(t *testing.T) {
	body := "socks5://127.0.0.1:1#fixture-provider-node\n"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer target.Close()
	for _, budget := range []time.Duration{0, time.Second, 90 * time.Second, 300 * time.Second} {
		t.Run(budget.String(), func(t *testing.T) {
			h := newHost(t)
			provider := map[string]any{"name": "sub", "type": "http", "url": target.URL, "interval": "1h"}
			if budget != 0 {
				provider["timeout"] = budget.String()
			}
			text := fixture(t, map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}, "providers": []any{provider}})
			if e := os.WriteFile(filepath.Join(h.workspace, "providers", "sub.cache"), []byte(body), 0600); e != nil {
				t.Fatal(e)
			}
			if _, e := applyLegacyFixture(h, text); e != nil {
				t.Fatal(e)
			}
			if _, e := h.Start(); e != nil {
				t.Fatal(e)
			}
			want := budget
			if want == 0 {
				want = 30 * time.Second
			}
			ctx, cancel, e := providerRefreshContext(context.Background(), h.server, "sub")
			if e != nil {
				t.Fatal(e)
			}
			deadline, ok := ctx.Deadline()
			cancel()
			if !ok || time.Until(deadline) < want || time.Until(deadline) > want+time.Second {
				t.Fatal("host wrapper truncates configured timeout")
			}
			// Exercise the actual Host.refresh wrapper with a real short request.
			// Kernel's fetchRequest seam separately observes the actual HTTP request
			// context (TCP dial deadlines are intentionally a different core limit).
			if _, e := h.server.RefreshProvider(context.Background(), "sub"); e != nil {
				t.Fatal(e)
			}

			if b, _ := os.ReadFile(h.path); string(b) != text {
				t.Fatal("refresh changed source")
			}
			if _, _, e := providerRefreshContext(context.Background(), h.server, "missing"); e == nil {
				t.Fatal("unknown provider accepted")
			}
		})
	}
}

func TestProviderRefreshQueuedCancellationAndStop(t *testing.T) {
	entered := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
	defer target.Close()
	h, _ := startSettings(t, map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}, "providers": []any{map[string]any{"name": "slow", "type": "http", "url": target.URL, "timeout": "90s", "interval": "1h"}}}, nil)
	// The real background fetch owns updateSlot while manual refresh queues.
	waitSignal(t, entered)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	before := time.Now()
	if _, e := h.server.RefreshProvider(ctx, "slow"); e == nil {
		t.Fatal("canceled queued refresh succeeded")
	}
	if time.Since(before) > time.Second {
		t.Fatal("queued refresh ignored cancellation")
	}
	done := make(chan struct{})
	go func() {
		h.mu.Lock()
		server := h.server
		h.mu.Unlock()
		if server != nil {
			server.RefreshProvider(context.Background(), "slow")
		}
		close(done)
	}()
	before = time.Now()
	if _, e := h.Stop(); e != nil {
		t.Fatal(e)
	}
	waitSignal(t, done)
	if time.Since(before) > time.Second {
		t.Fatal("Stop waited for 90s background update")
	}
}
