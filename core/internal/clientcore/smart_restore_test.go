package clientcore

import (
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/kernel"
	"golang.org/x/net/proxy"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"net/http"
	"net/http/httptest"

	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func restoreSmartProbeHost(t *testing.T, url string) *Host {
	t.Helper()
	k := settingsKernel(t)
	p := k["outbounds"].([]any)[0].(map[string]any)
	q := map[string]any{}
	for key, v := range p {
		q[key] = v
	}
	q["name"] = "q"
	k["outbounds"] = []any{p, q}
	k["groups"] = []any{map[string]any{"name": "G1", "type": "smart", "lazy": true, "smart": map[string]any{"scope": "site"}, "probe": map[string]any{"url": url}, "members": []string{"p", "q"}}, map[string]any{"name": "G2", "type": "smart", "lazy": true, "smart": map[string]any{"scope": "site"}, "probe": map[string]any{"url": url}, "members": []string{"p"}}, map[string]any{"name": "G3", "type": "smart", "lazy": true, "smart": map[string]any{"scope": "site"}, "probe": map[string]any{"url": url}, "members": []string{"q"}}}
	h := newHost(t)
	text := settingsText(t, fixture(t, k), map[string]any{"probe_url": url, "probe_timeout": "2s", "probe_round_timeout": "3s", "probe_concurrency": 4, "unified_delay": false, "close_on_switch": false})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	return h
}
func restoreSmartBlockedHTTP(t *testing.T) (string, *atomic.Int32, func(), <-chan struct{}) {
	t.Helper()
	var n atomic.Int32
	release := make(chan struct{})
	entered := make(chan struct{}, 32)
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.WriteHeader(204)
	}))
	done := func() { once.Do(func() { close(release) }) }
	t.Cleanup(srv.Close)
	t.Cleanup(done)
	return srv.URL, &n, done, entered
}
func restoreSmartStartGroup(t *testing.T, h *Host, name, url string) *probeRound {
	t.Helper()
	if _, e := h.startProbeBatch(context.Background(), name, url); e != nil {
		t.Fatal(e)
	}
	h.mu.Lock()
	r := h.groupRounds[name]
	h.mu.Unlock()
	if r == nil {
		t.Fatal("round not retained")
	}
	return r
}
func restoreSmartWaitRound(t *testing.T, r *probeRound) {
	t.Helper()
	select {
	case <-r.finished:
	case <-time.After(4 * time.Second):
		t.Fatal("round did not finish")
	}
}
func restoreSmartCancelGroup(t *testing.T, h *Host, name, id string) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"name": name, "cancel_id": id})
	if _, e := h.probeGroupBatch(context.Background(), raw); e != nil {
		t.Fatal(e)
	}
}
func TestSmartRestoreGroupAdmissionIsolationAndMerge(t *testing.T) {
	url, n, release, entered := restoreSmartBlockedHTTP(t)
	h := restoreSmartProbeHost(t, url)
	// G2 and G3 have separate real SOCKS leaves, G1 also shares both.
	r2 := restoreSmartStartGroup(t, h, "G2", "")
	waitSignal(t, entered)
	if _, e := h.startProbeBatch(context.Background(), "G2", ""); e == nil || e.Code != "probe_busy" {
		t.Fatal("duplicate group admitted", e)
	}
	r1 := restoreSmartStartGroup(t, h, "G1", "")
	waitSignal(t, entered)
	time.Sleep(50 * time.Millisecond)
	if n.Load() != 2 {
		t.Fatalf("same leaf not narrowly merged: requests=%d want=2", n.Load())
	}
	r3 := restoreSmartStartGroup(t, h, "G3", "")
	time.Sleep(50 * time.Millisecond)
	if n.Load() != 2 {
		t.Fatal("q not shared in flight", n.Load())
	}
	if _, e := h.probeAll(context.Background(), nil); e == nil || e.Code != "probe_busy" {
		t.Fatal("all overlapped groups", e)
	}
	restoreSmartCancelGroup(t, h, "G1", r1.id)
	restoreSmartWaitRound(t, r1)
	select {
	case <-r2.finished:
		t.Fatal("cancel G1 canceled G2")
	default:
	}
	select {
	case <-r3.finished:
		t.Fatal("cancel G1 canceled G3")
	default:
	}
	release()
	restoreSmartWaitRound(t, r2)
	restoreSmartWaitRound(t, r3)
	h.mu.Lock()
	for _, name := range []string{"p", "q"} {
		if h.probes[name].ProbeMS == nil {
			t.Error("healthy independent group lost result", name)
		}
	}
	h.mu.Unlock()
	r := restoreSmartStartGroup(t, h, "G2", "")
	restoreSmartWaitRound(t, r)
	if n.Load() != 3 {
		t.Fatal("completed measurement incorrectly cached", n.Load())
	}
	raw, _ := json.Marshal(map[string]any{"name": "G2", "cancel_id": r2.id})
	if _, e := h.probeGroupBatch(context.Background(), raw); e == nil || e.Code != "probe_round_expired" {
		t.Fatal("stale cancel id accepted", e)
	}
	t.Log("three groups admitted independently; two shared leaves => two sockets; duplicate same group/all excluded; cancel G1 leaves G2/G3 alive; next round fresh; expired cancel id rejected")
}
func TestSmartRestoreGroupDifferentURLNotMerged(t *testing.T) {
	url, n, release, entered := restoreSmartBlockedHTTP(t)
	h := restoreSmartProbeHost(t, url)
	a := restoreSmartStartGroup(t, h, "G2", url+"/a")
	waitSignal(t, entered)
	b := restoreSmartStartGroup(t, h, "G1", url+"/b")
	waitSignal(t, entered)
	waitSignal(t, entered)
	if n.Load() != 3 {
		t.Fatal("different URL merged", n.Load())
	}
	release()
	restoreSmartWaitRound(t, a)
	restoreSmartWaitRound(t, b)
	t.Log("same p with different URLs not merged; q separate => 3 requests")
}
func TestSmartRestoreGroupEpochCancellation(t *testing.T) {
	for _, action := range []string{"cancel", "stop", "apply", "reload", "close"} {
		t.Run(action, func(t *testing.T) {
			url, _, _, entered := restoreSmartBlockedHTTP(t)
			h := restoreSmartProbeHost(t, url)
			r := restoreSmartStartGroup(t, h, "G2", "")
			waitSignal(t, entered)
			epoch := h.manualCtx
			switch action {
			case "cancel":
				restoreSmartCancelGroup(t, h, "G2", r.id)
			case "stop":
				if _, e := h.Stop(); e != nil {
					t.Fatal(e)
				}
			case "apply":
				if _, e := h.Apply(settingsText(t, h.doc.text, map[string]any{"probe_concurrency": 2})); e != nil {
					t.Fatal(e)
				}
			case "reload":
				if _, e := h.Reload(); e != nil {
					t.Fatal(e)
				}
			case "close":
				if e := h.Close(); e != nil {
					t.Fatal(e)
				}
			}
			restoreSmartWaitRound(t, r)
			h.mu.Lock()
			defer h.mu.Unlock()
			if len(h.probes) != 0 {
				t.Fatal("canceled old epoch published node sample", h.probes)
			}
			if action != "cancel" && epoch.Err() == nil {
				t.Fatal("epoch not canceled")
			}
			if action != "cancel" && len(h.groupProbeOutcomes) != 0 {
				t.Fatal("old outcome overwrote new epoch")
			}
			t.Log("canceled/drained, no node timestamp or obsolete outcome published")
		})
	}
}

func TestSmartRestoreRealStatusHotPinAndRAMOnly(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer target.Close()
	h := restoreSmartProbeHost(t, target.URL)
	root, _ := sourceJSON(h.doc)
	k := rawObject(root["kernel"])
	gs := rawArray(k, "groups")
	g := rawObject(gs[0])
	g["priority"] = rawJSON(map[string]float64{"p": .5, "gone": .25})
	g["include_all_proxies"] = rawJSON(true)
	gs[0] = rawJSON(g)
	k["groups"] = rawJSON(gs)
	root["kernel"] = rawJSON(k)
	text := settingsText(t, string(rawJSON(root)), map[string]any{"mode": "global", "global_group": "G1"})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	r, probeErr := h.probe(context.Background(), false, "p", "")
	if probeErr != nil {
		t.Fatal(probeErr)
	}
	measured := r.(kernel.ProbeResult)
	if measured.ProbeMS == nil || measured.At.IsZero() || measured.ErrorCode != "" {
		t.Fatalf("manual probe did not produce a real successful sample: %+v", measured)
	}
	d, e := proxy.SOCKS5("tcp", portAddress(h.doc.client.SOCKSPort), nil, proxy.Direct)
	if e != nil {
		t.Fatal(e)
	}
	addr := strings.TrimPrefix(target.URL, "http://")
	conn, e := d.Dial("tcp", addr)
	if e != nil {
		t.Fatal(e)
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, e = conn.Write([]byte("GET / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")); e != nil {
		t.Fatal(e)
	}
	if b, e := io.ReadAll(conn); e != nil || len(b) == 0 {
		t.Fatal("real exchange", e)
	}
	conn.Close()
	// Status legitimately adopts newer background measurements after real use.
	// Compare identities within one Status projection, not against an obsolete
	// manual value; still require a genuine successful probe, never a score.
	var projectedP map[string]any
	statusGroup := func() map[string]any {
		b, _ := json.Marshal(h.Status())
		var v map[string]any
		json.Unmarshal(b, &v)
		projectedP = nil
		for _, n := range v["nodes"].([]any) {
			if node := n.(map[string]any); node["name"] == "p" {
				projectedP = node
			}
		}
		for _, g := range v["groups"].([]any) {
			m := g.(map[string]any)
			if m["name"] == "G1" {
				return m
			}
		}
		t.Fatal("no real status G1")
		return nil
	}
	status := statusGroup()
	if status["type"] != "smart" || status["algorithm_version"] != float64(2) || status["selection_mode"] != "site" || status["most_used_member"] != "p" || status["default_member"] != "p" {
		t.Fatal("Smart status not wired", status)
	}
	found := false
	for _, m := range status["members"].([]any) {
		v := m.(map[string]any)
		if v["name"] == "p" {
			found = true
			if v["sample_count"] != float64(1) || v["score_parts"].(map[string]any)["real_ms"] == nil || v["weight"] != .5 {
				t.Fatal("real quality/weight lost", v)
			}
			if projectedP == nil || v["probe_error"] != "" || v["probe_ms"] == nil || v["probe_at"] != projectedP["probe_at"] || v["probe_ms"] != projectedP["probe_ms"] || v["probe_error"] != projectedP["probe_error"] {
				t.Fatal("quality/probe identity separation lost", v, projectedP)
			}
			at, err := time.Parse(time.RFC3339Nano, v["probe_at"].(string))
			if err != nil || at.Before(measured.At) {
				t.Fatal("Status substituted an old/non-probe timestamp", v, measured)
			}
			if at.Equal(measured.At) && v["probe_ms"] != *measured.ProbeMS {
				t.Fatal("same probe identity changed its measured delay", v, measured)
			}
		}
	}
	if !found {
		t.Fatal("no p")
	}
	gen, epoch := h.server.GenerationID(), h.manualCtx
	root, _ = sourceJSON(h.doc)
	k = rawObject(root["kernel"])
	gs = rawArray(k, "groups")
	g = rawObject(gs[0])
	g["fixed"] = rawJSON("q")
	gs[0] = rawJSON(g)
	k["groups"] = rawJSON(gs)
	root["kernel"] = rawJSON(k)
	result, de := h.Apply(string(rawJSON(root)))
	if de != nil || result.(map[string]any)["selection_only"] != true || h.server.GenerationID() != gen || h.manualCtx != epoch {
		t.Fatal("Smart fixed was not hot", de)
	}
	if !reflect.DeepEqual(h.probes["p"], measured) {
		t.Fatal("hot pin cleared measured delay")
	}
	after := statusGroup()
	if after["fixed"] != "q" || after["most_used_member"] != "p" {
		t.Fatal("fixed/usage status mixed", after)
	}
	workspace := h.workspace
	accepted := h.doc.text
	if e := h.Close(); e != nil {
		t.Fatal(e)
	}
	h2, e := Open(workspace)
	if e != nil {
		t.Fatal(e)
	}
	defer h2.Close()
	if h2.doc.text != accepted || h2.doc.config.Groups[0].Type != "smart" || h2.doc.config.Groups[0].Fixed != "q" || h2.doc.config.Groups[0].Priority["gone"] != .25 {
		t.Fatal("reopen changed accepted Smart preferences")
	}
	if _, e := h2.Start(); e != nil {
		t.Fatal(e)
	}
	for _, s := range h2.server.GroupSnapshots() {
		if s.Name == "G1" {
			for _, m := range s.Members {
				if m.SampleCount != 0 || m.ScoreParts.RealMS != nil {
					t.Fatal("RAM learning persisted across restart")
				}
			}
		}
	}
	t.Log("real Host status quality/default/most-used; hot fixed keeps probes/epoch/generation; reopened preferences retained, RAM quality not persisted")
}
func TestSmartRestoreURLTestNeverGuessedFromBackup(t *testing.T) {
	h := newHost(t)
	text := fixture(t, map[string]any{"groups": []any{map[string]any{"name": "kept", "type": "url-test", "members": []string{"direct"}, "fixed": "direct", "priority": map[string]float64{"direct": .5}, "probe": map[string]any{"url": "http://127.0.0.1:9/", "interval": "7m"}}}})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	dir, accepted := h.workspace, h.doc.text
	if e := h.Close(); e != nil {
		t.Fatal(e)
	}
	backup := []byte(`{"type":"smart","private":"must-never-be-restored"}`)
	p := filepath.Join(dir, "client-before-no-smart.json")
	if e := os.WriteFile(p, backup, 0600); e != nil {
		t.Fatal(e)
	}
	h2, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer h2.Close()
	if h2.doc.text != accepted || h2.doc.config.Groups[0].Type != "url-test" {
		t.Fatal("URLTest guessed back to Smart")
	}
	b, _ := os.ReadFile(p)
	if string(b) != string(backup) {
		t.Fatal("old backup changed")
	}
}
