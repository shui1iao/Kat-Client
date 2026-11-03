package clientcore

import (
	"context"
	"fmt"
	"github.com/shui1iao/Kat/internal/kernel"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func beginAllProbeTest(t *testing.T, h *Host, ctx context.Context) *probeRound {
	t.Helper()
	v, e := h.probeAll(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	if v.(map[string]any)["started"] != true {
		t.Fatal(v)
	}
	h.mu.Lock()
	r := h.allRound
	h.mu.Unlock()
	if r == nil {
		t.Fatal("batch finished before test capture")
	}
	return r
}
func waitAllProbeTest(t *testing.T, r *probeRound) {
	t.Helper()
	select {
	case <-r.finished:
	case <-time.After(45 * time.Second):
		t.Fatal("batch did not finish")
	}
}
func batchKernel(t *testing.T, n int) map[string]any {
	t.Helper()
	k := settingsKernel(t)
	base := k["outbounds"].([]any)[0].(map[string]any)
	outs := []any{}
	for i := range n {
		node := map[string]any{}
		for k, v := range base {
			node[k] = v
		}
		node["name"] = fmt.Sprintf("n%02d", i)
		outs = append(outs, node)
	}
	k["outbounds"] = outs
	delete(k, "groups")
	return k
}

// Real second-scale HTTP behind the ordinary SOCKS outbound. Ten nodes exceed
// twice the two workers; the batch runs >10s, while each healthy target is 1-4s.
func TestR5AllProbeIndependentSecondsAndGenuineTimeout(t *testing.T) {
	var ordinal, in, maximum atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seq := ordinal.Add(1)
		n := in.Add(1)
		defer in.Add(-1)
		for {
			m := maximum.Load()
			if n <= m || maximum.CompareAndSwap(m, n) {
				break
			}
		}
		delay := time.Duration((seq-1)%4+1) * time.Second
		if seq == 10 || r.URL.Path == "/timeout" {
			delay = 6 * time.Second
		}
		select {
		case <-time.After(delay):
			w.WriteHeader(204)
		case <-r.Context().Done():
		}
	}))
	defer target.Close()
	h, _ := startSettings(t, batchKernel(t, 10), map[string]any{"probe_url": target.URL, "probe_timeout": "5s", "probe_round_timeout": "10s", "probe_concurrency": 2})
	ctx, cancel := context.WithCancel(context.Background())
	before := time.Now()
	round := beginAllProbeTest(t, h, ctx)
	if time.Since(before) > time.Second {
		t.Fatal("admission blocked on whole batch")
	}
	cancel() // accepted job is not tied to a wire/request deadline
	last := 0
	for {
		p, _ := round.projection()
		done := p["done"].(int)
		if done < last || done > 10 {
			t.Fatal("non-monotonic completions", last, done)
		}
		last = done
		select {
		case <-round.finished:
			goto finished
		case <-time.After(20 * time.Millisecond):
		}
	}
finished:
	elapsed := time.Since(before)
	p, rs := round.projection()
	if elapsed < 10*time.Second || elapsed > 35*time.Second || maximum.Load() != 2 || ordinal.Load() != 10 || p["done"] != 10 || len(p["names"].([]string)) != 0 {
		t.Fatal(elapsed, maximum.Load(), ordinal.Load(), p)
	}
	good, bad := 0, 0
	for name, r := range rs {
		if r.ProbeMS != nil && r.ErrorCode == "" {
			good++
		} else {
			bad++
			if r.ErrorCode != "PROBE_TARGET_TIMEOUT" || r.ErrorStage != "target" {
				t.Fatal("queue was mislabeled failed", name, r)
			}
		}
	}
	if good != 9 || bad != 1 {
		t.Fatal("expected nine healthy targets and one genuine timeout", good, bad, rs)
	}
	h.mu.Lock()
	if len(h.probes) != 10 || h.allRound != nil {
		t.Fatal("final results not published")
	}
	h.mu.Unlock()
	// The same single-node operation still uses 5s target/10s own-round and the
	// identical failure category; group budget regressions remain unchanged.
	v, e := h.probe(context.Background(), false, "n00", target.URL+"/timeout")
	if e != nil {
		t.Fatal(e)
	}
	one := v.(kernel.ProbeResult)
	if one.ErrorCode != "PROBE_TARGET_TIMEOUT" || one.ErrorStage != "target" {
		t.Fatal(one)
	}
	t.Logf("10 nodes / concurrency2: healthy=%d true-timeout=%d elapsed=%s; no shared 10s batch cutoff", good, bad, elapsed)
}

func TestR5BatchAdmissionNoDuplicateManualProbes(t *testing.T) {
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		entered <- struct{}{}
		select {
		case <-release:
			w.WriteHeader(204)
		case <-r.Context().Done():
		}
	}))
	defer target.Close()
	h, _ := startSettings(t, batchKernel(t, 3), map[string]any{"probe_url": target.URL, "probe_timeout": "2s", "probe_round_timeout": "3s", "probe_concurrency": 1})
	single := make(chan struct{})
	go func() { h.probe(context.Background(), false, "n00", ""); close(single) }()
	waitSignal(t, entered)
	if _, e := h.probeAll(context.Background(), nil); e == nil || e.Code != "probe_busy" {
		t.Fatal("batch overlapped single", e)
	}
	close(release)
	waitSignal(t, single)
	// Second server holds every target so duplicate requests can be asserted.
	hold := make(chan struct{})
	holdEntered := make(chan struct{}, 4)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		holdEntered <- struct{}{}
		select {
		case <-hold:
			w.WriteHeader(204)
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	h.mu.Lock()
	h.doc.client.ProbeURL = slow.URL
	h.mu.Unlock()
	round := beginAllProbeTest(t, h, context.Background())
	waitSignal(t, holdEntered)
	for range 3 {
		if _, e := h.probeAll(context.Background(), nil); e == nil || e.Code != "probe_busy" {
			t.Fatal("duplicate batch admitted", e)
		}
		if _, e := h.probe(context.Background(), false, "n00", ""); e == nil || e.Code != "probe_busy" {
			t.Fatal("single overlapped batch", e)
		}
	}
	h.Status()
	close(hold)
	waitAllProbeTest(t, round)
	// Admission and permits have drained; a subsequent ordinary single works.
	if _, e := h.probe(context.Background(), false, "n00", target.URL); e != nil {
		t.Fatal("busy gate stuck", e)
	}
	if calls.Load() != 2 {
		t.Fatal("single was duplicated", calls.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := h.probeAll(ctx, nil); e == nil || e.Code != "request_canceled" {
		t.Fatal("canceled admission launched a job", e)
	}
}

func TestR5BatchApplyAndCloseDiscardOldProgress(t *testing.T) {
	for _, action := range []string{"apply", "close"} {
		t.Run(action, func(t *testing.T) {
			entered := make(chan struct{}, 4)
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
			defer target.Close()
			h, text := startSettings(t, batchKernel(t, 6), map[string]any{"probe_url": target.URL, "probe_timeout": "5s", "probe_round_timeout": "10s", "probe_concurrency": 2})
			round := beginAllProbeTest(t, h, context.Background())
			waitSignal(t, entered)
			before := time.Now()
			if action == "apply" {
				// A full apply must actually change a non-selection field.
				text = settingsText(t, text, map[string]any{"probe_concurrency": 3})
				if _, e := h.Apply(text); e != nil {
					t.Fatal(e)
				}
			} else {
				if e := h.Close(); e != nil {
					t.Fatal(e)
				}
			}
			waitAllProbeTest(t, round)
			if time.Since(before) > 2*time.Second {
				t.Fatal("epoch cancellation did not drain promptly")
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if len(h.probes) != 0 || h.allRound != nil {
				t.Fatal("old epoch published results/progress")
			}
		})
	}
}
