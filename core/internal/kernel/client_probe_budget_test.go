package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/group"
)

// Real loopback SS -> SOCKS -> HTTP. The last Via member is usable, the other
// three are accepted silent SS peers. No external subscription or network.
func coldProbeFixture(t *testing.T, timeout time.Duration, target string) (*Server, Config) {
	t.Helper()
	blackhole, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	var sockets []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := blackhole.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			sockets = append(sockets, c)
			mu.Unlock()
			go io.Copy(io.Discard, c)
		}
	}()
	t.Cleanup(func() {
		blackhole.Close()
		<-done
		mu.Lock()
		defer mu.Unlock()
		for _, c := range sockets {
			c.Close()
		}
	})
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Log = &LogOptions{Level: "error"}
	c.Security = &SecurityOptions{AllowLoopback: true}
	good := c
	good.Inbounds = []Inbound{{Protocol: "shadowsocks", Listen: "127.0.0.1:0", SS: &SSOptions{Method: "aes-128-gcm", Password: "synthetic"}}}
	up := groupsStart(t, good)
	tail := groupsStart(t, c)
	for i := 0; i < 3; i++ {
		c.Outbounds = append(c.Outbounds, OutboundConfig{Name: fmt.Sprintf("bad-%d", i), Type: "shadowsocks", Server: "127.0.0.1", Port: uint16(blackhole.Addr().(*net.TCPAddr).Port), Method: "aes-128-gcm", Password: "synthetic"})
	}
	c.Outbounds = append(c.Outbounds, OutboundConfig{Name: "good-last", Type: "shadowsocks", Server: "127.0.0.1", Port: uint16(up.Addresses()[0].(*net.TCPAddr).Port), Method: "aes-128-gcm", Password: "synthetic"}, OutboundConfig{Name: "root", Type: "socks5", Server: "127.0.0.1", Port: uint16(tail.Addresses()[0].(*net.TCPAddr).Port), Via: "dep"})
	c.Groups = []GroupConfig{{Name: "dep", Type: "url-test", Members: []string{"bad-0", "bad-1", "bad-2", "good-last"}, Probe: &group.ProbeOptions{URL: target + "/health", Timeout: outbound.Duration(timeout)}}}
	return groupsStart(t, c), c
}
func newProbePolicy(t *testing.T, d time.Duration) *ManualProbePolicy {
	t.Helper()
	p, e := NewManualProbePolicy(d, 1)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func probeCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}
func assertGoodDependency(t *testing.T, s *Server) {
	t.Helper()
	snap := s.GroupSnapshots()[0]
	if snap.Current != "good-last" {
		t.Fatalf("did not keep full-round healthy choice: %s", snap.Current)
	}
	for i, m := range snap.Members {
		if !m.Probed || m.ProbeOK != (i == 3) {
			t.Fatal("partial or fabricated dependency health")
		}
	}
}

func TestManualProbeColdViaBudgetSeparation(t *testing.T) {
	var health, targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			health.Add(1)
		} else {
			targetCalls.Add(1)
			time.Sleep(25 * time.Millisecond)
		}
		w.WriteHeader(204)
	}))
	defer target.Close()
	// Execute the exact old combined-budget path on a cold generation. The
	// healthy last member replies early, but the root cannot begin in 100ms.
	old, _ := coldProbeFixture(t, 300*time.Millisecond, target.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, e := group.ProbeOutbound(ctx, old.rt.nodes["root"], target.URL+"/target")
	cancel()
	if !errors.Is(e, context.DeadlineExceeded) || targetCalls.Load() != 0 || health.Load() == 0 {
		t.Fatal("old cold combined budget did not reproduce starvation")
	}
	fresh, _ := coldProbeFixture(t, 300*time.Millisecond, target.URL)
	before := time.Now()
	r, e := fresh.ProbeNodeWithPolicy(probeCtx(t, 2*time.Second), "root", target.URL+"/target", newProbePolicy(t, 100*time.Millisecond))
	elapsed := time.Since(before)
	if e != nil || r.ProbeMS == nil || r.Error != "" || r.ErrorCode != "" || elapsed < 280*time.Millisecond || elapsed > time.Second || *r.ProbeMS > 100 {
		t.Fatalf("dependency consumed target budget: result=%+v elapsed=%s err=%v", r, elapsed, e)
	}
	assertGoodDependency(t, fresh)
	t.Logf("old combined 100ms deadline failed before target; new elapsed=%s target_ms=%.1f", elapsed, *r.ProbeMS)
	// Warm readiness is instantaneous; original target budget and group choice
	// remain unchanged on the next request.
	before = time.Now()
	r, e = fresh.ProbeNodeWithPolicy(probeCtx(t, time.Second), "root", target.URL+"/target", newProbePolicy(t, 100*time.Millisecond))
	if e != nil || r.ProbeMS == nil || time.Since(before) > 250*time.Millisecond {
		t.Fatal("warm readiness re-ran first round")
	}
	assertGoodDependency(t, fresh)
}

func TestManualProbeReadyTargetKeepsFiveSecondBudget(t *testing.T) {
	entered := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(204)
			return
		}
		entered <- struct{}{}
		<-r.Context().Done()
	}))
	defer target.Close()
	s, _ := coldProbeFixture(t, 150*time.Millisecond, target.URL)
	before := time.Now()
	r, e := s.ProbeNodeWithPolicy(probeCtx(t, 8*time.Second), "root", target.URL+"/slow", newProbePolicy(t, 5*time.Second))
	elapsed := time.Since(before)
	if e != nil || r.ProbeMS != nil || r.ErrorCode != "PROBE_TARGET_TIMEOUT" || r.ErrorStage != "target" || elapsed < 5*time.Second || elapsed > 7*time.Second {
		t.Fatalf("actual 5s target limit changed: %+v %s %v", r, elapsed, e)
	}
	select {
	case <-entered:
	default:
		t.Fatal("root target was never attempted")
	}
	assertGoodDependency(t, s)
	t.Logf("Via prepared; target timed out after original 5s: total=%s code=%s", elapsed, r.ErrorCode)
}

func TestManualProbeWithoutViaUnchanged(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(204)
	}))
	defer target.Close()
	c := socksCfg("127.0.0.1:0")
	c.Security = &SecurityOptions{AllowLoopback: true}
	s := groupsStart(t, c)
	policy := newProbePolicy(t, 100*time.Millisecond)
	for _, path := range []string{"/ok", "/slow"} {
		before := time.Now()
		r, e := s.ProbeNodeWithPolicy(probeCtx(t, time.Second), "direct", target.URL+path, policy)
		elapsed := time.Since(before)
		if e != nil {
			t.Fatal(e)
		}
		if path == "/ok" {
			if r.ProbeMS == nil {
				t.Fatal("ordinary direct probe failed")
			}
		} else if r.ErrorCode != "PROBE_TARGET_TIMEOUT" || elapsed < 80*time.Millisecond || elapsed > 500*time.Millisecond {
			t.Fatal("ordinary node timeout changed")
		}
	}
}

func TestManualProbeDependencyDeadlineCancelReload(t *testing.T) {
	for _, action := range []string{"deadline", "cancel", "reload"} {
		t.Run(action, func(t *testing.T) {
			healthy := make(chan struct{}, 1)
			var targets atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					select {
					case healthy <- struct{}{}:
					default:
					}
				} else {
					targets.Add(1)
				}
				w.WriteHeader(204)
			}))
			defer target.Close()
			s, c := coldProbeFixture(t, 400*time.Millisecond, target.URL)
			old := s.current()
			policy := newProbePolicy(t, 100*time.Millisecond)
			ctx, cancel := context.WithTimeout(context.Background(), 130*time.Millisecond)
			defer cancel()
			done := make(chan ProbeResult, 1)
			go func() { r, _ := s.ProbeNodeWithPolicy(ctx, "root", target.URL+"/target", policy); done <- r }()
			select {
			case <-healthy:
			case <-time.After(time.Second):
				t.Fatal("healthy Via never replied")
			}
			switch action {
			case "cancel":
				cancel()
			case "reload":
				if _, e := s.ApplyConfig(c); e != nil {
					t.Fatal(e)
				}
			}
			var r ProbeResult
			select {
			case r = <-done:
			case <-time.After(time.Second):
				t.Fatal("dependency wait leaked canceled context")
			}
			want := "PROBE_DEPENDENCY_UNREADY"
			if action != "deadline" {
				want = "PROBE_CANCELED"
			}
			if r.ErrorCode != want || r.ErrorStage != "dependency" || r.ProbeMS != nil || targets.Load() != 0 {
				t.Fatalf("late target/cause lost: %+v", r)
			}
			if action == "reload" {
				if s.current() == old {
					t.Fatal("not reloaded")
				}
				for _, g := range s.GroupSnapshots() {
					for _, m := range g.Members {
						if m.Probed {
							t.Fatal("old readiness committed to new generation")
						}
					}
				}
			}
			if len(policy.slots) != 0 {
				t.Fatal("manual permit leaked")
			}
			r, e := s.ProbeNodeWithPolicy(probeCtx(t, time.Second), "direct", target.URL+"/quick", policy)
			if e != nil || r.ProbeMS == nil {
				t.Fatal("cancellation leaked permit/context into new probe")
			}
		})
	}
}

func TestProbeFailureCategoriesNeverEchoRawError(t *testing.T) {
	for _, tc := range []struct {
		stage string
		err   error
		code  string
	}{{"dependency", fmt.Errorf("https://user:password@private.invalid/token: %w", context.DeadlineExceeded), "PROBE_DEPENDENCY_UNREADY"}, {"target", fmt.Errorf("private password=SECRET: %w", context.DeadlineExceeded), "PROBE_TARGET_TIMEOUT"}, {"target", errors.New("private token=SECRET"), "PROBE_FAILED"}, {"queue", context.DeadlineExceeded, "PROBE_QUEUE_TIMEOUT"}, {"dependency", context.Canceled, "PROBE_CANCELED"}} {
		var r ProbeResult
		setProbeFailure(&r, tc.stage, tc.err)
		b, _ := json.Marshal(r)
		if r.ErrorCode != tc.code || strings.Contains(string(b), "private") || strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "https") {
			t.Fatal("unsafe or ambiguous probe error")
		}
	}
}

// Readiness failure is not an HTTP health sample of the root. Incomplete
// manual group rounds must not mark the otherwise untested root unhealthy.
func TestManualProbeDependencyNotRecordedAsTargetHealth(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer target.Close()
	s, c := coldProbeFixture(t, 200*time.Millisecond, target.URL)
	lazy := true
	c.Groups = append(c.Groups, GroupConfig{Name: "manual", Type: "smart", Members: []string{"root"}, Fixed: "root", Lazy: &lazy, Probe: &group.ProbeOptions{URL: target.URL}})
	if _, e := s.ApplyConfig(c); e != nil {
		t.Fatal(e)
	}
	gen := s.current()
	for _, g := range gen.rt.groups {
		if g.Name() == "dep" {
			g.Close()
		}
	}
	rs, e := s.ProbeGroupWithPolicy(probeCtx(t, time.Second), "manual", target.URL, newProbePolicy(t, 100*time.Millisecond))
	if e != nil || len(rs) != 1 || rs[0].ErrorStage != "dependency" {
		t.Fatal("expected explicit readiness failure")
	}
	for _, g := range s.GroupSnapshots() {
		if g.Name == "manual" {
			for _, m := range g.Members {
				if m.Probed {
					t.Fatal("unattempted target was recorded as failed health")
				}
			}
		}
	}
}

func TestManualProbePreparationRetainsSharedPermit(t *testing.T) {
	healthy := make(chan struct{}, 1)
	var actual atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			select {
			case healthy <- struct{}{}:
			default:
			}
		} else {
			actual.Add(1)
		}
		w.WriteHeader(204)
	}))
	defer target.Close()
	s, _ := coldProbeFixture(t, 400*time.Millisecond, target.URL)
	policy := newProbePolicy(t, 100*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rootDone := make(chan ProbeResult, 1)
	go func() { r, _ := s.ProbeNodeWithPolicy(ctx, "root", target.URL+"/root", policy); rootDone <- r }()
	select {
	case <-healthy:
	case <-time.After(time.Second):
		t.Fatal("preparation did not start")
	}
	queued, cancelQueued := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancelQueued()
	r, e := s.ProbeNodeWithPolicy(queued, "direct", target.URL+"/queued", policy)
	if e != nil || r.ErrorCode != "PROBE_QUEUE_TIMEOUT" || r.ErrorStage != "queue" || actual.Load() != 0 {
		t.Fatal("preparation released permit or queued probe issued late target")
	}
	cancel()
	select {
	case r = <-rootDone:
		if r.ErrorCode != "PROBE_CANCELED" {
			t.Fatal("cancellation lost")
		}
	case <-time.After(time.Second):
		t.Fatal("preparation wait leaked")
	}
	if len(policy.slots) != 0 {
		t.Fatal("shared permit leaked")
	}
}
