package group

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/outbound"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// long interval: no periodic rounds unless a test advances that far
var smartLong = &ProbeOptions{URL: "http://probe.test/", Interval: outbound.Duration(10 * time.Hour)}

func setEWMA(g *autoGroup, name string, d time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, n := range g.cfg.members {
		if n == name {
			g.st[i].real.latency(d, g.clk.Now())
		}
	}
}

func near(a, b time.Duration) bool { return math.Abs(float64(a-b)) <= float64(time.Microsecond) }

func TestSmartColdStartOrder(t *testing.T) {
	clk := newFakeClock()
	a, b, c := newFake("a"), newFake("b"), newFake("c")
	p := newFakeProbe(map[string]time.Duration{"a": 300 * ms_, "b": 100 * ms_, "c": 200 * ms_})
	p.block = make(chan struct{})
	ev := &eventLog{}
	g := newAuto(t, Options{Type: TypeSmart}, members(a, b, c), clk, p, ev)
	g.Start(context.Background())
	if !isProbing(g) {
		t.Fatal("smart did not probe immediately on Start")
	}
	if g.Current() != "" || g.Snapshot().Current != "" {
		t.Fatal("cold Smart reported a zero-valued member as selected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if conn, err := g.DialTCP(ctx, outbound.Addr{Host: "x.test", Port: 443}); conn != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cold request did not wait within its own budget", conn, err)
	}
	if a.dialCount()+b.dialCount()+c.dialCount() != 0 {
		t.Fatal("cold timeout silently attempted an unmeasured member")
	}
	close(p.block)
	waitRounds(t, g, 1)
	if g.Current() != "b" || dial(t, g, "x.test") != "b" {
		t.Fatal("first full round did not select the best member without hysteresis", g.Current())
	}
	if sw := switches(ev); len(sw) != 1 || sw[0] != ">b" {
		t.Fatalf("first choice must come from unselected, not a fictitious a: %v", sw)
	}

	// A failed full first round cannot silently turn into configuration-order
	// business retries. A later partial success is not a new complete round.
	clk2 := newFakeClock()
	a2, b2, c2 := newFake("a"), newFake("b"), newFake("c")
	p2 := newFakeProbe(map[string]time.Duration{})
	g2 := newAuto(t, Options{Type: TypeSmart}, members(c2, a2, b2), clk2, p2, nil)
	for _, n := range []string{"a", "b", "c"} {
		p2.set(n, 0, true)
	}
	g2.Start(context.Background())
	waitRounds(t, g2, 1)
	clk2.Advance(time.Second)
	g2.RecordProbe("a", time.Millisecond, clk2.Now(), nil)
	if g2.Current() != "" || !g2.cold {
		t.Fatal("partial recovery after an all-down round bootstrapped Smart")
	}
	if a2.dialCount()+b2.dialCount()+c2.dialCount() != 0 {
		t.Fatal("failed first round issued business traffic")
	}
}

func TestSmartPriorityChangesChoice(t *testing.T) {
	for _, tc := range []struct {
		prio map[string]float64
		want string
	}{
		{nil, "a"},
		{map[string]float64{"b": 0.5}, "b"},  // 120*0.5 = 60 < 100
		{map[string]float64{"a": 2}, "b"},    // 200 > 120
		{map[string]float64{"b": 1.5}, "a"},  // 180 > 100
		{map[string]float64{"a": 0.01}, "a"}, // tiny factor keeps a
	} {
		clk := newFakeClock()
		a, b := newFake("a"), newFake("b")
		p := newFakeProbe(map[string]time.Duration{"a": 100 * ms_, "b": 120 * ms_})
		g := newAuto(t, Options{Type: TypeSmart, Probe: smartLong, Priority: tc.prio}, members(a, b), clk, p, nil)
		g.Start(context.Background())
		waitRounds(t, g, 1)
		if g.Current() != tc.want || dial(t, g, "x.test") != tc.want {
			t.Fatalf("priority %v: current %q, want %q", tc.prio, g.Current(), tc.want)
		}
	}
}

func TestSmartCurrentFailureSwitchesImmediately(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 100 * ms_, "b": 1000 * ms_})
	ev := &eventLog{}
	g := newAuto(t, Options{Type: TypeSmart, Probe: smartLong}, members(a, b), clk, p, ev)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	a.setErr(&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED})
	// no dwell, and a (100+300) would still score better than b (1000)
	if got := dial(t, g, "x.test"); got != "b" {
		t.Fatalf("retry via %q", got)
	}
	if g.Current() != "b" {
		t.Fatalf("current %q after current failed", g.Current())
	}
	if sw := switches(ev); len(sw) != 2 || sw[0] != ">a" || sw[1] != "a>b" {
		t.Fatalf("switches %v", sw)
	}
}

func TestSiteCacheBoundedLRU(t *testing.T) {
	c := newSiteCache(smartSiteCap)
	defer c.clear()
	now := time.Now()
	for i := 0; i < smartSiteCap+100; i++ {
		c.record(fmt.Sprintf("s%d.test", i), 0, true, now, 0)
	}
	if c.len() != smartSiteCap {
		t.Fatalf("len = %d, want %d", c.len(), smartSiteCap)
	}
	if c.get("s0.test", now) != nil || c.get(fmt.Sprintf("s%d.test", smartSiteCap+99), now) == nil {
		t.Fatal("LRU eviction order wrong")
	}
	if c.get(fmt.Sprintf("s%d.test", smartSiteCap+99), now.Add(time.Hour)) != nil {
		t.Fatal("entry not expired after 1h")
	}
}

// smartPair builds a started smart group whose current member is a.
func smartPair(t *testing.T) (*autoGroup, *fakeClock, *fakeOut, *fakeOut) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 50 * ms_, "b": 60 * ms_})
	g := newAuto(t, Options{Type: TypeSmart, Probe: smartLong}, members(a, b), clk, p, nil)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	if g.Current() != "a" {
		t.Fatalf("current %q", g.Current())
	}
	return g, clk, a, b
}

func TestSmartPausesProbingWhenIdle(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 50 * ms_, "b": 60 * ms_})
	g := newAuto(t, Options{Type: TypeSmart}, members(a, b), clk, p, nil) // interval default 5m
	g.Start(context.Background())
	waitRounds(t, g, 1)
	for k := int64(2); k <= 5; k++ { // t = 5m..20m
		clk.Advance(5 * time.Minute)
		waitRounds(t, g, k)
	}
	clk.Advance(5 * time.Minute) // t = 25m: unused for 5 intervals -> pause
	clk.Advance(2 * time.Hour)
	time.Sleep(20 * ms_)
	if n := g.roundsRun.Load(); n != 5 || isProbing(g) || clk.pending() != 0 {
		t.Fatalf("idle group kept probing: rounds %d probing %v timers %d", n, isProbing(g), clk.pending())
	}
	if p.count("a") != 5 {
		t.Fatalf("probe calls %d", p.count("a"))
	}
	dial(t, g, "x.test") // use resumes probing at once
	waitRounds(t, g, 6)
	clk.Advance(5 * time.Minute)
	waitRounds(t, g, 7)
}

func TestRestoredSmartOptionsPreserveExplicitAndDynamic(t *testing.T) {
	const old = `{"name":"same","type":"smart","members":["a","b"],"use":["p"],"include_group":"source","include_all":true,"include_all_proxies":true,"include_all_providers":true,"filter":"a|b","exclude_filter":"gone","exclude_type":"socks5","fixed":"a","priority":{"a":1.5,"temporarily-absent":0.5},"probe":{"url":"https://probe.invalid/custom","timeout":"9s","expected_status":"204"},"tolerance":0,"damping":{"relative_improvement":0,"confirm_rounds":3,"min_dwell":"0s"},"smart":{"scope":"site","exploration_rate":0.02,"adaptive_dial":false}}`
	var o Options
	if e := json.Unmarshal([]byte(old), &o); e != nil {
		t.Fatal(e)
	}
	if o.Type != TypeSmart || o.Name != "same" || o.Fixed != "a" || o.Priority["temporarily-absent"] != .5 {
		t.Fatal(o)
	}
	c, e := normalize(o)
	if e != nil || c.interval != 5*time.Minute || c.timeout != 9*time.Second || c.tolerance != 0 || c.relative != 0 || c.dwell != 0 || c.confirms != 3 {
		t.Fatal(c, e)
	}
	out, e := json.Marshal(o)
	if e != nil {
		t.Fatal(e)
	}
	var a, b map[string]json.RawMessage
	_ = json.Unmarshal([]byte(old), &a)
	_ = json.Unmarshal(out, &b)
	// Numeric zero and explicit duration zero have identical preserved semantics.
	delete(a, "tolerance")
	delete(b, "tolerance")
	var va, vb any
	_ = json.Unmarshal(mustJSON(a), &va)
	_ = json.Unmarshal(mustJSON(b), &vb)
	if !reflect.DeepEqual(va, vb) {
		t.Fatal("non-Smart fields changed", string(out))
	}
	o.Members = []string{"b", "temporarily-absent", "a"}
	o.Expanded = true
	c, e = normalize(o)
	if e != nil || !reflect.DeepEqual(c.priority, []float64{1, .5, 1.5}) {
		t.Fatal(c.priority, e)
	}
	o.Members = []string{"a", "b"}
	g := newAuto(t, o, members(newFake("a"), newFake("b")), newFakeClock(), nil, nil)
	if g.Type() != TypeSmart || g.Snapshot().Type != TypeSmart {
		t.Fatal("Smart runtime missing")
	}
	// A directly constructed runtime type is not a new/alternate Smart entry.
	if Validate(Options{Name: "g", Type: "smart", Members: []string{"a"}, Probe: probeOpts()}) != nil {
		t.Fatal("native Smart runtime rejected")
	}
	for _, interval := range []string{"0s", "7m"} {
		var v Options
		input := strings.Replace(old, `"timeout":"9s"`, `"interval":"`+interval+`","timeout":"9s"`, 1)
		if e := json.Unmarshal([]byte(input), &v); e != nil {
			t.Fatal(e)
		}
		cc, e := normalize(v)
		want := 5 * time.Minute
		if interval == "7m" {
			want = 7 * time.Minute
		}
		if e != nil || cc.interval != want {
			t.Fatal(interval, cc, e)
		}
	}
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func TestRestoredSmartInvalidStillRejected(t *testing.T) {
	base := `{"name":"g","type":"smart","members":["a"],"probe":{"url":"http://probe.invalid/"}}`
	for _, extra := range []string{`,"smart":{"unknown":true}`, `,"smart":{"scope":"other"}`, `,"smart":{"exploration_rate":0.1}`, `,"smart":{"adaptive_dial":"yes"}`, `,"unknown":true`, `,"max_failed_times":3`, `,"priority":{"a":0}`} {
		var o Options
		e := json.Unmarshal([]byte(strings.TrimSuffix(base, "}")+extra+"}"), &o)
		if e == nil {
			e = Validate(o)
		}
		if e == nil {
			t.Fatal("invalid accepted", extra)
		}
	}
	var o Options
	if json.Unmarshal([]byte(strings.Replace(base, `"smart"`, `"url-test"`, 1)[:len(base)-3]), &o) == nil {
		t.Fatal("invalid JSON accepted")
	}
}
func TestNoSmartFallbackFixedRemainsHealthyFirst(t *testing.T) {
	c := newFakeClock()
	g := newAuto(t, Options{Type: TypeFallback, Fixed: "b"}, members(newFake("a"), newFake("b")), c, nil, nil)
	v2Round(g, c, 10*time.Millisecond, 30*time.Millisecond)
	if g.Current() != "b" || g.Snapshot().Current != "b" {
		t.Fatal("healthy fixed ignored")
	}
	c.Advance(time.Second)
	g.RecordProbe("b", 0, c.Now(), errors.New("down"))
	if g.Current() != "a" || g.Snapshot().Fixed != "b" {
		t.Fatal("soft fixed lost")
	}
	c.Advance(time.Second)
	g.RecordProbe("b", 30*time.Millisecond, c.Now(), nil)
	if g.Current() != "b" {
		t.Fatal("fixed did not recover")
	}
	if e := g.SetFixed(""); e != nil {
		t.Fatal(e)
	}
	if g.Current() != "a" {
		t.Fatal("automatic fallback order changed")
	}
}

func TestClientSmartManualRoundOrder(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "a-first"
		if reverse {
			name = "b-first"
		}
		t.Run(name, func(t *testing.T) {
			clk := newFakeClock()
			g := newAuto(t, Options{Type: TypeSmart, Priority: map[string]float64{"a": 4}}, members(newFake("a"), newFake("b")), clk, nil, nil)
			results := []ProbeSample{{Name: "a", Latency: 100 * time.Millisecond, At: clk.Now()}, {Name: "b", Latency: 200 * time.Millisecond, At: clk.Now()}}
			if reverse {
				results[0], results[1] = results[1], results[0]
			}
			g.RecordProbeRound(results)
			for _, m := range g.Snapshot().Members {
				want := time.Duration(100) * time.Millisecond
				if m.Name == "b" {
					want = 200 * time.Millisecond
				}
				if !m.Probed || !m.ProbeOK || m.ProbeLatency != want || m.Latency != 0 || m.ScoreParts.ProbeMS == nil || *m.ScoreParts.ProbeMS != ms(want) {
					t.Fatalf("sample/EWMA not retained: %+v", m)
				}
			}
			if got := g.Current(); got != "b" {
				t.Fatalf("same full round: a=100ms*4, b=200ms*1: current=%s, want b", got)
			}
		})
	}
}

// V2 does not mix probe and real EWMA. Atomic manual order is retained;
// median/maturity and repeated rounds are exercised in TestV2StableMedianAndIndependentRounds.
func TestClientManualRoundFailuresFixedAndStale(t *testing.T) {
	for _, kind := range []string{TypeSmart, TypeURLTest} {
		t.Run(kind, func(t *testing.T) {
			clk := newFakeClock()
			g := newAuto(t, Options{Type: kind, Fixed: "a", Priority: map[string]float64{"a": 100}}, members(newFake("a"), newFake("b")), clk, nil, nil)
			failed := errors.New("HTTP probe failed")
			g.RecordProbeRound([]ProbeSample{{Name: "a", At: clk.Now(), Err: failed}, {Name: "b", Latency: time.Millisecond, At: clk.Now()}})
			s := g.Snapshot()
			if s.Current != "b" || s.Fixed != "a" || s.Members[0].ProbeOK || !s.Members[1].ProbeOK || s.Members[1].Priority != 1 {
				t.Fatal("fixed/failed/default weight changed")
			}
			g.RecordProbeRound(nil)
			g.RecordProbeRound([]ProbeSample{{Name: "a", Latency: time.Millisecond, At: clk.Now().Add(-time.Second)}})
			if !reflect.DeepEqual(s, g.Snapshot()) {
				t.Fatal("empty/stale round changed state")
			}
			g.Close()
			g.RecordProbeRound([]ProbeSample{{Name: "a", Latency: time.Millisecond, At: clk.Now().Add(time.Second)}})
			if !reflect.DeepEqual(s, g.Snapshot()) {
				t.Fatal("closed group accepted late round")
			}
			all := newAuto(t, Options{Type: kind}, members(newFake("a"), newFake("b")), clk, nil, nil)
			all.RecordProbeRound([]ProbeSample{{Name: "b", At: clk.Now(), Err: failed}, {Name: "a", At: clk.Now(), Err: failed}})
			for _, m := range all.Snapshot().Members {
				if !m.Probed || m.ProbeOK || m.ProbeLatency != 0 {
					t.Fatal("failed round fabricated success")
				}
			}
		})
	}
}

func TestClientConcurrentManualRounds(t *testing.T) {
	clk := newFakeClock()
	g := newAuto(t, Options{Type: TypeSmart, Fixed: "a"}, members(newFake("a"), newFake("b")), clk, nil, nil)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				g.RecordProbeRound([]ProbeSample{{Name: "a", Latency: time.Millisecond, At: clk.Now()}, {Name: "b", Latency: 2 * time.Millisecond, At: clk.Now()}})
				_ = g.Snapshot()
			}
		}()
	}
	wg.Wait()
	if g.Current() != "a" {
		t.Fatal("fixed changed under concurrent rounds")
	}
}

func TestClientManualPriorityValidation(t *testing.T) {
	for _, kind := range []string{TypeSmart, TypeURLTest} {
		for _, v := range []float64{0, -1, 101, math.NaN(), math.Inf(1), math.Inf(-1)} {
			if Validate(Options{Name: "g", Type: kind, Members: []string{"a"}, Probe: probeOpts(), Priority: map[string]float64{"a": v}}) == nil {
				t.Fatalf("accepted %s priority %v", kind, v)
			}
		}
		for _, v := range []float64{0.01, 1, 100} {
			if e := Validate(Options{Name: "g", Type: kind, Members: []string{"a"}, Probe: probeOpts(), Priority: map[string]float64{"a": v}}); e != nil {
				t.Fatal(e)
			}
		}
	}
}

type r9SlowDial struct{ calls atomic.Int32 }

func (s *r9SlowDial) Name() string { return "member" }
func (s *r9SlowDial) Type() string { return "direct" }
func (s *r9SlowDial) Close() error { return nil }
func (s *r9SlowDial) UDP() bool    { return false }
func (s *r9SlowDial) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return nil, outbound.ErrUDPUnsupported
}
func (s *r9SlowDial) DialTCP(ctx context.Context, a outbound.Addr) (net.Conn, error) {
	s.calls.Add(1)
	select {
	case <-time.After(80 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", a.String())
}
func TestR9UnifiedReusesOneSocketAndExcludesHandshake(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "HEAD" {
			t.Error("not HEAD")
		}
		calls.Add(1)
		time.Sleep(15 * time.Millisecond)
		w.WriteHeader(204)
	}))
	defer target.Close()
	out := &r9SlowDial{}
	lat, e := ProbeOutboundDelay(context.Background(), out, target.URL, true)
	if e != nil || lat < 10*time.Millisecond || lat > 70*time.Millisecond || out.calls.Load() != 1 || calls.Load() != 2 {
		t.Fatal("not warm RTT", lat, e, out.calls.Load(), calls.Load())
	}
	out = &r9SlowDial{}
	lat, e = ProbeOutboundDelay(context.Background(), out, target.URL, false)
	if e != nil || lat < 90*time.Millisecond || out.calls.Load() != 1 || calls.Load() != 3 {
		t.Fatal("full mode changed", lat, e)
	}
}
func TestR9UnifiedSecondFailureRetainsFirstSampleWithoutRedial(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 2 {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
		w.WriteHeader(204)
	}))
	defer target.Close()
	out := &r9SlowDial{}
	lat, e := ProbeOutboundDelay(context.Background(), out, target.URL, true)
	if e != nil || lat < 85*time.Millisecond || out.calls.Load() != 1 || calls.Load() != 2 {
		t.Fatal("fallback must keep first full sample", lat, e, out.calls.Load(), calls.Load())
	}
}
func TestR9UnifiedClosingServerDoesNotStartAnotherConnection(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Connection", "close")
		w.WriteHeader(204)
	}))
	defer target.Close()
	out := &r9SlowDial{}
	lat, e := ProbeOutboundDelay(context.Background(), out, target.URL, true)
	if e != nil || lat < 75*time.Millisecond || out.calls.Load() != 1 || calls.Load() != 1 {
		t.Fatal(lat, e, out.calls.Load(), calls.Load())
	}
}
func TestR9UnifiedSameDeadlineAndExpectedStatus(t *testing.T) {
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 2 {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Second):
			}
		}
		w.WriteHeader(204)
	}))
	defer target.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 140*time.Millisecond)
	defer cancel()
	out := &r9SlowDial{}
	before := time.Now()
	lat, e := ProbeOutboundDelay(ctx, out, target.URL, true)
	if e != nil || lat < 75*time.Millisecond || time.Since(before) > 300*time.Millisecond || out.calls.Load() != 1 {
		t.Fatal("deadline extended or first lost", lat, e)
	}
}
