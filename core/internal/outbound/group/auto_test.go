package group

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"net/netip"
	"testing"
	"time"
)

func TestRound2NestedFallbackStates(t *testing.T) {
	clk := newFakeClock()
	hk := newAuto(t, Options{Name: "HK", Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("hk1"), newFake("hk2")), clk, nil, nil)
	sg := newAuto(t, Options{Name: "SG", Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("sg1")), clk, nil, nil)
	final := newAuto(t, Options{Name: "Final", Type: TypeFallback, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, []outbound.Outbound{hk, sg}, clk, nil, nil)
	check := func(stage, want string) {
		t.Helper()
		got := final.Current()
		t.Logf("%s: Final=%s HK_al ive=%v HK_current=%s", stage, got, hk.ClientAlive(), hk.Current())
		if got != want {
			t.Fatalf("want %s got %s", want, got)
		}
	}
	check("both child groups untested", "HK")
	at := clk.Now()
	hk.RecordProbe("hk1", 0, at, errors.New("probe failure"))
	check("HK current leaf failed once, hk2 untested", "HK")
	hk.RecordProbe("hk2", 0, at, errors.New("probe failure"))
	check("all HK leaves latest probe failed, SG untested", "SG")
	final.RecordProbe("HK", 20*time.Millisecond, at.Add(time.Second), nil)
	check("parent fresher successful probe restores HK immediately", "HK")
	hk.RecordProbe("hk2", 30*time.Millisecond, at.Add(2*time.Second), nil)
	check("one HK child recovers", "HK")
	single := newAuto(t, Options{Name: "singleHK", Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("only")), clk, nil, nil)
	parent := newAuto(t, Options{Name: "P", Type: TypeFallback, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, []outbound.Outbound{single, sg}, clk, nil, nil)
	single.RecordProbe("only", 0, at, errors.New("one failed test"))
	if parent.Current() != "SG" {
		t.Fatal("single-leaf HK failure must select SG")
	}
	t.Log("one-leaf HK: one failed health sample => SG")
}

func TestRound2SoftFixedLifecycle(t *testing.T) {
	for _, kind := range []string{TypeURLTest, TypeSmart, TypeFallback, TypeLoadBalance} {
		t.Run(kind, func(t *testing.T) {
			clk := newFakeClock()
			g := newAuto(t, Options{Type: kind, Fixed: "b", Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("a"), newFake("b")), clk, nil, nil)
			at := clk.Now()
			g.RecordProbe("a", 10*time.Millisecond, at, nil)
			g.RecordProbe("b", 40*time.Millisecond, at, nil)
			check := func(want string) {
				t.Helper()
				if g.Current() != want || g.Snapshot().Current != want {
					t.Fatalf("current=%s snapshot=%s want=%s", g.Current(), g.Snapshot().Current, want)
				}
				g.mu.Lock()
				var cs []int
				if kind == TypeLoadBalance {
					cs = g.lbOrderLocked(netip.Addr{}, "test", false, at, nil)
				} else {
					cs = g.candidatesLocked("test", false, at)
				}
				g.mu.Unlock()
				if len(cs) == 0 || g.cfg.members[cs[0]] != want {
					t.Fatalf("candidates=%v want %s", cs, want)
				}
			}
			check("b")
			g.RecordProbe("b", 0, at.Add(time.Second), errors.New("failed"))
			check("a")
			if g.cfg.fixed != "b" {
				t.Fatal("lost fixed on failure")
			}
			g.RecordProbe("b", 40*time.Millisecond, at.Add(2*time.Second), nil)
			if kind == TypeFallback || kind == TypeURLTest {
				check("b")
			} else {
				check("a")
				clk.Advance(7 * time.Second)
				g.RecordProbe("b", 40*time.Millisecond, clk.Now(), nil)
				check("a")
				clk.Advance(5 * time.Second)
				check("b")
			}
			// Unpin is a document replacement, as desktop document.apply does.
			unpinned := newAuto(t, Options{Type: kind, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("a"), newFake("b")), clk, nil, nil)
			if unpinned.Snapshot().Fixed != "" {
				t.Fatal("unpin persisted")
			}
			if kind == TypeSmart {
				if unpinned.Current() != "" {
					t.Fatal("cold Smart selected before complete round")
				}
				v2Round(unpinned, clk, 10*time.Millisecond, 40*time.Millisecond)
			}
			if unpinned.Current() != "a" {
				t.Fatal("unpin did not restore automatic")
			}
		})
	}
}

func TestR10ClientStartupRetryOnceAndOriginalPeriodicDeadline(t *testing.T) {
	for _, kind := range []string{TypeURLTest, TypeFallback, TypeSmart} {
		t.Run(kind, func(t *testing.T) {
			clk := newFakeClock()
			p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond})
			p.set("a", 0, true)
			p.block = make(chan struct{})
			lazy := false
			g := newAuto(t, Options{Type: kind, Lazy: &lazy, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true, Interval: outbound.Duration(time.Minute)}}, members(newFake("a")), clk, p, nil)
			g.Start(context.Background())
			deadline := time.Now().Add(time.Second)
			for !isProbing(g) {
				if time.Now().After(deadline) {
					t.Fatal("no first round")
				}
				time.Sleep(time.Millisecond)
			}
			if g.Snapshot().Members[0].Probed {
				t.Fatal("unfinished startup published a failure")
			}
			close(p.block)
			waitRounds(t, g, 1)
			clk.Advance(11 * time.Second)
			if g.roundsRun.Load() != 1 {
				t.Fatal("early retry")
			}
			clk.Advance(time.Second)
			waitRounds(t, g, 2)
			clk.Advance(12 * time.Second)
			if g.roundsRun.Load() != 2 || p.count("a") > 6 {
				t.Fatal("retry became a loop")
			}
			p.set("a", 41*time.Millisecond, false)
			clk.Advance(36 * time.Second)
			waitRounds(t, g, 3)
			if !g.Snapshot().Members[0].ProbeOK {
				t.Fatal("original 1m tick moved")
			}
		})
	}
}
func TestR10ClientStartupRetryRecoversPartialFailures(t *testing.T) {
	clk := newFakeClock()
	p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond, "b": 2 * time.Millisecond})
	p.set("b", 0, true)
	lazy := false
	g := newAuto(t, Options{Type: TypeFallback, Lazy: &lazy, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("a"), newFake("b")), clk, p, nil)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	p.set("b", 42*time.Millisecond, false)
	clk.Advance(12 * time.Second)
	waitRounds(t, g, 2)
	for _, m := range g.Snapshot().Members {
		if !m.ProbeOK {
			t.Fatal("startup member not recovered")
		}
	}
}
func TestR10StartupRetryNotForServerOrSuccessOrManual(t *testing.T) {
	for _, mode := range []string{"server", "success", "manual"} {
		t.Run(mode, func(t *testing.T) {
			clk := newFakeClock()
			p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond})
			p.set("a", time.Millisecond, mode != "success" && mode != "manual")
			lazy := mode == "manual"
			g := newAuto(t, Options{Type: TypeFallback, Lazy: &lazy, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: mode != "server"}}, members(newFake("a")), clk, p, nil)
			g.Start(context.Background())
			if mode == "manual" {
				waitRounds(t, g, 1)
				g.RecordProbe("a", 0, clk.Now(), errors.New("manual failed"))
			} else {
				waitRounds(t, g, 1)
			}
			if mode == "server" {
				if g.st[0].probeOK || !g.st[0].probed {
					t.Fatal("server fallback probe failure not recorded")
				}
			}
			before := g.roundsRun.Load()
			clk.Advance(15 * time.Second)
			time.Sleep(5 * time.Millisecond)
			if g.roundsRun.Load() != before {
				t.Fatal("unwanted retry")
			}
		})
	}
}
func TestR10StartupRetryCanceledByCloseOrParent(t *testing.T) {
	for _, closeGroup := range []bool{true, false} {
		t.Run(map[bool]string{true: "close", false: "parent"}[closeGroup], func(t *testing.T) {
			clk := newFakeClock()
			p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond})
			p.set("a", 0, true)
			lazy := false
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			g := newAuto(t, Options{Type: TypeFallback, Lazy: &lazy, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("a")), clk, p, nil)
			g.Start(ctx)
			waitRounds(t, g, 1)
			if closeGroup {
				g.Close()
			} else {
				cancel()
			}
			clk.Advance(15 * time.Second)
			time.Sleep(5 * time.Millisecond)
			if g.roundsRun.Load() != 1 {
				t.Fatal("retry survived lifecycle")
			}
		})
	}
}

func TestR11ClientLazyHasStartupAndTouchedPeriodicChecks(t *testing.T) {
	clk := newFakeClock()
	p := newFakeProbe(map[string]time.Duration{"a": 80 * time.Millisecond, "b": 20 * time.Millisecond})
	g := newAuto(t, Options{Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true, Interval: outbound.Duration(time.Second)}}, members(newFake("a"), newFake("b")), clk, p, nil)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	if g.Current() != "b" {
		t.Fatal("lazy client skipped startup")
	}
	clk.Advance(time.Second)
	if p.count("a") != 1 {
		t.Fatal("idle lazy did not skip tick")
	}
	g.mu.Lock()
	g.useLocked(clk.Now())
	g.unlock()
	waitRounds(t, g, 2)
	p.set("a", time.Millisecond, false)
	clk.Advance(900 * time.Millisecond)
	g.mu.Lock()
	g.useLocked(clk.Now())
	g.unlock()
	clk.Advance(100 * time.Millisecond)
	waitRounds(t, g, 3)
	if snapMember(g, "a").ProbeLatency != time.Millisecond || g.Current() != "b" {
		t.Fatal("touched lazy did not refresh sample or violated 20ms tolerance")
	}
}
func TestR11ClientSameURLLatestSampleSelectsAndDifferentURLIgnored(t *testing.T) {
	clk := newFakeClock()
	p := newFakeProbe(map[string]time.Duration{"a": 80 * time.Millisecond, "b": 100 * time.Millisecond})
	g := newAuto(t, Options{Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("a"), newFake("b")), clk, p, nil)
	g.Start(context.Background())
	waitRounds(t, g, 1)
	sample := ProbeSample{Name: "b", Latency: 20 * time.Millisecond, At: clk.Now().Add(time.Second)}
	g.RecordURLProbe("http://other.test/", sample)
	if g.Current() != "a" {
		t.Fatal("foreign URL used")
	}
	g.RecordURLProbe("http://probe.test/", sample)
	if snapMember(g, "b").ProbeLatency != 20*time.Millisecond || g.Current() != "b" {
		t.Fatal("same URL sample missing or did not select faster member")
	}
	g.RecordURLProbe("http://probe.test/", ProbeSample{Name: "b", Latency: 200 * time.Millisecond, At: clk.Now()})
	if snapMember(g, "b").ProbeLatency != 20*time.Millisecond || g.Current() != "b" {
		t.Fatal("stale sample replaced newest")
	}
}
func TestR11URLTestDefaultToleranceSameOnDesktopAndServer(t *testing.T) {
	for _, client := range []bool{false, true} {
		g := newAuto(t, Options{Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: client}}, members(newFake("a"), newFake("b")), newFakeClock(), nil, nil)
		want := 20 * time.Millisecond // Current URLTest default is identical on both runtimes
		if g.cfg.tolerance != want {
			t.Fatal(g.cfg.tolerance, want)
		}
	}
}
func TestR11NestedClientHealthEmptyFailedAndRecovery(t *testing.T) {
	clk := newFakeClock()
	p := newFakeProbe(map[string]time.Duration{"a": time.Millisecond})
	inner := newAuto(t, Options{Name: "inner", Type: TypeURLTest, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, members(newFake("a")), clk, p, nil)
	inner.Start(context.Background())
	waitRounds(t, inner, 1)
	empty, e := New(Options{Name: "empty", Type: TypeURLTest, IncludeAll: true, Probe: &ProbeOptions{URL: "http://probe.test/"}}, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	g := newAuto(t, Options{Type: TypeFallback, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: true}}, []outbound.Outbound{empty, inner, newFake("last")}, clk, newFakeProbe(map[string]time.Duration{"last": time.Millisecond}), nil)
	if g.Current() != "inner" {
		t.Fatal("empty considered healthy")
	}
	inner.RecordURLProbe("http://probe.test/", ProbeSample{Name: "a", At: clk.Now().Add(time.Second), Err: outbound.ErrRejected})
	if g.Current() != "last" {
		t.Fatal("failed inner group considered healthy")
	}
	inner.RecordURLProbe("http://probe.test/", ProbeSample{Name: "a", Latency: time.Millisecond, At: clk.Now().Add(2 * time.Second)})
	if g.Current() != "inner" {
		t.Fatal("nested recovery did not restore fallback order")
	}
}
