package group

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestFallbackOrderPreference(t *testing.T) {
	clk := newFakeClock()
	a, b, c := newFake("a"), newFake("b"), newFake("c")
	p := newFakeProbe(map[string]time.Duration{"a": 400 * ms_, "b": 20 * ms_, "c": 10 * ms_})
	g := newAuto(t, Options{Type: TypeFallback}, members(a, b, c), clk, p, nil)
	g.Start(context.Background())
	if dial(t, g, "x.test") != "a" { // first use before results: first member
		t.Fatal("first use not on a")
	}
	waitRounds(t, g, 1)
	if g.Current() != "a" || dial(t, g, "x.test") != "a" {
		t.Fatalf("fallback must follow order, not latency: current %q", g.Current())
	}
}

func TestFallbackFirstFailsUsesSecond(t *testing.T) {
	clk := newFakeClock()
	a, b, c := newFake("a"), newFake("b"), newFake("c")
	p := newFakeProbe(map[string]time.Duration{"a": 10 * ms_, "b": 20 * ms_, "c": 30 * ms_})
	p.fail["a"] = true
	ev := &eventLog{}
	g := newAuto(t, Options{Type: TypeFallback}, members(a, b, c), clk, p, ev)
	g.Start(context.Background())
	dial(t, g, "x.test")
	waitRounds(t, g, 1)
	if g.Current() != "b" || dial(t, g, "x.test") != "b" {
		t.Fatalf("a failed its probe: current %q, want b", g.Current())
	}
	// Sparkle/mihomo semantics: transient dial failures while probe is still OK
	// do NOT convict b; only when health check also fails does c take over.
	b.setErr(errors.New("refused"))
	for range 5 {
		if got := dial(t, g, "x.test"); got != "c" {
			t.Fatalf("retry via %q", got)
		}
	}
	waitRounds(t, g, 2)
	if g.Current() != "b" {
		t.Fatalf("healthy probe was overridden by transient dial errors: %q", g.Current())
	}
	p.set("b", 0, true)
	clk.Advance(time.Second)
	for range 5 {
		dial(t, g, "x.test")
	}
	waitRounds(t, g, 3)
	if g.Current() != "c" {
		t.Fatalf("failed health check after dial failures: current %q, want c", g.Current())
	}
	if sw := switches(ev); len(sw) != 2 || sw[0] != "a>b" || sw[1] != "b>c" {
		t.Fatalf("switches %v", sw)
	}
}

func TestFallbackSwitchesBackWhenFirstRecovers(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{"a": 10 * ms_, "b": 20 * ms_})
	p.fail["a"] = true
	ev := &eventLog{}
	g := newAuto(t, Options{Type: TypeFallback}, members(a, b), clk, p, ev)
	g.Start(context.Background())
	dial(t, g, "x.test")
	waitRounds(t, g, 1)
	if g.Current() != "b" {
		t.Fatalf("current %q", g.Current())
	}
	p.set("a", 10*ms_, false) // a recovers; a single probe immediately restores order
	clk.Advance(11 * time.Minute)
	if got := dial(t, g, "x.test"); got != "b" { // round runs in background
		t.Fatalf("dial via %q", got)
	}
	waitRounds(t, g, 2)
	if g.Current() != "a" || dial(t, g, "x.test") != "a" {
		t.Fatalf("did not switch back to a immediately on probe success: %q", g.Current())
	}
	if sw := switches(ev); len(sw) != 2 || sw[1] != "b>a" {
		t.Fatalf("switches %v", sw)
	}
}

func TestFallbackAllDownUsesFirst(t *testing.T) {
	clk := newFakeClock()
	a, b := newFake("a"), newFake("b")
	p := newFakeProbe(map[string]time.Duration{})
	p.fail["a"], p.fail["b"] = true, true
	g := newAuto(t, Options{Type: TypeFallback}, members(a, b), clk, p, nil)
	g.Start(context.Background())
	dial(t, g, "x.test")
	waitRounds(t, g, 1)
	if g.Current() != "a" || dial(t, g, "x.test") != "a" {
		t.Fatalf("all down: current %q, want first member a", g.Current())
	}
}

func TestFallbackConcurrentFailuresDoNotInvalidateInFlightProbe(t *testing.T) {
	for _, clientHead := range []bool{false, true} {
		t.Run(map[bool]string{false: "server", true: "desktop"}[clientHead], func(t *testing.T) {
			clk := newFakeClock()
			a, b := newFake("a"), newFake("b")
			p := newFakeProbe(map[string]time.Duration{"a": 10 * ms_, "b": 20 * ms_})
			lazy := true
			g := newAuto(t, Options{Type: TypeFallback, Lazy: &lazy, Probe: &ProbeOptions{URL: "http://probe.test/", ClientHead: clientHead}}, members(a, b), clk, p, nil)
			g.Start(context.Background())
			if clientHead {
				waitRounds(t, g, 1)
			} else {
				probeNow(t, g)
			}
			if g.Current() != "a" {
				t.Fatalf("initial current %q, want a", g.Current())
			}
			// Make A fail probes and block the probe round mid-flight.
			p.set("a", 0, true)
			p.block = make(chan struct{})
			a.setErr(errors.New("dial timeout"))
			clk.Advance(time.Second)
			for range 5 {
				dial(t, g, "x.test")
			}
			deadline := time.Now().Add(time.Second)
			for !isProbing(g) {
				if time.Now().After(deadline) {
					t.Fatal("health check round was not started")
				}
				time.Sleep(time.Millisecond)
			}
			// While the probe round is in flight, additional business failures occur!
			clk.Advance(50 * ms_)
			dial(t, g, "x.test")
			dial(t, g, "x.test")
			clk.Advance(50 * ms_)
			close(p.block)
			waitRounds(t, g, 2)
			g.mu.Lock()
			probed, ok, recPending := g.st[0].probed, g.st[0].probeOK, g.st[0].recoveryStop != nil
			g.mu.Unlock()
			if g.Current() != "b" || !probed || ok || !recPending {
				t.Fatalf("in-flight probe invalidated by concurrent failure: current=%q probed=%v probeOK=%v recoveryPending=%v", g.Current(), probed, ok, recPending)
			}
		})
	}
}
