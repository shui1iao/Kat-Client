package group

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

type countingProbeOutbound struct {
	name     string
	target   string
	dials    atomic.Int32
	dialWait time.Duration
	onDial   func(ctx context.Context)
}

func (o *countingProbeOutbound) Name() string { return o.name }
func (o *countingProbeOutbound) Type() string { return "socks5" }
func (o *countingProbeOutbound) UDP() bool    { return false }
func (o *countingProbeOutbound) Close() error { return nil }
func (o *countingProbeOutbound) DialTCP(ctx context.Context, _ outbound.Addr) (net.Conn, error) {
	o.dials.Add(1)
	if o.onDial != nil {
		o.onDial(ctx)
	}
	if o.dialWait > 0 {
		t := time.NewTimer(o.dialWait)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", o.target)
}
func (o *countingProbeOutbound) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return nil, errors.New("unsupported")
}

type wrappedMember struct {
	outbound.Outbound
	groupTag string
}

func (w wrappedMember) Underlying() outbound.Outbound { return w.Outbound }

func TestDesktopProbeSingleflightAcrossWrappedGroupsAndColdWarmPropagation(t *testing.T) {
	var reqCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := reqCount.Add(1)
		if n == 1 {
			time.Sleep(45 * time.Millisecond)
		} else {
			time.Sleep(5 * time.Millisecond)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	base := &countingProbeOutbound{
		name:     "hk-01",
		target:   srv.Listener.Addr().String(),
		dialWait: 30 * time.Millisecond,
	}

	const callers = 6
	var wg sync.WaitGroup
	lats := make([]time.Duration, callers)
	colds := make([]time.Duration, callers)
	errs := make([]error, callers)

	startGate := make(chan struct{})
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			wrapped := wrappedMember{Outbound: base, groupTag: string(rune('A' + idx))}
			pm := &ProbeMeasurement{}
			ctx, cancel := context.WithTimeout(WithProbeMeasurement(context.Background(), pm), 5*time.Second)
			defer cancel()
			<-startGate
			lats[idx], errs[idx] = ProbeOutboundDelayWithStatus(ctx, wrapped, srv.URL+"/generate_204", true, "204")
			colds[idx] = pm.Cold
		}(i)
	}
	close(startGate)
	wg.Wait()

	if got := base.dials.Load(); got != 1 {
		t.Fatalf("expected exactly 1 underlying DialTCP across %d concurrent groups, got %d", callers, got)
	}
	for i := 0; i < callers; i++ {
		if errs[i] != nil {
			t.Fatalf("caller %d failed: %v", i, errs[i])
		}
		if colds[i] < 60*time.Millisecond {
			t.Fatalf("caller %d cold measurement not propagated: got %v", i, colds[i])
		}
		if lats[i] <= 0 || lats[i] >= colds[i] {
			t.Fatalf("caller %d warm unified latency %v expected < cold %v", i, lats[i], colds[i])
		}
		if lats[i] != lats[0] || colds[i] != colds[0] {
			t.Fatalf("caller %d got (%v, %v), want shared (%v, %v)", i, lats[i], colds[i], lats[0], colds[0])
		}
	}

	// Distinct outbound pointer with the same node name (e.g. a new Server generation) MUST NOT coalesce.
	gen2 := &countingProbeOutbound{name: "hk-01", target: srv.Listener.Addr().String(), dialWait: 40 * time.Millisecond}
	var genWG sync.WaitGroup
	genWG.Add(2)
	go func() {
		defer genWG.Done()
		_, _ = ProbeOutboundHead(context.Background(), wrappedMember{Outbound: base, groupTag: "g1"}, srv.URL+"/gen")
	}()
	go func() {
		defer genWG.Done()
		_, _ = ProbeOutboundHead(context.Background(), wrappedMember{Outbound: gen2, groupTag: "g2"}, srv.URL+"/gen")
	}()
	genWG.Wait()
	if gen2.dials.Load() != 1 {
		t.Fatalf("distinct generation outbound was wrongly coalesced: dials=%d", gen2.dials.Load())
	}
}

func TestDesktopProbeSingleflightCallerCancelIsolation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(90 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	dialEntered := make(chan struct{})
	var once sync.Once
	base := &countingProbeOutbound{
		name:     "sg-shared",
		target:   srv.Listener.Addr().String(),
		dialWait: 30 * time.Millisecond,
		onDial: func(context.Context) {
			once.Do(func() { close(dialEntered) })
		},
	}

	shortCtx, shortCancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer shortCancel()

	pm2 := &ProbeMeasurement{}
	ctx2, cancel2 := context.WithTimeout(WithProbeMeasurement(context.Background(), pm2), 3*time.Second)
	defer cancel2()
	pm3 := &ProbeMeasurement{}
	ctx3, cancel3 := context.WithTimeout(WithProbeMeasurement(context.Background(), pm3), 3*time.Second)
	defer cancel3()

	var (
		err1, err2, err3 error
		lat2, lat3       time.Duration
		wg               sync.WaitGroup
	)
	wg.Add(3)
	go func() {
		defer wg.Done()
		_, err1 = ProbeOutboundHead(shortCtx, wrappedMember{Outbound: base, groupTag: "short"}, srv.URL)
	}()
	<-dialEntered
	go func() {
		defer wg.Done()
		lat2, err2 = ProbeOutboundHead(ctx2, wrappedMember{Outbound: base, groupTag: "long2"}, srv.URL)
	}()
	go func() {
		defer wg.Done()
		lat3, err3 = ProbeOutboundHead(ctx3, wrappedMember{Outbound: base, groupTag: "long3"}, srv.URL)
	}()
	wg.Wait()

	if !errors.Is(err1, context.DeadlineExceeded) {
		t.Fatalf("short caller expected DeadlineExceeded, got %v", err1)
	}
	if err2 != nil || err3 != nil {
		t.Fatalf("surviving callers failed after peer cancel: err2=%v err3=%v", err2, err3)
	}
	if lat2 <= 0 || lat3 <= 0 || pm2.Cold <= 0 || pm3.Cold <= 0 {
		t.Fatalf("surviving callers missing measurements: lat2=%v lat3=%v cold2=%v cold3=%v", lat2, lat3, pm2.Cold, pm3.Cold)
	}
	if base.dials.Load() != 1 {
		t.Fatalf("expected 1 shared dial, got %d", base.dials.Load())
	}

	flightCanceled := make(chan struct{})
	blocking := &countingProbeOutbound{
		name:   "block-node",
		target: srv.Listener.Addr().String(),
		onDial: func(ctx context.Context) {
			<-ctx.Done()
			close(flightCanceled)
		},
	}
	cA, stopA := context.WithCancel(context.Background())
	cB, stopB := context.WithCancel(context.Background())
	var cancelWG sync.WaitGroup
	cancelWG.Add(2)
	go func() {
		defer cancelWG.Done()
		_, _ = ProbeOutboundHead(cA, wrappedMember{Outbound: blocking, groupTag: "A"}, srv.URL+"/all-cancel")
	}()
	go func() {
		defer cancelWG.Done()
		_, _ = ProbeOutboundHead(cB, wrappedMember{Outbound: blocking, groupTag: "B"}, srv.URL+"/all-cancel")
	}()
	time.Sleep(20 * time.Millisecond)
	stopA()
	select {
	case <-flightCanceled:
		t.Fatal("shared flight canceled prematurely while waiter B was still waiting")
	case <-time.After(25 * time.Millisecond):
	}
	stopB()
	select {
	case <-flightCanceled:
	case <-time.After(time.Second):
		t.Fatal("shared flight was not canceled after last waiter canceled")
	}
	cancelWG.Wait()
}

func TestMultipleAutoGroupsBackgroundProbeDeduplication(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(35 * time.Millisecond)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	sharedNode := &countingProbeOutbound{
		name:     "shared-leaf",
		target:   srv.Listener.Addr().String(),
		dialWait: 25 * time.Millisecond,
	}

	lazyFalse := false
	var groups []Group
	for i := 0; i < 5; i++ {
		g, err := New(Options{
			Name:    "auto-" + string(rune('1'+i)),
			Type:    TypeURLTest,
			Members: []string{"shared-leaf"},
			Lazy:    &lazyFalse,
			Probe: &ProbeOptions{
				URL:           srv.URL + "/generate_204",
				ClientHead:    true,
				ClientUnified: true,
			},
		}, []outbound.Outbound{wrappedMember{Outbound: sharedNode, groupTag: string(rune('1' + i))}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		groups = append(groups, g)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, g := range groups {
		g.Start(ctx)
		defer g.Close()
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		allProbed := true
		for _, g := range groups {
			snap := g.(Snapshotter).Snapshot()
			if len(snap.Members) != 1 || !snap.Members[0].Probed || !snap.Members[0].ProbeOK {
				allProbed = false
				break
			}
		}
		if allProbed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for 5 autoGroups to complete initial background probe")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := sharedNode.dials.Load(); got != 1 {
		t.Fatalf("expected 1 underlying DialTCP across 5 concurrent autoGroups, got %d", got)
	}
}

func TestSmartPartialBootstrapFollowedByFullRoundDoesNotPanic(t *testing.T) {
	a := &countingProbeOutbound{name: "node-a", target: "127.0.0.1:1"}
	b := &countingProbeOutbound{name: "node-b", target: "127.0.0.1:1"}
	g, err := New(Options{
		Name:    "smart-cold",
		Type:    TypeSmart,
		Members: []string{"node-a", "node-b"},
		Probe: &ProbeOptions{
			URL:        "http://127.0.0.1:1/generate_204",
			ClientHead: true,
		},
	}, []outbound.Outbound{a, b}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	rec := g.(interface{ RecordProbeRound([]ProbeSample) })
	now := time.Now()
	// Step 1: partial single-node sample unblocks cold Smart group and closes firstReady.
	rec.RecordProbeRound([]ProbeSample{{Name: "node-a", Latency: 20 * time.Millisecond, At: now}})
	if g.Current() != "node-a" {
		t.Fatalf("expected partial bootstrap to select node-a, got %q", g.Current())
	}
	// Step 2: subsequent full probe round calls markCompleteLocked() and must not double-close firstReady.
	rec.RecordProbeRound([]ProbeSample{
		{Name: "node-a", Latency: 22 * time.Millisecond, At: now.Add(time.Second)},
		{Name: "node-b", Latency: 12 * time.Millisecond, At: now.Add(time.Second)},
	})
}
