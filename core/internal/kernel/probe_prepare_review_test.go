package kernel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestReviewProbePreparationWorkersBoundedAndShareBudget(t *testing.T) {
	p := newProbeDependencies(nil, nil)
	var started atomic.Int32
	gate := make(chan struct{})
	entered := make(chan struct{}, probeDepWorkers+1)
	done := make(chan error, 1)
	members := make([]string, 128)
	go func() {
		done <- p.each(context.Background(), members, func(_ string) error {
			if int(started.Add(1)) <= cap(entered) {
				entered <- struct{}{}
			}
			<-gate
			return nil
		})
	}()
	for range cap(entered) {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			close(gate)
			t.Fatal("independent preparation serialized")
		}
	}
	if got := len(p.workers); got != probeDepWorkers {
		close(gate)
		t.Fatalf("workers=%d", got)
	}
	// Same generation, no remaining worker slots. A second caller can still make
	// progress inline: a cold parent's readiness must not starve nested rounds.
	if e := p.each(context.Background(), []string{"a", "b"}, func(string) error { return nil }); e != nil {
		close(gate)
		t.Fatal(e)
	}
	close(gate)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if int(started.Load()) != len(members) || len(p.workers) != 0 {
		t.Fatal("batch incomplete")
	}
}

// Cancel a waiting consumer without canceling the shared leader. Synced via
// ctx.Done() observation rather than timing the entry into the flight.
type reviewProbeWaiting struct {
	context.Context
	entered chan struct{}
}

func (c reviewProbeWaiting) Done() <-chan struct{} {
	select {
	case c.entered <- struct{}{}:
	default:
	}
	return c.Context.Done()
}
func TestReviewProbeFlightsScopedAndCancellation(t *testing.T) {
	p := newProbeDependencies(nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	k := probeDepKey{"x", true}
	leader := make(chan struct{})
	ended := make(chan error, 1)
	go func() { ended <- p.share(ctx, k, func() error { close(leader); <-ctx.Done(); return ctx.Err() }) }()
	<-leader
	wc, stop := context.WithCancel(context.Background())
	entered := make(chan struct{}, 1)
	result := make(chan error, 1)
	go func() {
		result <- p.share(reviewProbeWaiting{wc, entered}, k, func() error { return errors.New("unexpected duplicate") })
	}()
	<-entered
	stop()
	if e := <-result; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	// The other readiness class cannot inherit a progressive result.
	if e := p.share(context.Background(), probeDepKey{"x", false}, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	next := make(chan struct{})
	go func() {
		result <- p.share(reviewProbeWaiting{context.Background(), entered}, k, func() error { close(next); return nil })
	}()
	<-entered
	cancel()
	if e := <-ended; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e := <-result; e != nil {
		t.Fatal(e)
	}
	<-next
}
