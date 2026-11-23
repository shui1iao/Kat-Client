package kernel

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/group"
)

func (s *Server) prepareManualProbe(ctx context.Context, name string) error {
	return s.prepareProbeDependencies(ctx, s.rt, name, false)
}

// Manual and progressive background probes have different readiness contracts.
// Scope flights to both the captured generation and the caller's readiness mode.
type probeDepKey struct {
	name       string
	background bool
}
type depFlight struct {
	done      chan struct{}
	err       error
	abandoned bool
}
type probeDependencies struct {
	outs    map[string]outbound.Options
	groups  map[string]group.Options
	mu      sync.Mutex
	flights map[probeDepKey]*depFlight
	// Only optional sibling workers use this budget. Never require a worker or
	// a network slot to descend, or parents could starve a cold child's round.
	workers chan struct{}
}

const probeDepWorkers = 8

func newProbeDependencies(outs map[string]outbound.Options, groups map[string]group.Options) *probeDependencies {
	return &probeDependencies{outs: outs, groups: groups, flights: make(map[probeDepKey]*depFlight), workers: make(chan struct{}, probeDepWorkers)}
}
func (p *probeDependencies) share(ctx context.Context, k probeDepKey, do func() error) error {
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		p.mu.Lock()
		f := p.flights[k]
		if f != nil {
			p.mu.Unlock()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-f.done:
			}
			if f.abandoned {
				continue
			}
			return f.err
		}
		f = &depFlight{done: make(chan struct{})}
		p.flights[k] = f
		p.mu.Unlock()
		e := do()
		p.mu.Lock()
		f.err = e
		f.abandoned = ctx.Err() != nil && (errors.Is(e, context.DeadlineExceeded) || errors.Is(e, context.Canceled))
		delete(p.flights, k)
		close(f.done)
		p.mu.Unlock()
		return e
	}
}

// Generated graph is cycle-checked by config validation. One traversal per
// active target, using the generation's existing indexes; do not cache readiness
// after completion (select/fixed state can change between requests).
func (s *Server) prepareProbeDependencies(ctx context.Context, rt *routingRuntime, name string, background bool) error {
	if rt == nil || rt.probeDeps == nil {
		return errors.New("probe dependency graph unavailable")
	}
	p := rt.probeDeps
	var seen sync.Map // avoid re-walking a diamond even if its shared flight already completed
	var visit func(string) error
	visit = func(target string) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if s.superseded.Load() {
			return context.Canceled
		}
		if target == "" || target == "direct" || target == "reject" {
			return nil
		}
		if _, ok := seen.Load(target); ok {
			return nil
		}
		// The common leaf path is constant time, allocates no flight or goroutine.
		if o, ok := p.outs[target]; ok && (o.Via == "" || o.Via == "direct") {
			return nil
		}
		e := p.share(ctx, probeDepKey{target, background}, func() error {
			if o, ok := p.outs[target]; ok {
				return visit(o.Via)
			}
			g, ok := p.groups[target]
			node := rt.nodes[target]
			if !ok || node == nil {
				return errors.New("probe dependency unavailable")
			}
			members := g.Members
			if g.Type == group.TypeSelect {
				members = []string{node.(group.Group).Current()}
			} else if g.Fixed != "" {
				members = []string{g.Fixed}
			}
			if e := p.each(ctx, members, visit); e != nil {
				return e
			}
			if ready, ok := node.(interface{ WaitReady(context.Context) error }); ok {
				return ready.WaitReady(ctx)
			}
			return nil
		})
		if e == nil {
			seen.Store(target, struct{}{})
		}
		return e
	}
	return visit(name)
}

func (p *probeDependencies) each(ctx context.Context, members []string, visit func(string) error) error {
	var wg sync.WaitGroup
	var mu sync.Mutex
	first := len(members)
	var failure error
	run := func(i int, m string) {
		if e := visit(m); e != nil {
			mu.Lock()
			if i < first {
				first, failure = i, e
			}
			mu.Unlock()
		}
	}
	if len(members) == 0 {
		return nil
	}
	if len(members) == 1 {
		return visit(members[0])
	}
	var next atomic.Int64
	worker := func() {
		for ctx.Err() == nil {
			i := int(next.Add(1) - 1)
			if i >= len(members) {
				return
			}
			run(i, members[i])
		}
	}
	// A bounded set of workers drains the batch; do not launch a goroutine per edge.
schedule:
	for range min(probeDepWorkers, len(members)-1) {
		select {
		case p.workers <- struct{}{}:
			wg.Add(1)
			go func() { defer wg.Done(); defer func() { <-p.workers }(); worker() }()
		default:
			break schedule
		}
	}
	worker()
	wg.Wait()
	if e := ctx.Err(); e != nil {
		return e
	}
	return failure
}
