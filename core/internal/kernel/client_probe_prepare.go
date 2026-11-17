package kernel

import (
	"context"
	"errors"
	"sync"

	"github.com/shui1iao/Kat/internal/outbound/group"
)

// prepareManualProbe waits for the same first URLTest/Smart readiness that a real
// dial would await. It does not dial the target, override fixed/selected members,
// or change any group's probe policy.
func (s *Server) prepareManualProbe(ctx context.Context, name string) error {
	return s.prepareProbeDependencies(ctx, s.rt, name)
}

type depFlight struct {
	done chan struct{}
	err  error
}

// Both probe paths resolve the captured generation's expanded dependency graph.
// Independent child dependencies warm concurrently with singleflight deduplication.
func (s *Server) prepareProbeDependencies(ctx context.Context, rt *routingRuntime, name string) error {
	outs := make(map[string]OutboundConfig, len(s.cfg.Outbounds))
	groups := make(map[string]GroupConfig, len(s.cfg.Groups))
	for _, o := range s.cfg.Outbounds {
		outs[o.Name] = o
	}
	for _, g := range s.cfg.Groups {
		groups[g.Name] = g
	}

	var mu sync.Mutex
	flights := make(map[string]*depFlight)

	var prepare func(string, map[string]bool) error
	prepare = func(target string, stack map[string]bool) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if s.superseded.Load() {
			return context.Canceled
		}
		if target == "" || target == "direct" || target == "reject" || stack[target] {
			return nil
		}

		mu.Lock()
		if f, ok := flights[target]; ok {
			mu.Unlock()
			select {
			case <-f.done:
				return f.err
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		f := &depFlight{done: make(chan struct{})}
		flights[target] = f
		mu.Unlock()

		nextStack := make(map[string]bool, len(stack)+1)
		for k := range stack {
			nextStack[k] = true
		}
		nextStack[target] = true

		err := func() error {
			if o, ok := outs[target]; ok {
				return prepare(o.Via, nextStack)
			}
			cfg, ok := groups[target]
			if !ok {
				return errors.New("probe dependency unavailable")
			}
			node := rt.nodes[target]
			if node == nil {
				return errors.New("probe dependency unavailable")
			}
			members := cfg.Members
			if cfg.Type == group.TypeSelect {
				members = []string{node.(group.Group).Current()}
			} else if cfg.Fixed != "" {
				members = []string{cfg.Fixed}
			}
			if len(members) == 1 {
				if e := prepare(members[0], nextStack); e != nil {
					return e
				}
			} else if len(members) > 1 {
				errs := make([]error, len(members))
				var wg sync.WaitGroup
				wg.Add(len(members))
				for idx, m := range members {
					go func(i int, memberName string) {
						defer wg.Done()
						errs[i] = prepare(memberName, nextStack)
					}(idx, m)
				}
				wg.Wait()
				for _, e := range errs {
					if e != nil {
						return e
					}
				}
			}
			if ready, ok := node.(interface{ WaitReady(context.Context) error }); ok {
				return ready.WaitReady(ctx)
			}
			return nil
		}()

		f.err = err
		close(f.done)
		return err
	}

	return prepare(name, nil)
}
