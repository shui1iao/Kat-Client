package kernel

import (
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/route"
)

func (s *Server) ResourceViews() []route.ResourceView {
	g := s.current()
	if !g.tryRef() {
		return []route.ResourceView{}
	}
	defer g.unref()
	return g.rt.engine.Resources()
}
func (s *Server) RefreshResource(ctx context.Context, kind, name string) error {
	return s.RefreshResourceWithReader(ctx, kind, name, nil, 0)
}

func (s *Server) RefreshResourceWithReader(ctx context.Context, kind, name string, read func(string, int64) ([]byte, error), expectedGeneration uint64) error {
	if s.ctx.Err() != nil {
		return ErrCoreNotRunning
	}
	g := s.current()
	if expectedGeneration != 0 && g.id != expectedGeneration {
		return route.ErrResourceRefresh
	}
	if !g.tryRef() {
		return ErrCoreNotRunning
	}
	defer g.unref()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	return g.rt.engine.RefreshResourceWith(ctx, kind, name, read, func(publish func() error) error {
		// Serialize only publication with generation commit, never network I/O.
		s.core.bindMu.RLock()
		defer s.core.bindMu.RUnlock()
		if s.core.gen.Load() != g || ctx.Err() != nil {
			return route.ErrResourceRefresh
		}
		return publish()
	})
}

// A single immutable resource version uses the normal reload transaction, but
// must not publish a silently failed local parse or a stale source generation.
type resourceChangeCheck struct {
	previous   *route.Engine
	kind, name string
	generation uint64
}

func (s *Server) ApplyResourceConfigContext(ctx context.Context, c Config, kind, name string, generation uint64) (ReloadResult, error) {
	c.resourceChange = &resourceChangeCheck{kind: kind, name: name, generation: generation}
	if len(c.raw) == 0 {
		b, err := json.Marshal(c)
		if err != nil {
			return ReloadResult{}, err
		}
		c.raw = b
	}
	// No file-provider re-read or node/provider mutation for a resource click.
	return s.reloadCandidateContext(ctx, "client", false, &c)
}

func (g *Server) checkResourceChange(prev *Server, check *resourceChangeCheck) error {
	if prev == nil || prev.id != check.generation {
		return route.ErrResourceRefresh
	}
	before := map[string]bool{}
	for _, v := range prev.rt.engine.Resources() {
		// A failed last refresh changes State, but can still retain loaded data.
		before[v.Kind+":"+v.Name] = v.SizeBytes != nil
	}
	found := false
	for _, v := range g.rt.engine.Resources() {
		if v.Kind == check.kind && v.Name == check.name {
			if v.State != "ok" {
				return route.ErrResourceRefresh
			}
			found = true
		}
		if before[v.Kind+":"+v.Name] && v.SizeBytes == nil {
			return route.ErrResourceRefresh
		}
	}
	if !found {
		return route.ErrResourceRefresh
	}
	return nil
}

func (s *Server) DownloadResource(ctx context.Context, kind, name string, expectedGeneration uint64) ([]byte, error) {
	g := s.current()
	if g.id != expectedGeneration {
		return nil, route.ErrResourceRefresh
	}
	if !g.tryRef() {
		return nil, ErrCoreNotRunning
	}
	defer g.unref()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	return g.rt.engine.DownloadResource(ctx, kind, name)
}
