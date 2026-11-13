package kernel

import (
	"context"
	"net/netip"
	"time"

	"github.com/shui1iao/Kat/internal/outbound/group"
	"github.com/shui1iao/Kat/internal/route"
)

func (c *Config) previewRouteOptions(override *RoutingOptions) route.Options {
	if override == nil {
		return c.routeOptions()
	}
	cp := *c
	cp.Routing = override
	return cp.routeOptions()
}

// PreviewTarget evaluates target against the running generation using target-only
// rule projection, live loaded resource snapshots, kernel DNS when an IP rule
// requires resolution, and read-only policy group chain expansion.
func (s *Server) PreviewTarget(ctx context.Context, routing *RoutingOptions, target string) (route.TargetPreview, error) {
	if s == nil || (s.core != nil && s.core.ctx.Err() != nil) {
		return route.TargetPreview{}, ErrCoreNotRunning
	}
	g := s.current()
	if g.core != nil {
		if !g.tryRef() {
			return route.TargetPreview{}, ErrCoreNotRunning
		}
		defer g.unref()
	}
	opts := g.cfg.previewRouteOptions(routing)
	eng, err := g.router()
	if err != nil {
		return route.TargetPreview{}, &route.TargetPreviewError{Code: "invalid_rules", Message: "当前路由规则配置无效"}
	}
	if g.rt == nil {
		defer eng.Close()
	}
	timeout := g.cfg.Limits.DialTimeout.value()
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	resolve := func(rctx context.Context, host string) ([]netip.Addr, error) {
		dctx, cancel := context.WithTimeout(rctx, timeout)
		defer cancel()
		if g.core != nil {
			stop := context.AfterFunc(g.core.ctx, cancel)
			defer stop()
		}
		return g.lookup(dctx, host)
	}
	res, err := eng.PreviewTarget(ctx, opts, target, resolve)
	if err != nil {
		return route.TargetPreview{}, err
	}
	res.Chain = g.previewPolicyChain(res.Matched.Policy)
	return res, nil
}

// PreviewStoppedTarget evaluates target against a stopped configuration using
// local resource snapshots without starting background downloads or dialing.
func PreviewStoppedTarget(ctx context.Context, cfg Config, routing *RoutingOptions, target string) (route.TargetPreview, error) {
	if _, _, err := route.ParsePreviewTarget(target); err != nil {
		return route.TargetPreview{}, err
	}
	opts := cfg.previewRouteOptions(routing)
	eng, err := route.NewReadOnlyEngine(opts)
	if err != nil {
		return route.TargetPreview{}, &route.TargetPreviewError{Code: "invalid_rules", Message: "当前路由规则配置无效"}
	}
	defer eng.Close()
	res, err := eng.PreviewTarget(ctx, opts, target, nil)
	if err != nil {
		return route.TargetPreview{}, err
	}
	res.Chain = PreviewConfigPolicyChain(cfg, res.Matched.Policy)
	return res, nil
}

func (s *Server) previewPolicyChain(policy string) []string {
	if policy == "" {
		return []string{}
	}
	if policy == "direct" || policy == "reject" {
		return []string{policy}
	}
	if s.rt == nil {
		return PreviewConfigPolicyChain(s.cfg, policy)
	}
	byName := make(map[string]group.Group, len(s.rt.groups))
	for _, gr := range s.rt.groups {
		byName[gr.Name()] = gr
	}
	chain := []string{policy}
	seen := map[string]bool{policy: true}
	curr := policy
	for len(chain) <= len(s.rt.groups)+2 {
		gr, ok := byName[curr]
		if !ok {
			break
		}
		next := group.PreviewMember(gr)
		if next == "" || seen[next] {
			break
		}
		seen[next] = true
		chain = append(chain, next)
		curr = next
	}
	return chain
}

// PreviewConfigPolicyChain expands reliable static group selections from cfg.
func PreviewConfigPolicyChain(cfg Config, policy string) []string {
	if policy == "" {
		return []string{}
	}
	if policy == "direct" || policy == "reject" {
		return []string{policy}
	}
	groups := make(map[string]GroupConfig, len(cfg.Groups))
	for _, g := range cfg.Groups {
		groups[g.Name] = g
	}
	chain := []string{policy}
	seen := map[string]bool{policy: true}
	curr := policy
	for len(chain) <= len(cfg.Groups)+2 {
		g, ok := groups[curr]
		if !ok {
			break
		}
		next := ""
		switch g.Type {
		case group.TypeSelect:
			next = configuredDefault(g)
		case group.TypeURLTest, group.TypeFallback, group.TypeSmart, group.TypeLoadBalance:
			if g.Fixed != "" && contains(g.Members, g.Fixed) {
				next = g.Fixed
			}
		}
		if next == "" || seen[next] {
			break
		}
		seen[next] = true
		chain = append(chain, next)
		curr = next
	}
	return chain
}
