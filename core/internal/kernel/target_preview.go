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

func validateConfigGroupDepth(groups []GroupConfig) error {
	if len(groups) == 0 {
		return nil
	}
	byName := make(map[string]GroupConfig, len(groups))
	for _, g := range groups {
		byName[g.Name] = g
	}
	color := make(map[string]uint8, len(groups))
	depth := make(map[string]int, len(groups))
	var visit func(string) error
	visit = func(name string) error {
		switch color[name] {
		case 1:
			return group.ErrGroupDepthExceeded
		case 2:
			return nil
		}
		g, ok := byName[name]
		if !ok {
			return nil
		}
		color[name] = 1
		d := 0
		if g.IncludeGroup != "" {
			if _, isGrp := byName[g.IncludeGroup]; isGrp {
				if err := visit(g.IncludeGroup); err != nil {
					return err
				}
				d = max(d, depth[g.IncludeGroup])
			}
		}
		for _, m := range g.Members {
			if _, isGrp := byName[m]; isGrp {
				if err := visit(m); err != nil {
					return err
				}
				d = max(d, depth[m])
			}
		}
		d++
		if d > group.MaxGroupDepth {
			return group.ErrGroupDepthExceeded
		}
		depth[name] = d
		color[name] = 2
		return nil
	}
	for _, g := range groups {
		if err := visit(g.Name); err != nil {
			return err
		}
	}
	return nil
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
	if err := validateConfigGroupDepth(g.cfg.Groups); err != nil {
		return route.TargetPreview{}, &route.TargetPreviewError{Code: "invalid_rules", Message: "当前策略组嵌套层级超过上限"}
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
	chain, err := g.expandPolicyChainChecked(res.Matched.Policy)
	if err != nil {
		return route.TargetPreview{}, &route.TargetPreviewError{Code: "invalid_rules", Message: "当前策略组配置无效"}
	}
	res.Chain = chain
	return res, nil
}

// PreviewStoppedTarget evaluates target against a stopped configuration using
// local resource snapshots without starting background downloads or dialing.
func PreviewStoppedTarget(ctx context.Context, cfg Config, routing *RoutingOptions, target string) (route.TargetPreview, error) {
	if _, _, err := route.ParsePreviewTarget(target); err != nil {
		return route.TargetPreview{}, err
	}
	if err := validateConfigGroupDepth(cfg.Groups); err != nil {
		return route.TargetPreview{}, &route.TargetPreviewError{Code: "invalid_rules", Message: "当前策略组嵌套层级超过上限"}
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
	chain, err := expandConfigPolicyChainChecked(cfg, res.Matched.Policy)
	if err != nil {
		return route.TargetPreview{}, &route.TargetPreviewError{Code: "invalid_rules", Message: "当前策略组配置无效"}
	}
	res.Chain = chain
	return res, nil
}

func (s *Server) expandPolicyChainChecked(policy string) ([]string, error) {
	if s.rt == nil {
		return expandConfigPolicyChainChecked(s.cfg, policy)
	}
	byName := make(map[string]group.Group, len(s.rt.groups))
	for _, gr := range s.rt.groups {
		byName[gr.Name()] = gr
	}
	return group.ExpandPolicyChain(policy, func(name string) (string, bool) {
		gr, ok := byName[name]
		if !ok {
			return "", false
		}
		return group.PreviewMember(gr), true
	})
}

func (s *Server) previewPolicyChain(policy string) []string {
	chain, err := s.expandPolicyChainChecked(policy)
	if err != nil {
		if policy == "" {
			return []string{}
		}
		return []string{policy}
	}
	return chain
}

func expandConfigPolicyChainChecked(cfg Config, policy string) ([]string, error) {
	groups := make(map[string]GroupConfig, len(cfg.Groups))
	for _, g := range cfg.Groups {
		groups[g.Name] = g
	}
	return group.ExpandPolicyChain(policy, func(name string) (string, bool) {
		g, ok := groups[name]
		if !ok {
			return "", false
		}
		return group.PreviewStaticMember(group.Options(g)), true
	})
}

// PreviewConfigPolicyChain expands reliable static group selections from cfg.
func PreviewConfigPolicyChain(cfg Config, policy string) []string {
	chain, err := expandConfigPolicyChainChecked(cfg, policy)
	if err != nil {
		if policy == "" {
			return []string{}
		}
		return []string{policy}
	}
	return chain
}
