package kernel

import (
	"context"
	"github.com/shui1iao/Kat/internal/route"
	"net/netip"
)

// OfflineRuleView retains the target-only internal entry point.
func (s *Server) OfflineRuleView(routing *RoutingOptions, input string) (route.OfflineResult, error) {
	return s.OfflineRuleViewWithContext(routing, route.OfflineInput{Target: input})
}

// Only hand-supplied metadata is consumed. No Decide, resolver, attribution,
// dial, selection or accounting callback is reachable from this API.
func (s *Server) OfflineRuleViewWithContext(routing *RoutingOptions, in route.OfflineInput) (route.OfflineResult, error) {
	g := s.current()
	if !g.tryRef() {
		return route.OfflineResult{}, ErrCoreNotRunning
	}
	defer g.unref()
	if g.rt == nil || g.rt.engine == nil {
		return route.OfflineResult{}, ErrCoreNotRunning
	}
	c := g.cfg
	c.Routing = routing
	out, err := g.rt.engine.OfflineWithContext(c.routeOptions(), in)
	if err == nil && g.cfg.IPv6Disabled() {
		if ip, e := netip.ParseAddr(out.Known.IP); e == nil && ip.Is6() {
			out.AdmissionWarnings = []string{"ipv6_disabled"}
		}
	}
	return out, err
}

// TargetRuleViewWithContext performs target-only rule matching. Its only
// network-capable callback is the pinned generation's ordinary rule DNS
// resolver; no target dial, process lookup, outbound selection or accounting
// path is reachable.
func (s *Server) TargetRuleViewWithContext(ctx context.Context, routing *RoutingOptions, in route.OfflineInput) (route.TargetResult, error) {
	g := s.current()
	if !g.tryRef() {
		return route.TargetResult{}, ErrCoreNotRunning
	}
	defer g.unref()
	if g.rt == nil || g.rt.engine == nil {
		return route.TargetResult{}, ErrCoreNotRunning
	}
	ctx, cancel := context.WithTimeout(ctx, g.cfg.Limits.DialTimeout.value())
	defer cancel()
	stop := context.AfterFunc(g.core.ctx, cancel)
	defer stop()
	c := g.cfg
	c.Routing = routing
	out, err := g.rt.engine.TestTarget(ctx, c.routeOptions(), in, g.lookup)
	if err == nil && g.cfg.IPv6Disabled() {
		if ip, e := netip.ParseAddr(out.Known.IP); e == nil && ip.Is6() {
			out.AdmissionWarnings = []string{"ipv6_disabled"}
		}
	}
	return out, err
}
