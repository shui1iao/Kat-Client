package kernel

import (
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
