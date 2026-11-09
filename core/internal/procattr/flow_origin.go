package procattr

import (
	"context"
	"runtime"
	"strings"
)

// HTTPFlowOrigin is metadata-only: it never performs process lookup or IPC.
func HTTPFlowOrigin(q Query) (string, string, bool) {
	httpFlows.Lock()
	o := httpFlows.m[key{q.ControlSource, q.ControlDestination}]
	httpFlows.Unlock()
	if o != nil && q.ControlSource.IsValid() && q.ControlDestination.IsValid() {
		return o.query.Source.String(), "system_proxy", true
	}
	return "", "", false
}
func FlowOrigin(ctx context.Context, q Query) (string, string) {
	if source, kind, ok := HTTPFlowOrigin(q); ok {
		return source, kind
	}
	return OriginFromIdentity(q, Lookup(ctx, q))
}

// OriginFromIdentity uses the SAME proof the routing decision already uses.
// It deliberately does not call Lookup (especially not for a UDP display).
func OriginFromIdentity(q Query, id Identity) (string, string) {
	httpFlows.Lock()
	o := httpFlows.m[key{q.ControlSource, q.ControlDestination}]
	httpFlows.Unlock()
	if o != nil && q.ControlSource.IsValid() && q.ControlDestination.IsValid() {
		return o.query.Source.String(), "system_proxy"
	}
	if id.InboundKind != "" {
		return id.SourceAddr, id.InboundKind
	}
	if runtime.GOOS == "windows" && id.Status != "known" {
		return "", ""
	}
	if id.Status == "denied" || id.Status == "unknown" || strings.EqualFold(id.Name, "tun2socks.exe") {
		return "", ""
	}
	if q.Source.IsValid() {
		return q.Source.String(), ""
	}
	return "", ""
}
