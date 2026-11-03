package procattr

import (
	"context"
	"runtime"
	"strings"
)

func FlowOrigin(ctx context.Context, q Query) (string, string) {
	httpFlows.Lock()
	o := httpFlows.m[key{q.ControlSource, q.ControlDestination}]
	httpFlows.Unlock()
	if o != nil && q.ControlSource.IsValid() && q.ControlDestination.IsValid() {
		return o.query.Source.String(), "system_proxy"
	}
	id := Lookup(ctx, q)
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
