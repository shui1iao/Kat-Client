package kernel

import (
	"context"
	"github.com/shui1iao/Kat/internal/procattr"
	"net/netip"
)

var lookupApplication = procattr.Lookup

type udpProcessKey struct{}
type udpProcessTuple struct{ source, destination netip.AddrPort }

func processIdentity(ctx context.Context, network string, target Address) func() procattr.Identity {
	im := inboundMetaOf(ctx)
	if im == nil {
		return func() procattr.Identity { return procattr.Identity{Status: "unsupported"} }
	}
	originalTarget, _ := netip.ParseAddr(target.Host)
	var targetAP netip.AddrPort
	if originalTarget.IsValid() {
		targetAP = netip.AddrPortFrom(originalTarget.Unmap(), target.Port)
	}
	q := procattr.Query{Network: network, Source: im.remote, Destination: im.local, ControlSource: im.remote, ControlDestination: im.local, Target: targetAP}
	if network == "udp" {
		if udp, ok := ctx.Value(udpProcessKey{}).(udpProcessTuple); ok {
			q.Source, q.Destination = netip.AddrPortFrom(udp.source.Addr().Unmap(), udp.source.Port()), netip.AddrPortFrom(udp.destination.Addr().Unmap(), udp.destination.Port())
		} else {
			return func() procattr.Identity { return procattr.Identity{Status: "unsupported"} }
		}
	}
	return func() procattr.Identity {
		if network == "tcp" {
			im.process.once.Do(func() { im.process.identity = lookupApplication(ctx, q) })
			return im.process.identity
		}
		// UDP source ports can move to another live process while the control TCP
		// association stays open. Never reuse its previous positive attribution.
		id := lookupApplication(ctx, q)
		return id
	}
}

func processMetadata(ctx context.Context, network string, target Address) func() (string, string) {
	lookup := processIdentity(ctx, network, target)
	return func() (string, string) { id := lookup(); return id.Name, id.Status }
}
