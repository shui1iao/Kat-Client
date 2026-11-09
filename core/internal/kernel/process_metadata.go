package kernel

import (
	"context"
	"github.com/shui1iao/Kat/internal/procattr"
	"net/netip"
	"sync"
)

var lookupApplication = procattr.Lookup
var lookupTUNApplication = procattr.LookupTuple

type udpProcessKey struct{}
type udpProcessTuple struct{ source, destination netip.AddrPort }

func processQuery(ctx context.Context, network string, target Address) (procattr.Query, bool) {
	if t, ok := tunFlowOf(ctx); ok {
		// The packet/flow context is authoritative. A sniffed, rewritten or
		// resolved rule target must never replace a TCP owner's remote tuple.
		// UDP's packetContext supplies that datagram's actual destination.
		return procattr.Query{Network: network, Source: t.Source, Destination: t.Destination, Target: t.Destination}, true
	}
	target = originalTarget(ctx, target)
	im := inboundMetaOf(ctx)
	if im == nil {
		return procattr.Query{}, false
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
			return procattr.Query{}, false
		}
	}
	return q, true
}

type packetProcessKey struct{}
type packetProcess struct {
	once sync.Once
	id   procattr.Identity
}

func processIdentity(ctx context.Context, network string, target Address) func() procattr.Identity {
	q, ok := processQuery(ctx, network, target)
	if !ok {
		return func() procattr.Identity {
			return procattr.Identity{Status: "unsupported", Cause: "process:unsupported"}
		}
	}
	im := inboundMetaOf(ctx)
	lookup := lookupApplication
	_, tun := tunFlowOf(ctx)
	if tun {
		lookup = lookupTUNApplication
	}
	return func() procattr.Identity {
		if tun && ctx.Err() != nil {
			return procattr.Identity{Status: "unknown", Cause: "process:unknown"}
		}
		var id procattr.Identity
		if network == "tcp" && im != nil && im.process != nil {
			// Only the accepted connection owns a TCP lifetime cache.
			im.process.once.Do(func() { im.process.identity = lookup(ctx, q) })
			id = im.process.identity
		} else if p, ok := ctx.Value(packetProcessKey{}).(*packetProcess); network != "tcp" && ok && p != nil {
			// Rule and display can share this datagram's proof, never a
			// previous packet's positive on a long-lived UDP association.
			p.once.Do(func() { p.id = lookup(ctx, q) })
			id = p.id
		} else {
			// A bare TUN context without accepted metadata has no lifetime
			// cache; neither TCP nor UDP may fall back to proxy attribution.
			id = lookup(ctx, q)
		}
		if tun && ctx.Err() != nil {
			return procattr.Identity{Status: "unknown", Cause: "process:unknown"}
		}
		return id
	}
}

func processAttribution(ctx context.Context, network string, target Address) (func() (string, string), func() (string, uint32)) {
	lookup := processIdentity(ctx, network, target)
	var identity procattr.Identity
	return func() (string, string) {
			identity = lookup()
			if identity.Status != "known" && identity.Cause == "" {
				if identity.Status == "denied" {
					identity.Cause = "local_denied"
				} else {
					identity.Cause = procattr.SafeCause("process:" + identity.Status)
				}
			}
			return identity.Name, identity.Status
		}, func() (string, uint32) {
			if identity.Status == "known" {
				return "", 0
			}
			return procattr.SafeCause(identity.Cause), identity.Win32
		}
}
func processMetadata(ctx context.Context, network string, target Address) func() (string, string) {
	lookup, _ := processAttribution(ctx, network, target)
	return lookup
}
