package outbound

import (
	"context"
	"net/netip"
	"strings"
)

// Public-target scope applies only to the ultimate target of a subscription
// download/probe. An explicitly configured proxy resolves its targets remotely;
// the local socket can vouch only for a Direct leaf's actual destination.
type publicTargetKey struct{}

func WithPublicTarget(ctx context.Context) context.Context {
	return context.WithValue(ctx, publicTargetKey{}, true)
}
func PublicTargetOnly(ctx context.Context) bool {
	v, _ := ctx.Value(publicTargetKey{}).(bool)
	return v
}
func CarrierTargetContext(ctx context.Context) context.Context {
	if !PublicTargetOnly(ctx) {
		return ctx
	}
	return context.WithValue(ctx, publicTargetKey{}, false)
}
func PublicTargetCandidatesOK(ctx context.Context, ips []netip.Addr) bool {
	if !PublicTargetOnly(ctx) {
		return true
	}
	if len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !PublicTargetIP(ip) {
			return false
		}
	}
	return true
}

var importReserved = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range strings.Fields("0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/3 2001::/23 2001:db8::/32 2002::/16 3fff::/20") {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func PublicTargetIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, p := range importReserved {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
