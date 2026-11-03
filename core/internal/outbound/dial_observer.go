package outbound

import (
	"context"
	"net/netip"
)

type dialObserverKey struct{}
type DialObserver func([]netip.Addr, netip.Addr)

func WithDialObserver(ctx context.Context, fn DialObserver) context.Context {
	return context.WithValue(ctx, dialObserverKey{}, fn)
}
func ObserveDial(ctx context.Context, ips []netip.Addr, chosen netip.Addr) {
	if fn, _ := ctx.Value(dialObserverKey{}).(DialObserver); fn != nil {
		fn(ips, chosen)
	}
}
