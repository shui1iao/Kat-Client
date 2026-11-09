package kernel

import "context"

func (r *internalDNS) dnsScope(ctx context.Context) (context.Context, func(), uint64) {
	if r.dnsContext != nil {
		return r.dnsContext(ctx)
	}
	return ctx, func() {}, 0
}
func (r *internalDNS) dnsEpoch() uint64 {
	_, cancel, epoch := r.dnsScope(context.Background())
	cancel()
	return epoch
}
func (r *internalDNS) bindDNSRevision(scope func(context.Context) (context.Context, func(), uint64)) {
	if r == nil {
		return
	}
	r.dnsContext = scope
	for _, p := range r.rules {
		p.resolver.bindDNSRevision(scope)
	}
}
