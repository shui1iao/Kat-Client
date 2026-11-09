package outbound

import "context"

type endpointIndependentKey struct{}

// WithEndpointIndependent is private in-process plumbing for the TUN raw UDP
// adapter. It is not configuration, a proxy header, or a public management API.
func WithEndpointIndependent(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, endpointIndependentKey{}, enabled)
}
func EndpointIndependent(ctx context.Context) bool {
	v, _ := ctx.Value(endpointIndependentKey{}).(bool)
	return v
}
