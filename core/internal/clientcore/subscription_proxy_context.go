package clientcore

import "context"

// Native reads the current egress under its short operation lock. The core
// atomically checks that exact generation before admitting a bootstrap request.
type bootstrapEgress struct {
	Generation uint64 `json:"generation"`
	Enabled    bool   `json:"enabled"`
}

// All methods below require h.mu; only cancellation signals cross the lock.
func (h *Host) bootstrapContextLocked(parent context.Context) (context.Context, func()) {
	if h.bootstrapLife == nil {
		h.bootstrapLife, h.bootstrapCancel = context.WithCancel(context.Background())
	}
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(h.bootstrapLife, cancel)
	return ctx, func() { stop(); cancel() }
}
func (h *Host) cancelBootstrapLocked() {
	if h.bootstrapCancel != nil {
		h.bootstrapCancel()
	}
	h.bootstrapLife = nil
	h.bootstrapCancel = nil
}
