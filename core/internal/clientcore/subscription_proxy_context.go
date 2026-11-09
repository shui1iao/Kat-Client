package clientcore

import (
	"context"
	"github.com/shui1iao/Kat/internal/clientegress"
)

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
	if clientegress.Supported || h.tunSession != nil {
		p, g, frozen := h.egressSwitch.PolicySnapshot()
		parent = context.WithValue(parent, hostEgressKey{}, hostEgressRequest{switcher: &h.egressSwitch, policy: p, generation: g, ordinary: h.hostOrdinaryLocked(), frozen: frozen})
	}
	ctx, cancel := context.WithCancel(parent)
	// Register the actual child cancellations: AfterFunc propagation alone can
	// be delayed past activation. Cancel them synchronously under the same Host
	// operation lock BEFORE TUN changes a route/epoch or replaces nil policy.
	if h.bootstrapRequests == nil {
		h.bootstrapRequests = make(map[context.Context]context.CancelFunc)
	}
	h.bootstrapRequests[ctx] = cancel
	stop := context.AfterFunc(h.bootstrapLife, cancel)
	if h.bootstrapLife.Err() != nil {
		cancel()
	}
	return ctx, func() {
		stop()
		cancel()
		h.mu.Lock()
		delete(h.bootstrapRequests, ctx)
		h.mu.Unlock()
	}
}
func (h *Host) cancelBootstrapLocked() {
	for ctx, cancel := range h.bootstrapRequests {
		cancel()
		delete(h.bootstrapRequests, ctx)
	}
	if h.bootstrapCancel != nil {
		h.bootstrapCancel()
	}
	h.bootstrapLife = nil
	h.bootstrapCancel = nil
}
