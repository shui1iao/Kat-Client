package procattr

import "github.com/shui1iao/Kat/internal/outbound"

// HTTPObservation is private in-process metadata, never an identity source.
// It borrows the lifetime and exact socket key of the existing HTTP registration.
// Neither callback performs network operations, IPC, waits or process lookup.
type HTTPObservation struct {
	Bind     func(uint64)
	Decorate func(*outbound.Diagnostic)
}

func HTTPFlowObservation(q Query) *HTTPObservation {
	// Diagnostic association must never add a wait to flow admission.
	if !httpFlows.TryLock() {
		return nil
	}
	o := httpFlows.observations[key{q.ControlSource, q.ControlDestination}]
	httpFlows.Unlock()
	return o
}
