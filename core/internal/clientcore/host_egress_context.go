package clientcore

import (
	"context"
	"github.com/shui1iao/Kat/internal/clientegress"
	"net"
)

// Native-only request capability, not a JSON option or another policy writer.
// The tuple is borrowed read-only; generation alone is NOT a lifecycle token.
type hostEgressKey struct{}
type hostEgressRequest struct {
	switcher         *clientegress.Switch
	policy           *clientegress.Policy
	generation       uint64
	ordinary, frozen bool
}

func hostEgress(ctx context.Context) *clientegress.Switch {
	r, _ := ctx.Value(hostEgressKey{}).(hostEgressRequest)
	return r.switcher
}
func checkHostEgress(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	r, ok := ctx.Value(hostEgressKey{}).(hostEgressRequest)
	if !ok {
		return nil
	}
	p, g, frozen := r.switcher.PolicySnapshot()
	if r.frozen || frozen || g != r.generation || p != r.policy || p == nil && !r.ordinary || p != nil && !p.Ready() {
		return dl("connect", "egress_unavailable")
	}
	return nil
}
func dialHostEgress(ctx context.Context, s *clientegress.Switch, n, a string) (net.Conn, error) {
	if e := checkHostEgress(ctx); e != nil {
		return nil, e
	}
	c, e := s.DialContext(ctx, n, a)
	if e != nil {
		return nil, e
	}
	if e = checkHostEgress(ctx); e != nil {
		c.Close()
		return nil, e
	}
	return c, nil
}

// h.mu required. Explicit OFF with proven native clearance authorizes ordinary traffic;
// nil/frozen/failed while TUN intent is retained never means a direct fallback.
func (h *Host) hostOrdinaryLocked() bool {
	if h.tunSession == nil {
		return h.egress == nil
	}
	if h.tun == nil {
		return true
	}
	s := h.tun.Status()
	_, _, frozen := h.egressSwitch.PolicySnapshot()
	return (!s.Intent && s.NetworkClear) || (!s.Enabled && !frozen)
}
func (h *Host) hostEgressReadyLocked() bool {
	return !h.egressFrozen && (h.egress != nil && h.egress.Ready() || h.egress == nil && h.hostOrdinaryLocked())
}

// Mirror the sole OS writer for presentation/accepted-source checks. Do not
// call Fail/SetIPv6/Replace on the borrowed policy or manufacture blocked policy.
func (h *Host) syncTUNEgressLocked() {
	if h.tunSession == nil {
		return
	}
	p, g, frozen := h.egressSwitch.PolicySnapshot()
	frozen = frozen || p == nil && !h.hostOrdinaryLocked()
	if p != h.egress || g != h.egressPhysicalGeneration || frozen != h.egressFrozen {
		h.cancelBootstrapLocked()
		h.egressGeneration++
	}
	h.egress, h.egressPhysicalGeneration, h.egressFrozen = p, g, frozen
	h.egressOptions = clientegress.Options{Schema: clientegress.Schema, DNS: []clientegress.DNSEndpoint{}, Enabled: frozen}
	if p != nil {
		h.egressOptions = p.Options.Clone()
	}
}
