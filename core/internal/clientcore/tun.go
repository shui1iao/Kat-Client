package clientcore

import (
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/elevated"
	"github.com/shui1iao/Kat/internal/tunplatform"
	"github.com/shui1iao/Kat/internal/tunstack"
	"time"
)

// AttachElevated is native bootstrap only, after authenticated activation and
// unique writer acquisition. No JSON field can install this capability.
func (h *Host) AttachElevated(s *elevated.Session) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if s == nil || h.tunSession != nil {
		return elevated.ErrIdentity
	}
	h.tunSession = s
	return nil
}
func (h *Host) makeTUNLocked() error {
	if h.tun != nil {
		return nil
	}
	if h.tunSession == nil {
		return tunplatform.At("make_session", "CORE_IDENTITY", elevated.ErrIdentity)
	}
	if h.server == nil || !h.localReady {
		return tunplatform.At("make_running", "CORE_NOT_READY", fail("not_ready", "runtime", "Start the core before enabling TUN"))
	}
	// Resolve the server-only ingress BEFORE OS creates/transfers any device.
	// It follows server.current() per flow, so reloads remain valid. From the
	// factory call onward every device/error close is exclusively DATA's.
	ingress, e := h.server.NewTUNIngress()
	if e != nil {
		return tunplatform.At("make_ingress", "CORE_INGRESS", e)
	}
	manager, e := tunplatform.New(tunplatform.Config{Launch: h.tunSession.Binding.TunLaunch, Broker: &tunplatform.JournalClient{Launch: h.tunSession.Binding.TunLaunch, Exchange: h.tunSession.Exchange}, Egress: &h.egressSwitch, Observe: func(d tunplatform.Diagnostic) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		h.tunSession.ReportTUN(ctx, d)
	}, Start: func(ctx context.Context, dev tunplatform.Device, fc tunplatform.FlowContext) (tunplatform.DataPlane, error) {
		return tunstack.StartReady(ctx, tunstack.Config{Device: dev, Ingress: ingress, Admitting: fc.Admitting, Epoch: fc.Epoch})
	}})
	if e != nil {
		return e
	}
	h.tun = manager
	return nil
}
func (h *Host) tunFailure(e error) *Error {
	if e == nil {
		return nil
	}
	d := tunplatform.Describe("active_failure", e)
	if h.tunSession != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		recorded := h.tunSession.ReportTUN(ctx, d)
		cancel()
		d.Recorded = &recorded
	}
	out := fail("TUN_OPERATION_FAILED", "network.tun", "Owned core TUN operation did not complete; recovery state retained")
	out.Tun = &d
	return out
}
func (h *Host) tunPrepare(ctx context.Context, params json.RawMessage) (any, *Error) {
	if e := decodeParams(params, &struct{}{}); e != nil {
		return nil, e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if e := h.makeTUNLocked(); e != nil {
		return nil, h.tunFailure(e)
	}
	h.cancelBootstrapLocked()
	defer h.syncTUNEgressLocked()
	p, e := h.tun.Prepare(ctx)
	return map[string]any{"token": p.Token, "tun": h.tun.Status()}, h.tunFailure(e)
}
func (h *Host) tunCommit(ctx context.Context, params json.RawMessage) (any, *Error) {
	var p struct {
		Token uint64 `json:"token"`
	}
	if e := decodeParams(params, &p); e != nil {
		return nil, e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tun == nil || p.Token == 0 {
		return nil, h.tunFailure(tunplatform.At("commit_guard", "TUN_PREPARED_STALE", fail("invalid_params", "token", "Prepared TUN token required")))
	}
	h.cancelBootstrapLocked()
	defer h.syncTUNEgressLocked()
	s, e := h.tun.Commit(ctx, p.Token)
	return s, h.tunFailure(e)
}
func (h *Host) tunDisable(ctx context.Context, params json.RawMessage) (any, *Error) {
	if e := decodeParams(params, &struct{}{}); e != nil {
		return nil, e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tun == nil {
		return tunplatform.Status{State: "off", CleanupComplete: true}, nil
	}
	h.cancelBootstrapLocked()
	defer h.syncTUNEgressLocked()
	s, e := h.tun.Disable(ctx)
	return s, h.tunFailure(e)
}
func (h *Host) tunStatus(params json.RawMessage) (any, *Error) {
	if e := decodeParams(params, &struct{}{}); e != nil {
		return nil, e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tun == nil {
		return tunplatform.Status{State: "off", CleanupComplete: true}, nil
	}
	return h.tun.Status(), nil
}
