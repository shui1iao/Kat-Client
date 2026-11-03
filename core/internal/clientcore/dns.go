package clientcore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/kernel"
)

func (h *Host) queryDNS(ctx context.Context, raw json.RawMessage) (any, *Error) {
	var p struct {
		Name string          `json:"name"`
		Type json.RawMessage `json:"type"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	typ := "both"
	if p.Type != nil && (string(p.Type) == "null" || json.Unmarshal(p.Type, &typ) != nil || typ != "A" && typ != "AAAA" && typ != "both") {
		return nil, fail("invalid_params", "params.type", "Expected A, AAAA or both")
	}
	if p.Name == "" {
		return nil, fail("invalid_name", "params.name", "Valid DNS name required")
	}
	h.mu.Lock()
	s := h.server
	if s == nil {
		h.mu.Unlock()
		return nil, fail("core_not_running", "runtime", "Core is stopped")
	}
	qctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(h.probeCtx, cancel)
	h.probeWG.Add(1)
	h.mu.Unlock()
	result, err := s.QueryDNS(qctx, p.Name, typ)
	stop()
	cancel()
	h.probeWG.Done()
	if errors.Is(err, kernel.ErrDNSInvalidName) {
		return nil, fail("invalid_name", "params.name", "Valid DNS name required")
	}
	if errors.Is(err, kernel.ErrCoreNotRunning) {
		return nil, fail("core_not_running", "runtime", "Core is stopped")
	}
	if err != nil {
		return nil, fail("dns_failed", "params.name", "DNS chain did not return an answer")
	}
	return result, nil
}
