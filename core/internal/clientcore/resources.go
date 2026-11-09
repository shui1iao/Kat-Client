package clientcore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/route"
	"time"
)

func (h *Host) listResources(raw json.RawMessage) (any, *Error) {
	if e := decodeParams(raw, &struct{}{}); e != nil {
		return nil, e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	items := []route.ResourceView{}
	if s := h.server; s != nil {

		items = append(items, s.ResourceViews()...)
	} else {
		// Stopped: enumerate configured resources, but do not read files or claim
		// that a file is parsed/loaded. No stale generation metadata survives Stop.
		for _, r := range h.doc.config.RuleSets {
			items = append(items, route.ResourceView{Kind: "rule_set", Name: r.Name, State: "pending"})
		}
		if h.doc.config.GeoIP != nil {
			items = append(items, route.ResourceView{Kind: "geoip", Name: "geoip", State: "pending"})
		}
		if h.doc.config.ASN != nil {
			items = append(items, route.ResourceView{Kind: "asn", Name: "asn", State: "pending"})
		}
	}
	return map[string]any{"items": items}, nil
}
func (h *Host) refreshResource(ctx context.Context, raw json.RawMessage) (any, *Error) {
	var p struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	if p.Name == "" || p.Kind != "rule_set" && p.Kind != "geoip" && p.Kind != "asn" {
		return nil, fail("invalid_params", "params", "Expected configured resource kind and name")
	}
	h.mu.Lock()
	s := h.server
	if s == nil {
		h.mu.Unlock()
		return nil, fail("core_not_running", "runtime", "Core is stopped")
	}
	h.syncTUNEgressLocked()
	base, generation, policy := h.doc, s.GenerationID(), h.egress
	target, failure := h.manualResourceLocked(base, p.Kind, p.Name)
	if failure != nil {
		h.mu.Unlock()
		return nil, failure
	}
	ctx, cancel := context.WithTimeout(ctx, 300*time.Second)
	stop := context.AfterFunc(h.probeCtx, cancel)
	stopEpoch := context.AfterFunc(h.manualCtx, cancel)
	if h.probeCtx.Err() != nil || h.manualCtx.Err() != nil {
		cancel()
	}
	// Local reload has no Host callbacks and can be drained under Stop's lock.
	// Downloads use existing Host-aware routes; never wait under h.mu for work
	// that must acquire that mutex. Cancellation plus source/generation checks
	// discard its result before any source or cache publication.
	local := target.url == ""
	var stopBootstrap func()
	if !local {
		if !h.hostEgressReadyLocked() {
			stopEpoch()
			stop()
			cancel()
			h.mu.Unlock()
			return nil, fail("resource_refresh_failed", "params", "Physical egress is unavailable")
		}
		ctx, stopBootstrap = h.bootstrapContextLocked(ctx)
	}
	if local {
		h.probeWG.Add(1)
	}
	h.mu.Unlock()
	defer func() {
		if stopBootstrap != nil {
			stopBootstrap()
		}
		stopEpoch()
		stop()
		cancel()
	}()
	if !local {
		return h.refreshDownloadedResource(ctx, base, s, generation, policy, target)
	}
	err := s.RefreshResourceWithReader(ctx, p.Kind, p.Name, readSubscriptionResource, generation)
	h.probeWG.Done()
	if errors.Is(err, route.ErrResourceUnsupported) {
		return nil, fail("unsupported", "params", "No configured file or remote resource")
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, requestCanceled()
		}
		return nil, fail("resource_refresh_failed", "params", "Resource reload failed; previous data retained")
	}
	return map[string]any{"kind": p.Kind, "name": p.Name, "state": "ok", "action": "reloaded"}, nil
}
