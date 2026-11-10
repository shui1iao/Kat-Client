package clientcore

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/kernel"
	"io"
	"time"
)

var BuildCommit = "development"

func decodeParams(raw json.RawMessage, v any) *Error {
	if len(raw) == 0 {
		raw = []byte(`{}`)
	}
	if raw[0] != '{' || uniqueJSON(raw) != nil {
		return fail("invalid_params", "params", "Expected unambiguous JSON object")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return fail("invalid_params", "params", "Invalid method parameters")
	}
	return nil
}
func (h *Host) Request(ctx context.Context, method string, params json.RawMessage) (any, *Error) {
	if ctx.Err() != nil {
		return nil, requestCanceled()
	}
	if h.tunSession != nil && method != "network.egress.get" && (method == "network.egress.set" || method == "network.egress.pause") {
		return nil, fail("TUN_ENGINE_RETIRED", "network.egress", "Physical lifecycle is owned by core TUN Manager")
	}
	switch method {
	case "network.tun.prepare":
		return h.tunPrepare(ctx, params)
	case "network.tun.commit":
		return h.tunCommit(ctx, params)
	case "network.tun.disable":
		return h.tunDisable(ctx, params)
	case "network.tun.status":
		return h.tunStatus(params)
	case "host.prepare-update":
		return h.prepareHandover(ctx, params)
	case "host.resume-update":
		return h.resumeUpdate(params)
	case "rules.test":
		return h.testRules(ctx, params)
	case "diagnostics.network":
		return h.diagnosticsNetwork(ctx, params)
	case "icon.cached":
		if e := decodeParams(params, &struct{}{}); e != nil {
			return nil, e
		}
		return h.cachedIcons(), nil
	case "icon.get":
		return h.getIcon(ctx, params)
	case "group.filter_preview":
		return h.filterPreview(params)
	case "connections.close":
		return h.closeConnections(params)
	case "probe.all":
		return h.probeAll(ctx, params)
	case "subscription.migrate":
		return h.previewLegacy(ctx, params)
	case "connections.list":
		return h.listConnections(params)
	case "logs.kernel":
		return h.getKernelLogs(params)
	case "logs.connections":
		return h.getConnectionLogs(params)
	case "dns.cache.clear":
		if e := decodeParams(params, &struct{}{}); e != nil {
			return nil, e
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.server == nil {
			return nil, fail("core_not_running", "runtime", "Core is stopped")
		}
		n, e := h.server.ClearDNSCache()
		if e != nil {
			return nil, fail("core_not_running", "runtime", "Core is stopped")
		}
		return map[string]any{"cleared": n}, nil
	case "dns.query":
		return h.queryDNS(ctx, params)
	case "resources.list":
		return h.listResources(params)
	case "resources.refresh":
		return h.refreshResource(ctx, params)
	case "logs.get":
		return h.getLogs(params)
	case "hello":
		if e := decodeParams(params, &struct{}{}); e != nil {
			return nil, e
		}
		caps := []string{"document.v1", "local.http.v1", "local.socks.v1", "probe.http.v1", "subscription.full.v1", "logs.v1", "host.prepare-update.v1", "host.handover.v1"}
		if clientegress.Supported {
			caps = append(caps, "network.egress.v3")
		}
		if h.tunSession != nil {
			caps = append(caps, "host.elevated.v1", "network.tun-core.v1")
		}
		return map[string]any{"protocol": 1, "core_version": kernel.Version, "build_commit": BuildCommit, "instance": logInstance, "capabilities": caps}, nil
	case "document.get":
		if e := decodeParams(params, &struct{}{}); e != nil {
			return nil, e
		}
		return h.Document(), nil
	case "document.validate", "document.apply":
		var p struct {
			Text   *string         `json:"text"`
			Format json.RawMessage `json:"format"`
		}
		if e := decodeParams(params, &p); e != nil {
			return nil, e
		}
		if p.Text == nil {
			return nil, fail("invalid_params", "params.text", "Text required")
		}
		var formats []DocumentFormat
		if len(p.Format) != 0 {
			var format DocumentFormat
			if string(p.Format) == "null" || json.Unmarshal(p.Format, &format) != nil || !format.valid() {
				return nil, fail("invalid_params", "params.format", "Expected json, yaml or yml")
			}
			formats = []DocumentFormat{format}
		}
		if method == "document.validate" {
			v, e := h.validateDocument(*p.Text, formats...)
			if e != nil {
				h.mu.Lock()
				for _, pending := range h.fullCandidates {
					if pending.Text == *p.Text && pending.Refresh {
						h.recordSubscriptionStatusLocked(pending.ID, e)
						break
					}
				}
				h.mu.Unlock()
			}
			if e != nil && e.Detail == nil && e.Code != "legacy_provider_unsupported" {
				e.Detail = &ResourceDetail{Resource: "resource_stage", Source: "local", Stage: "validate", Category: "invalid_format", Route: "direct"}
			}
			return v, e
		}
		v, e := h.applyContext(ctx, *p.Text, formats...)
		if e != nil && e.Detail == nil && e.Code != "legacy_provider_unsupported" {
			switch e.Code {
			case "apply_failed", "save_failed", "document_changed", "subscription_stale", "request_canceled":
				category := "file_io"
				if e.Code == "request_canceled" {
					category = "canceled"
				}
				e.Detail = &ResourceDetail{Resource: "resource_stage", Source: "cache", Stage: "apply", Category: category, Route: "direct"}
			}
		}
		return v, e
	case "core.start", "core.stop", "core.reload", "status":
		if e := decodeParams(params, &struct{}{}); e != nil {
			return nil, e
		}
		switch method {
		case "core.start":
			return h.Start()
		case "core.stop":
			return h.Stop()
		case "core.reload":
			return h.Reload()
		default:
			return h.Status(), nil
		}
	case "probe.group":
		return h.probeGroupBatch(ctx, params)
	case "probe.node":
		var p struct {
			Name string `json:"name"`
			URL  string `json:"url,omitempty"`
		}
		if e := decodeParams(params, &p); e != nil {
			return nil, e
		}
		if p.Name == "" {
			return nil, fail("invalid_params", "params.name", "Name required")
		}
		return h.probe(ctx, false, p.Name, p.URL)
	case "subscription.status":
		if e := decodeParams(params, &struct{}{}); e != nil {
			return nil, e
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.subscriptionStatusesLocked(), nil
	case "subscription.select":
		return h.selectSubscription(params)
	case "subscription.preview":
		v, e := h.previewSubscription(ctx, params)
		if e != nil {
			var p struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(params, &p)
			h.mu.Lock()
			h.recordSubscriptionStatusLocked(p.ID, e)
			h.mu.Unlock()
		}
		return v, e
	case "subscription.cancel":
		return h.cancelSubscription(params)
	case "import.parse":
		return h.importParse(ctx, params)
	case "network.egress.get":
		if e := decodeParams(params, &struct{}{}); e != nil {
			return nil, e
		}
		return h.EgressGet(), nil
	case "network.egress.pause":
		h.mu.Lock()
		if h.egress == nil {
			h.egress = clientegress.Blocked()
			h.egressOptions = h.egress.Options.Clone()
			h.egressSwitch.Replace(h.egress)
		}
		if h.egress.Ready() {
			h.egressSwitch.Pause()
		}
		h.cancelBootstrapLocked()
		h.logs.record(kernel.ClientLogEvent{Time: time.Now(), Level: "info", Event: "egress_waiting", Generation: h.egressGeneration})
		v := h.egressViewLocked()
		h.mu.Unlock()
		return v, nil
	case "network.egress.set":
		var p struct {
			MetricDigest  string                     `json:"metric_digest"`
			GatewayDigest string                     `json:"gateway_digest"`
			AddressDigest string                     `json:"address_digest"`
			Schema        int                        `json:"schema"`
			Enabled       *bool                      `json:"enabled"`
			IPv4          *uint32                    `json:"ipv4_if_index"`
			IPv6          *uint32                    `json:"ipv6_if_index"`
			LUID4         *uint64                    `json:"ipv4_luid"`
			LUID6         *uint64                    `json:"ipv6_luid"`
			DNS           []clientegress.DNSEndpoint `json:"system_dns"`
			Identity      string                     `json:"identity"`
			Fingerprint   string                     `json:"fingerprint"`
		}
		if e := decodeParams(params, &p); e != nil {
			return nil, e
		}
		if p.Schema != clientegress.Schema || p.Enabled == nil || p.DNS == nil {
			return nil, fail("invalid_params", "params", "egress schema 3, enabled and system_dns required")
		}
		return h.EgressSet(clientegress.Options{MetricDigest: p.MetricDigest, GatewayDigest: p.GatewayDigest, AddressDigest: p.AddressDigest, Schema: p.Schema, Enabled: *p.Enabled, IPv4: p.IPv4, IPv6: p.IPv6, LUID4: p.LUID4, LUID6: p.LUID6, DNS: p.DNS, Identity: p.Identity, Fingerprint: p.Fingerprint})
	default:
		return nil, fail("unknown_method", "method", "Unknown core method")
	}
}
func (h *Host) probe(ctx context.Context, isGroup bool, name, url string) (any, *Error) {
	h.mu.Lock()
	s := h.server
	if s == nil {
		h.mu.Unlock()
		return nil, fail("not_running", "runtime", "Core is stopped")
	}
	if h.allRound != nil {
		h.mu.Unlock()
		return nil, fail("probe_busy", "", "A manual batch is running")
	}
	// Node keys are independent; do not disable all other groups/nodes.
	if h.manualNodes[name] == h.manualCtx && h.manualCtx != nil {
		h.mu.Unlock()
		return nil, fail("probe_busy", "params.name", "该节点正在测速")
	}
	if h.manualNodes == nil {
		h.manualNodes = map[string]context.Context{}
	}
	nodeEpoch := h.manualCtx
	h.manualNodes[name] = nodeEpoch
	h.activeManualProbes++
	defer func() {
		h.mu.Lock()
		if h.manualNodes[name] == nodeEpoch {
			delete(h.manualNodes, name)
		}
		h.activeManualProbes--
		h.mu.Unlock()
	}()

	if url == "" {
		url = h.doc.client.ProbeURL
	}
	epoch, policy := h.manualCtx, h.manualPolicy
	generation := s.GenerationID()
	budget := time.Duration(h.doc.client.ProbeRoundTimeout)
	lctx, cancel := context.WithCancel(ctx)
	if !isGroup {
		cancel()
		lctx, cancel = context.WithTimeout(ctx, budget)
	}
	stop := context.AfterFunc(epoch, cancel)
	if epoch.Err() != nil {
		cancel()
	}
	h.manualWG.Add(1)
	h.mu.Unlock()
	var result any
	var err error
	results := []kernel.ProbeResult{}
	if isGroup {
		var rs []kernel.ProbeResult
		rs, err = s.ProbeGroupRoundWithPolicy(lctx, name, url, policy, budget, nil)
		results = rs
		result = map[string]any{"name": name, "members": rs}
	} else {
		var r kernel.ProbeResult
		r, err = s.ProbeNodeWithPolicy(lctx, name, url, policy)
		results = append(results, r)
		result = r
	}
	complete := lctx.Err() == nil || (!isGroup && ctx.Err() == nil && epoch.Err() == nil && len(results) == 1 && results[0].ErrorStage == "target")
	stop()
	cancel()
	h.manualWG.Done() // before reacquiring mu: Stop/Apply can safely Wait
	if err != nil {
		return nil, fail("probe_failed", "params.name", "Unknown or unavailable node/group")
	}
	h.mu.Lock()
	if complete && h.server == s && h.manualCtx == epoch && s.GenerationID() == generation {
		for _, r := range results {
			if !r.At.IsZero() && !r.At.Before(h.probes[r.Name].At) {
				h.probes[r.Name] = r
			}
		}
	}
	h.mu.Unlock()
	return result, nil
}

func requestCanceled() *Error {
	return fail("request_canceled", "", "请求已取消，未接纳更改")
}
