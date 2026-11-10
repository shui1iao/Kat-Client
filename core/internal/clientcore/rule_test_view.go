package clientcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/route"
)

func (h *Host) testRules(ctx context.Context, raw json.RawMessage) (any, *Error) {
	if len(raw) > 32<<10 {
		return nil, fail("invalid_params", "params", "判定参数超过长度限制")
	}
	// Keep the existing duplicate-key and unknown-field rejection. Raw scalars
	// additionally give malformed/null optional fields their own field error.
	var p struct {
		Target      json.RawMessage `json:"target"`
		Network     json.RawMessage `json:"network"`
		TargetPort  json.RawMessage `json:"target_port"`
		ProcessName json.RawMessage `json:"process_name"`
		SourceIP    json.RawMessage `json:"source_ip"`
		SourcePort  json.RawMessage `json:"source_port"`
		InboundName json.RawMessage `json:"inbound_name"`
		InboundType json.RawMessage `json:"inbound_type"`
		InboundPort json.RawMessage `json:"inbound_port"`
		Protocol    json.RawMessage `json:"protocol"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	// encoding/json matches struct fields case-insensitively. For this strict
	// method reject aliases such as target/Target before consuming any value;
	// uniqueJSON above still rejects actual duplicate and escaped-equal keys.
	if len(raw) != 0 {
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return nil, fail("invalid_params", "params", "Invalid method parameters")
		}
		for key := range fields {
			switch key {
			case "target", "network", "target_port", "process_name", "source_ip", "source_port", "inbound_name", "inbound_type", "inbound_port", "protocol":
			default:
				return nil, fail("invalid_params", "params", "判定字段名称无效，请使用规范字段名")
			}
		}
	}
	in := route.OfflineInput{}
	strings := []struct {
		name string
		raw  json.RawMessage
		dst  *string
	}{
		{"target", p.Target, &in.Target}, {"network", p.Network, &in.Network},
		{"process_name", p.ProcessName, &in.ProcessName}, {"source_ip", p.SourceIP, &in.SourceIP},
		{"inbound_name", p.InboundName, &in.InboundName}, {"inbound_type", p.InboundType, &in.InboundType}, {"protocol", p.Protocol, &in.Protocol},
	}
	for _, s := range strings {
		if len(s.raw) == 0 {
			continue
		}
		if bytes.Equal(bytes.TrimSpace(s.raw), []byte("null")) || json.Unmarshal(s.raw, s.dst) != nil {
			return nil, fail("invalid_params", s.name, "该字段应为文本，未指定时请省略")
		}
	}
	ports := []struct {
		name string
		raw  json.RawMessage
		dst  **uint16
	}{{"target_port", p.TargetPort, &in.TargetPort}, {"source_port", p.SourcePort, &in.SourcePort}, {"inbound_port", p.InboundPort, &in.InboundPort}}
	for _, p := range ports {
		if len(p.raw) == 0 {
			continue
		}
		var value uint16
		if bytes.Equal(bytes.TrimSpace(p.raw), []byte("null")) || json.Unmarshal(p.raw, &value) != nil || value == 0 {
			return nil, fail("invalid_params", p.name, "端口应为 1–65535 的整数，未指定时请省略")
		}
		*p.dst = &value
	}
	h.mu.Lock()
	s := h.server
	if s == nil {
		h.mu.Unlock()
		return nil, fail("core_not_running", "runtime", "请先启动内核，判定使用当前已生效规则")
	}
	routing, mode, ipv6 := h.doc.ruleRouting, h.doc.client.Mode, h.doc.client.IPv6
	generation := s.GenerationID()
	qctx, cancel := context.WithCancel(ctx)
	var stop func() bool
	if h.probeCtx != nil {
		stop = context.AfterFunc(h.probeCtx, cancel)
	}
	h.probeWG.Add(1)
	h.mu.Unlock()
	result, e := s.TargetRuleViewWithContext(qctx, routing, in)
	if stop != nil {
		stop()
	}
	cancel()
	// Stop/Apply can wait under mu; release our ownership before reacquiring it.
	h.probeWG.Done()
	if e != nil {
		var invalid *route.OfflineInputError
		if errors.As(e, &invalid) {
			return nil, fail("invalid_params", invalid.Field, invalid.Message)
		}
		if ctx.Err() != nil {
			return nil, requestCanceled()
		}
		if errors.Is(e, kernel.ErrCoreNotRunning) {
			return nil, fail("core_not_running", "runtime", "请先启动内核，判定使用当前已生效规则")
		}
		return nil, fail("rule_test_unavailable", "runtime", "当前规则或资源无法安全判定，请检查已生效配置与资源状态")
	}
	h.mu.Lock()
	stale := h.server != s || h.doc.ruleRouting != routing || h.doc.client.Mode != mode || h.doc.client.IPv6 != ipv6 || s.GenerationID() != generation
	h.mu.Unlock()
	if stale {
		return nil, fail("rule_test_stale", "runtime", "规则、资源或模式已变化，请重新判定")
	}
	return map[string]any{"result": result, "mode": mode, "simulation": "target", "ipv6_enabled": ipv6}, nil
}
