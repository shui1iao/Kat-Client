package clientcore

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/route"
)

type previewTargetParams struct {
	Target string `json:"target"`
}

func (h *Host) previewTarget(ctx context.Context, raw json.RawMessage) (any, *Error) {
	var p previewTargetParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, fail("invalid_target", "params.target", "请输入有效的域名、IP 或 HTTP(S) 网址")
	}
	h.mu.Lock()
	srv := h.server
	doc := h.doc
	h.mu.Unlock()
	var routing *kernel.RoutingOptions
	if src := doc.ruleRouting; src != nil {
		r := *src
		r.Rules = append([]kernel.RouteRule(nil), r.Rules...)
		routing = &r
	} else if doc.config.Routing != nil {
		r := *doc.config.Routing
		r.Rules = append([]kernel.RouteRule(nil), r.Rules...)
		routing = &r
	}
	if srv != nil {
		res, err := srv.PreviewTarget(ctx, routing, p.Target)
		if err == nil {
			return res, nil
		}
		if !errors.Is(err, kernel.ErrCoreNotRunning) {
			return nil, mapPreviewError(err)
		}
	}
	res, err := kernel.PreviewStoppedTarget(ctx, doc.config, routing, p.Target)
	if err != nil {
		return nil, mapPreviewError(err)
	}
	return res, nil
}

func mapPreviewError(err error) *Error {
	var pe *route.TargetPreviewError
	if errors.As(err, &pe) {
		return fail(pe.Code, "params.target", pe.Message)
	}
	return fail("preview_failed", "params.target", "规则判定失败")
}
