package clientcore

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/shui1iao/Kat/internal/route"
)

func TestRoutingPreviewTargetIPC(t *testing.T) {
	h := newHost(t)
	k := settingsKernel(t)
	k["groups"] = []any{
		map[string]any{
			"name":     "Proxy",
			"type":     "select",
			"members":  []any{"p", "direct"},
			"selected": "p",
		},
		map[string]any{
			"name":    "Auto",
			"type":    "url-test",
			"members": []any{"p"},
			"probe": map[string]any{
				"url":      "https://www.gstatic.com/generate_204",
				"interval": "5m",
			},
		},
	}
	k["routing"] = map[string]any{
		"final": "Auto",
		"rules": []any{
			map[string]any{"process_name": "curl", "action": "reject"},
			map[string]any{"domain_suffix": "example.com", "outbound": "Proxy"},
		},
	}
	text := settingsText(t, fixture(t, k), nil)
	if _, err := h.Apply(text); err != nil {
		t.Fatal(err)
	}

	raw, rpcErr := h.Request(context.Background(), "routing.previewTarget", json.RawMessage(`{"target":"https://Sub.Example.com:8443/hello"}`))
	if rpcErr != nil {
		t.Fatalf("unexpected rpc error: %+v", rpcErr)
	}
	res, ok := raw.(route.TargetPreview)
	if !ok {
		t.Fatalf("unexpected response type %T", raw)
	}
	if res.Scope != "target-only" || res.Target.Host != "sub.example.com" || res.Target.Kind != "domain" {
		t.Fatalf("unexpected target info: %+v", res)
	}
	if res.Matched.Source != "rule" || res.Matched.Index == nil || *res.Matched.Index != 2 || res.Matched.Type != "DOMAIN-SUFFIX" || res.Matched.Payload != "example.com" || res.Matched.Policy != "Proxy" {
		t.Fatalf("unexpected matched rule: %+v", res.Matched)
	}
	if len(res.Chain) != 2 || res.Chain[0] != "Proxy" || res.Chain[1] != "p" {
		t.Fatalf("unexpected select policy chain: %+v", res.Chain)
	}

	// Unmatched target hits final ("Auto"); cold url-test group without fixed node returns only ["Auto"].
	rawFinal, rpcErr := h.Request(context.Background(), "routing.previewTarget", json.RawMessage(`{"target":"other.org"}`))
	if rpcErr != nil {
		t.Fatalf("unexpected rpc error: %+v", rpcErr)
	}
	resFinal := rawFinal.(route.TargetPreview)
	if resFinal.Matched.Source != "final" || resFinal.Matched.Index != nil || resFinal.Matched.Policy != "Auto" {
		t.Fatalf("unexpected final match: %+v", resFinal.Matched)
	}
	if len(resFinal.Chain) != 1 || resFinal.Chain[0] != "Auto" {
		t.Fatalf("expected cold auto group chain [Auto], got %+v", resFinal.Chain)
	}

	// Invalid userinfo URL is rejected.
	if _, rpcErr := h.Request(context.Background(), "routing.previewTarget", json.RawMessage(`{"target":"https://user:pass@example.com/"}`)); rpcErr == nil {
		t.Fatal("expected invalid_target rpcError for userinfo URL")
	}
}
