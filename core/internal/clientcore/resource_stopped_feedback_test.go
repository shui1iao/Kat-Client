package clientcore

import (
	"context"
	"encoding/json"
	"testing"
)

// Freeze the native category used by the resource-page display-only mapping.
// Host checks stopped runtime before any local/full-subscription remote ownership.
func TestStoppedResourceRefreshStableCategory(t *testing.T) {
	h := newHost(t)
	for _, kind := range []string{"rule_set", "geoip", "asn"} {
		raw, _ := json.Marshal(map[string]string{"kind": kind, "name": "local-resource"})
		_, e := h.Request(context.Background(), "resources.refresh", raw)
		if e == nil || e.Code != "core_not_running" {
			t.Fatalf("%s: expected frozen core_not_running, got %v", kind, e)
		}
	}
}
