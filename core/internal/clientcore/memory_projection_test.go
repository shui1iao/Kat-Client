package clientcore

import (
	"encoding/json"
	"os"
	"testing"
)

// Directly exercise the production status projector, not a UI memory fixture.
func TestStatusOwnMemoryLifecycle(t *testing.T) {
	h := newHost(t)
	text := fixture(t, map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}})
	if _, err := h.Apply(text); err != nil {
		t.Fatal(err)
	}
	checkNull := func() {
		t.Helper()
		st := h.Status().(map[string]any)["runtime"].(map[string]any)
		if st["memory_bytes"] != nil || st["pid"] != nil {
			t.Fatalf("inactive leaked memory/PID: %#v", st)
		}
		b, err := json.Marshal(st)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]json.RawMessage
		if err = json.Unmarshal(b, &wire); err != nil {
			t.Fatal(err)
		}
		if string(wire["memory_bytes"]) != "null" {
			t.Fatalf("absent memory must be JSON null: %s", b)
		}
	}
	checkNull()
	if _, err := h.Start(); err != nil {
		t.Fatal(err)
	}
	st := h.Status().(map[string]any)["runtime"].(map[string]any)
	memory, ok := st["memory_bytes"].(uint64)
	if !ok || memory == 0 || st["state"] != "running" || st["pid"] != os.Getpid() {
		t.Fatalf("actual own running memory missing: %#v", st)
	}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Memory uint64 `json:"memory_bytes"`
	}
	if err = json.Unmarshal(b, &wire); err != nil || wire.Memory != memory {
		t.Fatalf("numeric projection lost: %s %v", b, err)
	}
	if _, err := h.Stop(); err != nil {
		t.Fatal(err)
	}
	checkNull()
	for _, state := range []string{"unknown", "starting", "error", "stopped"} {
		h.mu.Lock()
		h.state = state
		h.mu.Unlock()
		checkNull()
	}
	t.Logf("actual Linux own-process RSS observed: %d bytes; not Windows privateUsage runtime proof", memory)
}
