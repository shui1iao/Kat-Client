package clientcore

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound/group"
	"github.com/shui1iao/Kat/internal/provider"
	"golang.org/x/net/proxy"
)

// Decode the actual JSON, not the Go slice length: absent and null do not satisfy [] contracts.
func contractJSON(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
func emptyJSONArray(t *testing.T, m map[string]any, k string) {
	t.Helper()
	a, ok := m[k].([]any)
	if !ok || len(a) != 0 {
		t.Fatalf("%s must be []", k)
	}
}
func TestIPCContractStatusAndLegacyCaches(t *testing.T) {
	h := newHost(t)
	if _, de := h.Apply(fixture(t, map[string]any{})); de != nil {
		t.Fatal(de)
	}
	if _, de := h.Start(); de != nil {
		t.Fatal(de)
	}
	emptyJSONArray(t, contractJSON(t, h.Status())["traffic"].(map[string]any), "domains")
	if _, de := h.Stop(); de != nil {
		t.Fatal(de)
	}
	historyPath := filepath.Join(h.workspace, "traffic-history.json")
	before := []byte("{\"total_up\":7,\"daily\":null}\n")
	if err := os.WriteFile(historyPath, before, 0600); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	err := h.loadHistory()
	h.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	traffic := contractJSON(t, h.Status())["traffic"].(map[string]any)
	emptyJSONArray(t, traffic, "daily")
	if traffic["total_up"] != float64(7) {
		t.Fatal("lost totals")
	}
	if b, e := os.ReadFile(historyPath); e != nil || string(b) != string(before) {
		t.Fatal("history rewritten")
	}
	for _, tc := range []struct {
		kind, raw string
		row       bool
	}{
		{"exit", `{"at":"2026-01-01T00:00:00Z","items":null}`, false},
		{"unlock", `{"at":"2026-01-01T00:00:00Z"}`, false},
		{"connectivity", `{"at":"2026-01-01T00:00:00Z","items":[{"result":"ok","chain":null}]}`, true},
	} {
		path := filepath.Join(h.workspace, "network-diagnostic-"+tc.kind+".json")
		if err := os.WriteFile(path, []byte(tc.raw), 0600); err != nil {
			t.Fatal(err)
		}
		v, de := h.Request(context.Background(), "diagnostics.network", rawJSON(map[string]string{"kind": tc.kind}))
		if de != nil {
			t.Fatal(de)
		}
		m := contractJSON(t, v)
		if tc.row {
			emptyJSONArray(t, m["items"].([]any)[0].(map[string]any), "chain")
		} else {
			emptyJSONArray(t, m, "items")
		}
		if b, e := os.ReadFile(path); e != nil || string(b) != tc.raw {
			t.Fatal("cache rewritten")
		}
	}
}
func TestIPCContractSubscriptionArraysPreserveLegacyDocument(t *testing.T) {
	p := contractJSON(t, subscriptionPreview{Items: subscriptionItems(provider.Full{Groups: []group.Options{{Name: "dynamic", IncludeAll: true}}})})["items"].(map[string]any)
	emptyJSONArray(t, p, "rules")
	emptyJSONArray(t, p["groups"].([]any)[0].(map[string]any), "members")
	dir := t.TempDir()
	h, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if h != nil {
			_ = h.Close()
		}
	}()
	manual := strings.Replace(initialDocument, `"kernel":{}`, `"kernel":{"routing":{"rules":[{"domain":"manual.invalid","action":"direct"}],"final":"direct"}}`, 1)
	if _, de := h.Apply(manual); de != nil {
		t.Fatal(de)
	}
	const remote = "rules: ['MATCH,DIRECT']\n"
	preview := fullPreview(t, h, remote, "")
	var doc map[string]any
	if err = json.Unmarshal([]byte(preview.Text), &doc); err != nil {
		t.Fatal(err)
	}
	snap := doc["subscriptions"].([]any)[0].(map[string]any)["snapshot"].(map[string]any)
	for _, k := range []string{"outbounds", "groups", "rules", "rule_sets"} {
		emptyJSONArray(t, snap, k)
		snap[k] = nil
	}
	path := h.path
	if err = h.Close(); err != nil {
		t.Fatal(err)
	}
	h = nil
	old, err := json.MarshalIndent(doc, "", "   ")
	if err != nil {
		t.Fatal(err)
	}
	old = append(old, '\n')
	if err = os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	h, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if h.Document().(map[string]any)["text"] != string(old) {
		t.Fatal("opened legacy source changed")
	}
	refreshed := fullPreview(t, h, remote, preview.ID)
	if refreshed.NeedsConfirmation {
		t.Fatal("empty/null equivalence prompted a precedence change")
	}
	if b, e := os.ReadFile(path); e != nil || string(b) != string(old) {
		t.Fatal("legacy source rewritten by open/preview")
	}
}

func TestIPCContractCloseCapturedMembersOnly(t *testing.T) {
	h := newHost(t)
	if _, e := h.Apply(fixture(t, map[string]any{"security": map[string]bool{"allow_loopback": true}})); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	dst, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	dial := func() func() {
		t.Helper()
		d, e := proxy.SOCKS5("tcp", portAddress(h.doc.client.SOCKSPort), nil, &net.Dialer{Timeout: 2 * time.Second})
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c, e := d.(proxy.ContextDialer).DialContext(ctx, "tcp", dst.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		peer, e := dst.Accept()
		if e != nil {
			t.Fatal(e)
		}
		finish := func() { c.Close(); peer.Close() }
		t.Cleanup(finish)
		return finish
	}
	type capture struct {
		ID     uint64   `json:"id"`
		IDs    []uint64 `json:"member_ids"`
		Target string   `json:"target"`
	}
	rows := func(n int) (string, capture) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			v, de := h.listConnections(nil)
			if de != nil {
				t.Fatal(de)
			}
			b, e := json.Marshal(v)
			if e != nil {
				t.Fatal(e)
			}
			var reply struct {
				Instance string    `json:"connection_instance"`
				Active   []capture `json:"active"`
			}
			if e = json.Unmarshal(b, &reply); e != nil {
				t.Fatal(e)
			}
			for _, r := range reply.Active {
				if r.Target == dst.Addr().String() && len(r.IDs) == n {
					return reply.Instance, r
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("no aggregate with %d captured members", n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	closeIDs := func(instance string, ids []uint64) int {
		t.Helper()
		v, e := h.closeConnections(rawJSON(map[string]any{"connection_instance": instance, "ids": ids}))
		if e != nil {
			t.Fatal(e)
		}
		return v.(map[string]int)["closed"]
	}
	finishFirst := dial()
	dial()
	instance, selected := rows(2)
	if instance == "" || !slices.Contains(selected.IDs, selected.ID) {
		t.Fatal("missing list instance/representative")
	}
	dial()
	_, late := rows(3)
	lateID := late.IDs[2]
	if slices.Contains(selected.IDs, lateID) {
		t.Fatal("new flow not distinguishable")
	}
	finishFirst()
	rows(2) // The original representative has ended, but its surviving captured member still matches.
	if n := closeIDs(instance, append(selected.IDs, selected.IDs[1])); n != 1 {
		t.Fatalf("closed %d, want one surviving captured member", n)
	}
	_, survivor := rows(1)
	if survivor.ID != lateID {
		t.Fatal("new member closed or original member survived")
	}
	if _, de := h.closeConnections(rawJSON(map[string]any{"ids": survivor.IDs})); de == nil || de.Code != "invalid_params" {
		t.Fatal("missing instance accepted")
	}
	if _, e := h.Stop(); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	dial()
	newInstance, afterRestart := rows(1)
	if instance == newInstance {
		t.Fatal("flow ID namespace reused")
	}
	if closeIDs(instance, afterRestart.IDs) != 0 {
		t.Fatal("stale instance closed a new flow")
	}
	if closeIDs(newInstance, afterRestart.IDs) != 1 {
		t.Fatal("valid close after restart rejected")
	}
}

func TestIPCContractDuplicateResumeKeepsCancellableEpoch(t *testing.T) {
	var epoch ipcEpoch
	for range 2 {
		epoch.resume(t.Context())
		active := epoch.ctx
		epoch.resume(t.Context())
		if active != epoch.ctx || active.Err() != nil {
			t.Fatal("duplicate resume replaced or cancelled the live epoch")
		}
		epoch.pause()
		if active.Err() != context.Canceled || epoch.ctx != nil || epoch.cancel != nil {
			t.Fatal("pause retained a live request epoch")
		}
	}
}
