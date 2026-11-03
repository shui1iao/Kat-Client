package clientcore

import (
	"encoding/json"
	"github.com/shui1iao/Kat/internal/kernel"
	"sync"
	"testing"
)

func TestSelectionOnlyRetainsRuntimeAndMixedFallsBack(t *testing.T) {
	h := newHost(t)
	text := fixture(t, map[string]any{"groups": []any{map[string]any{"name": "S", "type": "select", "members": []string{"direct", "reject"}, "selected": "direct"}, map[string]any{"name": "A", "type": "fallback", "members": []string{"direct"}, "probe": map[string]any{"url": "http://127.0.0.1:1"}}}})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	gen := h.server.StatsView().Reload.Generation
	bridge := h.bridge
	manual := h.manualCtx
	h.probes["direct"] = kernel.ProbeResult{Name: "direct"}
	change := func(name, key string, value any) string {
		root, _ := sourceJSON(h.doc)
		var k map[string]any
		json.Unmarshal(root["kernel"], &k)
		for _, v := range k["groups"].([]any) {
			g := v.(map[string]any)
			if g["name"] == name {
				if value == nil {
					delete(g, key)
				} else {
					g[key] = value
				}
			}
		}
		root["kernel"] = rawJSON(k)
		return string(rawJSON(root))
	}
	for _, next := range []string{change("S", "selected", "reject"), change("A", "fixed", "direct")} {
		r, e := h.Apply(next)
		if e != nil {
			t.Fatal(e)
		}
		if r.(map[string]any)["selection_only"] != true {
			t.Fatal("full apply", r)
		}
		if h.server.StatsView().Reload.Generation != gen || h.bridge != bridge || h.manualCtx != manual {
			t.Fatal("runtime/listener/probe lifetime replaced")
		}
		if _, ok := h.probes["direct"]; !ok {
			t.Fatal("probe cleared")
		}
	}
	if _, e := h.Apply(change("A", "fixed", nil)); e != nil {
		t.Fatal(e)
	}
	next := change("S", "selected", "direct")
	next = settingsText(t, next, map[string]any{"close_on_switch": false})
	r, e := h.Apply(next)
	if e != nil {
		t.Fatal(e)
	}
	if r.(map[string]any)["selection_only"] == true || h.server.StatsView().Reload.Generation == gen {
		t.Fatal("mixed edit did not rebuild")
	}
}
func TestSelectionOnlyConcurrentWritesNoGenerationChange(t *testing.T) {
	h := newHost(t)
	text := fixture(t, map[string]any{"groups": []any{map[string]any{"name": "S", "type": "select", "members": []string{"direct", "reject"}}}})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	gen := h.server.StatsView().Reload.Generation
	root, _ := sourceJSON(h.doc)
	var k map[string]any
	json.Unmarshal(root["kernel"], &k)
	g := k["groups"].([]any)[0].(map[string]any)
	sources := []string{}
	for _, m := range []string{"direct", "reject"} {
		g["selected"] = m
		root["kernel"] = rawJSON(k)
		sources = append(sources, string(rawJSON(root)))
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, e := h.Apply(sources[i%2]); e != nil {
				t.Error(e)
			}
		}(i)
	}
	wg.Wait()
	if h.server.StatsView().Reload.Generation != gen {
		t.Fatal("concurrent switch rebuilt")
	}
}
func TestSelectionOnlySubscriptionWritesOverlay(t *testing.T) {
	h := fullHost(t)
	p := fullPreview(t, h, "proxies: [{name: n, type: socks5, server: 127.0.0.1, port: 1080}]\nproxy-groups: [{name: Auto, type: url-test, proxies: [n], url: 'http://127.0.0.1:1/'}]\nrules: ['MATCH,Auto']\n", "")
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	gen := h.server.StatsView().Reload.Generation
	root, _ := sourceJSON(h.doc)
	var k map[string]any
	json.Unmarshal(root["kernel"], &k)
	g := k["groups"].([]any)[0].(map[string]any)
	g["fixed"] = g["members"].([]any)[0]
	root["kernel"] = rawJSON(k)
	r, e := h.Apply(string(rawJSON(root)))
	if e != nil {
		t.Fatal(e)
	}
	if r.(map[string]any)["selection_only"] != true || h.server.StatsView().Reload.Generation != gen {
		t.Fatal("subscription selection rebuilt")
	}
	accepted, _ := sourceJSON(h.doc)
	subs, _ := subscriptionsOf(accepted)
	if len(subs[0].State) == 0 {
		t.Fatal("no local state overlay")
	}
	if r.(map[string]any)["text"] != h.doc.text {
		t.Fatal("reply lost normalized overlay")
	}
}
func TestSelectionOnlyRejectsAllOtherDifferencesPrecisely(t *testing.T) {
	a := document{text: `{"client":{},"kernel":{"groups":[{"name":"S","selected":"a"}],"extension":9007199254740992}}`}
	b := document{text: `{"client":{},"kernel":{"groups":[{"name":"S","selected":"b"}],"extension":9007199254740993}}`}
	if selectionOnly(a, b) {
		t.Fatal("different large integer accepted as selection")
	}
	b.text = `{"client":{},"kernel":{"groups":[{"name":"S","selected":"b"}],"extension":9007199254740992}}`
	if !selectionOnly(a, b) {
		t.Fatal("selection missed")
	}
}

func TestSelectionOnlyPersistsAcrossProcessReopen(t *testing.T) {
	workspace := t.TempDir()
	h, e := Open(workspace)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { h.Close() }()
	text := fixture(t, map[string]any{"groups": []any{
		map[string]any{"name": "S", "type": "select", "members": []string{"direct", "reject"}, "selected": "direct"},
		map[string]any{"name": "A", "type": "fallback", "members": []string{"direct"}, "probe": map[string]any{"url": "http://127.0.0.1:1/"}},
	}})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	for _, fixed := range []bool{true, false} {
		root, _ := sourceJSON(h.doc)
		var k map[string]any
		json.Unmarshal(root["kernel"], &k)
		groups := k["groups"].([]any)
		groups[0].(map[string]any)["selected"] = "reject"
		if fixed {
			groups[1].(map[string]any)["fixed"] = "direct"
		} else {
			delete(groups[1].(map[string]any), "fixed")
		}
		root["kernel"] = rawJSON(k)
		reply, e := h.Apply(string(rawJSON(root)))
		if e != nil {
			t.Fatal(e)
		}
		if reply.(map[string]any)["selection_only"] != true {
			t.Fatal("unexpected runtime apply")
		}
		if e := h.Close(); e != nil {
			t.Fatal(e)
		}
		reopened, err := Open(workspace)
		if err != nil {
			t.Fatal(err)
		}
		h = reopened
		if h.doc.config.Groups[0].Selected != "reject" || (h.doc.config.Groups[1].Fixed == "direct") != fixed {
			t.Fatal("selection or pin lost on reopen")
		}
		if _, e := h.Start(); e != nil {
			t.Fatal(e)
		}
	}
}
