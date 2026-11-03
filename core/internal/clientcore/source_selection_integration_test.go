package clientcore

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// Integration of the two accepted packages: preferences are hot even when the
// chosen leaf comes from include_group; editing the reference remains full apply.
func TestSourceGroupHotSelectionIntegration(t *testing.T) {
	h := newHost(t)
	if _, e := h.Apply(sourceClientDocument(t)); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	gen, bridge, manual := h.server.StatsView().Reload.Generation, h.bridge, h.manualCtx
	change := func(name, key, value string) any {
		var root map[string]any
		if e := json.Unmarshal([]byte(h.doc.text), &root); e != nil {
			t.Fatal(e)
		}
		for _, v := range root["kernel"].(map[string]any)["groups"].([]any) {
			g := v.(map[string]any)
			if g["name"] == name {
				g[key] = value
			}
		}
		reply, e := h.Apply(string(rawJSON(root)))
		if e != nil {
			t.Fatal(e)
		}
		return reply
	}
	for _, edit := range [][3]string{{"target", "selected", "c"}, {"source", "selected", "b"}, {"target", "selected", "a"}} {
		reply := change(edit[0], edit[1], edit[2]).(map[string]any)
		if reply["selection_only"] != true || h.server.StatsView().Reload.Generation != gen || h.bridge != bridge || h.manualCtx != manual {
			t.Fatal("source leaf selection rebuilt runtime", reply)
		}
		if got := sourceClientMembers(h.server.CurrentConfig(), "target"); !reflect.DeepEqual(got, []string{"outside", "b", "c", "a"}) {
			t.Fatal("source selection changed leaf set", got)
		}
		if got := sourceClientMembers(h.doc.config, "target"); !reflect.DeepEqual(got, []string{"outside"}) {
			t.Fatal("expanded leaves written back", got)
		}
		disk, e := os.ReadFile(h.path)
		if e != nil || string(disk) != h.doc.text {
			t.Fatal("selection not persisted", e)
		}
	}
	// Reset the chosen preference to a member shared by both sources before the
	// actual reference edit; this must stay on the complete document apply path.
	change("target", "selected", "c")
	reply := change("target", "include_group", "nested").(map[string]any)
	if reply["selection_only"] == true || h.server.StatsView().Reload.Generation == gen {
		t.Fatal("reference edit incorrectly treated as a hot preference", reply)
	}
	if got := sourceClientMembers(h.server.CurrentConfig(), "target"); !reflect.DeepEqual(got, []string{"outside", "c", "b"}) {
		t.Fatal(got)
	}
}
