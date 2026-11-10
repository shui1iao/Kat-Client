package clientcore

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/shui1iao/Kat/internal/kernel"
	"gopkg.in/yaml.v3"
)

func sourceClientDocument(t *testing.T) string {
	return fixture(t, map[string]any{
		"outbounds": []any{
			map[string]any{"name": "a", "type": "socks5", "server": "example.org", "port": 9},
			map[string]any{"name": "b", "type": "socks5", "server": "example.org", "port": 9},
			map[string]any{"name": "c", "type": "socks5", "server": "example.org", "port": 9},
			map[string]any{"name": "outside", "type": "socks5", "server": "example.org", "port": 9},
		},
		"groups": []any{
			map[string]any{"name": "target", "type": "select", "members": []string{"outside"}, "include_group": "source"},
			map[string]any{"name": "source", "type": "select", "members": []string{"b", "nested", "a"}, "selected": "a"},
			map[string]any{"name": "nested", "type": "select", "members": []string{"c", "b"}},
		},
	})
}
func sourceClientMembers(c kernel.Config, name string) []string {
	for _, g := range c.Groups {
		if g.Name == name {
			return g.Members
		}
	}
	return nil
}
func TestSourceGroupPreviewScopedAndReadOnly(t *testing.T) {
	h := newHost(t)
	text := sourceClientDocument(t)
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	for _, running := range []bool{false, true} {
		if running {
			if _, e := h.Start(); e != nil {
				t.Fatal(e)
			}
		}
		for _, tc := range []struct {
			params map[string]any
			want   []string
			bad    bool
		}{
			{map[string]any{"include_group": "source"}, []string{"b", "c", "a"}, false},
			{map[string]any{"include_group": "source", "group_name": "target", "filter": "^(a|c)$"}, []string{"c", "a"}, false},
			{map[string]any{"include_group": "source", "filter": "^outside$"}, []string{}, false},
			{map[string]any{"include_group": "source", "exclude_filter": "b"}, []string{"c", "a"}, false},
			{map[string]any{"include_group": "source", "filter": "["}, nil, true},
			{map[string]any{"include_group": "source", "exclude_filter": "["}, nil, true},
			{map[string]any{"include_group": "missing"}, nil, true},
			{map[string]any{"include_group": "source", "group_name": "source"}, nil, true},
			{map[string]any{"include_group": "target", "group_name": "nested"}, nil, true},
			{map[string]any{}, []string{}, false},
		} {
			v, e := h.Request(context.Background(), "group.filter_preview", rawJSON(tc.params))
			if e != nil {
				t.Fatal(e)
			}
			out := v.(map[string]any)
			if tc.bad {
				if out["error"] == nil || len(out["names"].([]string)) != 0 {
					t.Fatal(out)
				}
				continue
			}
			if out["error"] != nil || !reflect.DeepEqual(out["names"], tc.want) {
				t.Fatal(tc.params, out, tc.want)
			}
		}
	}
	disk, e := os.ReadFile(h.path)
	if e != nil || string(disk) != text || h.doc.text != text {
		t.Fatal("preview rewrote source", e)
	}
	if got := sourceClientMembers(h.doc.config, "target"); !reflect.DeepEqual(got, []string{"outside"}) {
		t.Fatal("preview persisted expansion", got)
	}
	if got := sourceClientMembers(h.server.CurrentConfig(), "target"); !reflect.DeepEqual(got, []string{"outside", "b", "c", "a"}) {
		t.Fatal(got)
	}
	// A normal source member edit must be visible without resaving the consumer.
	var root map[string]any
	_ = json.Unmarshal([]byte(text), &root)
	gs := root["kernel"].(map[string]any)["groups"].([]any)
	gs[1].(map[string]any)["members"] = []string{"a"}
	if _, e := h.Apply(string(rawJSON(root))); e != nil {
		t.Fatal(e)
	}
	if got := sourceClientMembers(h.server.CurrentConfig(), "target"); !reflect.DeepEqual(got, []string{"outside", "a"}) {
		t.Fatal(got)
	}
}
func TestSourceGroupInvalidApplyRetainsDiskAndRuntime(t *testing.T) {
	for _, running := range []bool{false, true} {
		h := newHost(t)
		text := sourceClientDocument(t)
		if _, e := h.Apply(text); e != nil {
			t.Fatal(e)
		}
		if running {
			if _, e := h.Start(); e != nil {
				t.Fatal(e)
			}
		}
		for _, bad := range []string{"self", "missing", "cycle", "regex", "exclude", "relay", "inherited-reject"} {
			var root map[string]any
			_ = json.Unmarshal([]byte(text), &root)
			gs := root["kernel"].(map[string]any)["groups"].([]any)
			target := gs[0].(map[string]any)
			source := gs[1].(map[string]any)
			switch bad {
			case "self":
				target["include_group"] = "target"
			case "missing":
				target["include_group"] = "gone"
			case "cycle":
				source["members"] = []string{"target"}
			case "regex":
				target["filter"] = "["
			case "exclude":
				target["exclude_filter"] = "["
			case "relay":
				target["type"] = "relay"
				target["members"] = []string{"a"}
			case "inherited-reject":
				target["type"] = "url-test"
				target["probe"] = map[string]any{"url": "http://127.0.0.1:9/"}
				source["members"] = []string{"reject"}
				delete(source, "selected")
			}
			var gen uint64
			if running {
				gen = h.server.GenerationID()
			}
			if _, e := h.Apply(string(rawJSON(root))); e == nil || e.Code != "invalid_kernel" {
				t.Fatal(bad, "invalid config accepted", e)
			}
			disk, e := os.ReadFile(h.path)
			if e != nil || string(disk) != text || h.doc.text != text {
				t.Fatal(bad, "failed apply modified source", e)
			}
			if running && h.server.GenerationID() != gen {
				t.Fatal(bad, "failed apply changed generation")
			}
		}
	}
}
func TestSourceGroupYAMLReferencePreserved(t *testing.T) {
	h := newHost(t)
	var root map[string]any
	_ = json.Unmarshal([]byte(sourceClientDocument(t)), &root)
	b, e := yaml.Marshal(root)
	if e != nil {
		t.Fatal(e)
	}
	text := "# retained source reference\n" + string(b)
	if _, e := h.Apply(text, FormatYAML); e != nil {
		t.Fatal(e)
	}
	if h.doc.text != text || !strings.Contains(h.doc.text, "include_group: source") {
		t.Fatal("YAML source changed")
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	if got := sourceClientMembers(h.server.CurrentConfig(), "target"); !reflect.DeepEqual(got, []string{"outside", "b", "c", "a"}) {
		t.Fatal(got)
	}
	if _, e := h.Reload(); e != nil {
		t.Fatal(e)
	}
	disk, e := os.ReadFile(h.path)
	if e != nil || string(disk) != text {
		t.Fatal("reload wrote YAML expansion", e)
	}
}
func TestSourceGroupSubscriptionOverlayRefreshAndMissingSource(t *testing.T) {
	h := fullHost(t)
	remote := strings.Replace(fullFixture, "rules:\n", "  - {name: consumer, type: select, proxies: [DIRECT]}\nrules:\n", 1)
	p := fullPreview(t, h, remote, "")
	if _, e := h.Apply(p.Text, p.Format); e != nil {
		t.Fatal(e)
	}
	root, _ := sourceJSON(h.doc)
	k := rawObject(root["kernel"])
	gs := rawArray(k, "groups")
	for i, g := range gs {
		if rawName(g) == "consumer" {
			m := rawObject(g)
			m["include_group"] = rawJSON("pick")
			gs[i] = rawJSON(m)
		}
	}
	k["groups"] = rawJSON(gs)
	root["kernel"] = rawJSON(k)
	if _, e := h.Apply(string(rawJSON(root))); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	if got := sourceClientMembers(h.server.CurrentConfig(), "consumer"); !reflect.DeepEqual(got, []string{"direct", "n"}) {
		t.Fatal(got)
	}
	next := strings.Replace(remote, "{name: n,", "{name: fresh,", 1)
	next = strings.Replace(next, "[n, DIRECT]", "[fresh, DIRECT]", 1)
	q := fullPreview(t, h, next, p.ID)
	if _, e := h.Apply(q.Text, q.Format); e != nil {
		t.Fatal(e)
	}
	if got := sourceClientMembers(h.server.CurrentConfig(), "consumer"); !reflect.DeepEqual(got, []string{"direct", "fresh"}) {
		t.Fatal("refresh froze source nodes", got)
	}
	root, _ = sourceJSON(h.doc)
	owners, e := subscriptionsOf(root)
	if e != nil || len(owners) != 1 {
		t.Fatal(e)
	}
	if string(owners[0].Overlay.Groups["consumer"]["include_group"]) != `"pick"` {
		t.Fatal("source reference missing from overlay", owners[0].Overlay)
	}
	if got := sourceClientMembers(h.doc.config, "consumer"); !reflect.DeepEqual(got, []string{"direct"}) {
		t.Fatal("source nodes stored as explicit members", got)
	}
	before := h.doc.text
	gen := h.server.GenerationID()
	// Existing ownership policy refuses dangling external/overlay references;
	// remote deletion/rename must not silently clear include_group or drop it.
	renamed := strings.ReplaceAll(next, "pick", "renamed")
	if _, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"text": renamed, "id": p.ID})); e == nil || e.Code != "subscription_conflict" {
		t.Fatal("dangling source rename accepted", e)
	}
	if h.doc.text != before || h.server.GenerationID() != gen {
		t.Fatal("failed refresh changed accepted state")
	}
	disk, err := os.ReadFile(h.path)
	if err != nil || string(disk) != before {
		t.Fatal("failed refresh changed disk", err)
	}
}

func TestSourceGroupSubscriptionFixedPriorityPreserved(t *testing.T) {
	h := fullHost(t)
	initial := strings.Replace(initialDocument, `"kernel":{}`, `"kernel":{"outbounds":[{"name":"outside","type":"socks5","server":"example.org","port":9}]}`, 1)
	if _, e := h.Apply(initial); e != nil {
		t.Fatal(e)
	}
	remote := strings.Replace(fullFixture, "rules:\n", "  - {name: consumer, type: url-test, proxies: [DIRECT], url: 'http://127.0.0.1:9/'}\nrules:\n", 1)
	p := fullPreview(t, h, remote, "")
	if _, e := h.Apply(p.Text, p.Format); e != nil {
		t.Fatal(e)
	}
	root, _ := sourceJSON(h.doc)
	k := rawObject(root["kernel"])
	gs := rawArray(k, "groups")
	for i, g := range gs {
		if rawName(g) == "consumer" {
			m := rawObject(g)
			m["include_group"] = rawJSON("pick")
			m["fixed"] = rawJSON("n")
			m["priority"] = rawJSON(map[string]float64{"n": 2, "outside": 3})
			gs[i] = rawJSON(m)
		}
	}
	k["groups"] = rawJSON(gs)
	root["kernel"] = rawJSON(k)
	if _, e := h.Apply(string(rawJSON(root))); e != nil {
		t.Fatal(e)
	}
	next := strings.Replace(remote, "proxy-groups:\n", "  - {name: added, type: socks5, server: example.org, port: 9}\nproxy-groups:\n", 1)
	next = strings.Replace(next, "[n, DIRECT]", "[n, added, DIRECT]", 1)
	q := fullPreview(t, h, next, p.ID)
	for _, change := range q.Changes {
		if strings.Contains(change, "权重") || strings.Contains(change, "手动选择的成员已移除") {
			t.Fatal("refresh falsely reported lost dynamic state", change)
		}
	}
	if _, e := h.Apply(q.Text, q.Format); e != nil {
		t.Fatal(e)
	}
	for _, g := range h.doc.config.Groups {
		if g.Name == "consumer" && (g.Fixed != "n" || g.Priority["n"] != 2 || g.Priority["outside"] != 3) {
			t.Fatal("source overlay cleared preferences/weights", g)
		}
	}
}
