package clientcore

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func legacySmartSeed(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	h := fullHost(t)
	remote := strings.Replace(fullFixture, "type: select", "type: url-test", 1)
	p := fullPreview(t, h, remote, "")
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	root, _ := sourceJSON(h.doc)
	k := rawObject(root["kernel"])
	gs := rawArray(k, "groups")
	g := rawObject(gs[0])
	g["type"] = rawJSON("smart")
	g["smart"] = rawJSON(map[string]any{"scope": "site", "exploration_rate": .01, "adaptive_dial": false})
	g["include_all_proxies"] = rawJSON(true)
	g["fixed"] = rawJSON("n")
	g["priority"] = rawJSON(map[string]float64{"n": 1.5, "gone": .5})
	g["tolerance"] = rawJSON(0)
	g["damping"] = rawJSON(map[string]any{"relative_improvement": 0, "min_dwell": "0s"})
	g["probe"] = rawJSON(map[string]any{"url": "https://probe.invalid/custom", "timeout": "9s", "expected_status": "204"})
	gs[0] = rawJSON(g)
	k["groups"] = rawJSON(gs)
	// A local node differs from its old remote snapshot. Migration must not
	// reconstruct kernel from that old remote declaration/credentials.
	nodes := rawArray(k, "outbounds")
	node := rawObject(nodes[0])
	node["port"] = rawJSON(1081)
	nodes[0] = rawJSON(node)
	k["outbounds"] = rawJSON(nodes)
	root["kernel"] = rawJSON(k)
	subs, e := subscriptionsOf(root)
	if e != nil {
		t.Fatal(e)
	}
	sg := rawObject(subs[0].Snapshot.Groups[0])
	sg["type"] = rawJSON("smart")
	sg["smart"] = g["smart"]
	subs[0].Snapshot.Groups[0] = rawJSON(sg)
	subs[0].State = map[string]map[string]json.RawMessage{"pick": groupState(rawJSON(g))}
	subs[0].Overlay.Groups = map[string]map[string]json.RawMessage{"pick": {"type": rawJSON("smart"), "smart": g["smart"], "include_all_proxies": rawJSON(true), "damping": g["damping"], "tolerance": rawJSON(0)}}
	root["subscriptions"] = rawJSON(subs)
	return root
}
func assertRestoredSmartSource(t *testing.T, d document) {
	t.Helper()
	root, e := sourceJSON(d)
	if e != nil {
		t.Fatal(e)
	}
	groups := rawArray(rawObject(root["kernel"]), "groups")
	for _, v := range groups {
		g := rawObject(v)
		if string(g["type"]) != `"smart"` || g["smart"] == nil {
			t.Fatal("legacy kernel survived", string(v))
		}
	}
	subs, e := subscriptionsOf(root)
	if e != nil {
		t.Fatal(e)
	}
	for _, s := range subs {
		for _, v := range s.Snapshot.Groups {
			g := rawObject(v)
			if string(g["type"]) != `"smart"` || g["smart"] == nil {
				t.Fatal("legacy snapshot survived")
			}
		}
		for _, p := range s.Overlay.Groups {
			if p["smart"] == nil || string(p["type"]) != `"smart"` {
				t.Fatal("legacy patch survived")
			}
		}
	}
}
func TestRestoredSmartOpenPreservesAcceptedJSONYAMLAndPreservesHistory(t *testing.T) {
	for _, format := range []DocumentFormat{FormatJSON, FormatYAML, FormatYML} {
		t.Run(string(format), func(t *testing.T) {
			root := legacySmartSeed(t)
			original := string(rawJSON(root)) + "\n"
			if format != FormatJSON {
				var v yaml.Node
				if e := yaml.Unmarshal([]byte(original), &v); e != nil {
					t.Fatal(e)
				}
				b, e := yaml.Marshal(&v)
				if e != nil {
					t.Fatal(e)
				}
				original = "# retained source\n" + string(b)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, format.filename())
			if e := os.WriteFile(path, []byte(original), 0600); e != nil {
				t.Fatal(e)
			}
			// Avoid re-running the unrelated, previously completed IPv6 migration.
			_ = os.WriteFile(filepath.Join(dir, "c16-network-migration.json"), []byte(`{"version":1,"entries":[]}`), 0600)
			history := []byte(`{"total_up":1234,"total_down":5678,"daily":[{"date":"2026-11-02","up":12,"down":34}]}` + "\n")
			_ = os.WriteFile(filepath.Join(dir, "traffic-history.json"), history, 0600)
			h, e := Open(dir)
			if e != nil {
				t.Fatal(e)
			}
			assertRestoredSmartSource(t, h.doc)
			migrated := h.doc.text
			if migrated != original {
				t.Fatal("Open rewrote Smart source bytes")
			}
			g := h.doc.config.Groups[0]
			if g.Name != "pick" || g.Type != "smart" || g.Fixed != "n" || g.Priority["n"] != 1.5 || g.Priority["gone"] != .5 || !g.IncludeAllProxies || !g.ToleranceSet || g.Tolerance != 0 || g.Damping.RelativeImprovement == nil || *g.Damping.RelativeImprovement != 0 || *g.Damping.MinDwell != 0 || g.Probe.Interval.Value() != 5*time.Minute || g.Probe.Timeout.Value() != 9*time.Second {
				t.Fatal("migration lost values", g)
			}
			after, _ := sourceJSON(h.doc)
			oldK, newK := rawObject(root["kernel"]), rawObject(after["kernel"])
			for _, key := range []string{"outbounds", "routing"} {
				if !sameJSON(oldK[key], newK[key]) {
					t.Fatal("unrelated source changed", key)
				}
			}
			groups := rawArray(newK, "groups")
			probe := rawObject(rawObject(groups[0])["probe"])
			if probe["interval"] != nil {
				t.Fatal("default interval materialized into source")
			}
			if h.history.TotalUp != 1234 || h.history.TotalDown != 5678 {
				t.Fatal("history not retained")
			}
			if e := h.Close(); e != nil {
				t.Fatal(e)
			}
			saved, _ := os.ReadFile(path)
			backup, _ := os.ReadFile(filepath.Join(dir, "client-before-no-smart."+string(format)))
			hist, _ := os.ReadFile(filepath.Join(dir, "traffic-history.json"))
			if string(saved) != migrated || len(backup) != 0 || !bytes.Equal(hist, history) {
				t.Fatal("source transaction/backup/history changed")
			}
			h, e = Open(dir)
			if e != nil {
				t.Fatal(e)
			}
			if h.doc.text != migrated {
				t.Fatal("migration not idempotent")
			}
			_ = h.Close()
		})
	}
}
func TestRestoredSmartInvalidApplyAndOpenLeaveSourceUntouched(t *testing.T) {
	h := fullHost(t)
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	seed := legacySmartSeed(t)
	for _, where := range []string{"kernel", "snapshot", "overlay", "unknown", "probe"} {
		t.Run(where, func(t *testing.T) {
			var root map[string]json.RawMessage
			_ = json.Unmarshal(rawJSON(seed), &root)
			k := rawObject(root["kernel"])
			gs := rawArray(k, "groups")
			g := rawObject(gs[0])
			switch where {
			case "kernel":
				g["smart"] = rawJSON(map[string]any{"unknown": true})
			case "unknown":
				g["future_field"] = rawJSON(true)
			case "probe":
				p := rawObject(g["probe"])
				p["unknown"] = rawJSON(true)
				g["probe"] = rawJSON(p)
			default:
				var subs []map[string]json.RawMessage
				_ = json.Unmarshal(root["subscriptions"], &subs)
				if where == "snapshot" {
					s := rawObject(subs[0]["snapshot"])
					ss := rawArray(s, "groups")
					v := rawObject(ss[0])
					v["smart"] = rawJSON(map[string]any{"unknown": true})
					ss[0] = rawJSON(v)
					s["groups"] = rawJSON(ss)
					subs[0]["snapshot"] = rawJSON(s)
				} else {
					o := rawObject(subs[0]["overlay"])
					var patches map[string]map[string]json.RawMessage
					_ = json.Unmarshal(o["groups"], &patches)
					patches["pick"]["smart"] = rawJSON(map[string]any{"unknown": true})
					o["groups"] = rawJSON(patches)
					subs[0]["overlay"] = rawJSON(o)
				}
				root["subscriptions"] = rawJSON(subs)
			}
			gs[0] = rawJSON(g)
			k["groups"] = rawJSON(gs)
			root["kernel"] = rawJSON(k)
			text := string(rawJSON(root))
			before := h.doc.text
			running := h.server
			generation := running.GenerationID()
			disk, _ := os.ReadFile(h.path)
			if _, e := h.Apply(text); e == nil {
				t.Fatal("invalid apply accepted")
			}
			after, _ := os.ReadFile(h.path)
			if h.doc.text != before || !bytes.Equal(disk, after) || h.server != running || h.server.GenerationID() != generation {
				t.Fatal("invalid apply affected source")
			}
			dir := t.TempDir()
			path := filepath.Join(dir, FormatJSON.filename())
			_ = os.WriteFile(path, []byte(text), 0600)
			if x, e := Open(dir); e == nil {
				x.Close()
				t.Fatal("invalid Open accepted")
			}
			intact, _ := os.ReadFile(path)
			if string(intact) != text {
				t.Fatal("invalid Open mutated source")
			}
			if _, e := os.Stat(filepath.Join(dir, "client-before-no-smart.json")); !os.IsNotExist(e) {
				t.Fatal("invalid Open published backup/transaction")
			}
		})
	}
}
func TestRestoredSmartSubscriptionRefreshAndDynamicWeights(t *testing.T) {
	h := fullHost(t)
	remote := `proxies: [{name: n, type: socks5, server: example.org, port: 1080}]
proxy-groups: [{name: Auto, type: smart, proxies: [n], include-all-proxies: true, filter: '.*', fixed: n, priority: {n: 1.5, gone: 0.5}, smart: {scope: site, exploration_rate: 0.01, adaptive_dial: false}, tolerance: 0, damping: {relative_improvement: 0, min_dwell: 0s}, url: 'https://probe.invalid/custom', timeout: 9000}]
rules: ['DOMAIN,example.org,Auto', 'MATCH,Auto']
`
	p := fullPreview(t, h, remote, "")
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	assertRestoredSmartSource(t, h.doc)
	root, _ := sourceJSON(h.doc)
	k := rawObject(root["kernel"])
	gs := rawArray(k, "groups")
	g := rawObject(gs[0])
	g["priority"] = rawJSON(map[string]float64{"n": 2, "gone": .5})
	gs[0] = rawJSON(g)
	k["groups"] = rawJSON(gs)
	root["kernel"] = rawJSON(k)
	if _, e := h.Apply(string(rawJSON(root))); e != nil {
		t.Fatal(e)
	}
	for _, nodes := range []string{"n", "gone", "n"} {
		// Remote still declares legacy Smart every time. Only its current nodes
		// change; our local named preferences remain separate from that snapshot.
		input := strings.Replace(remote, "name: n, type: socks5", "name: "+nodes+", type: socks5", 1)
		if nodes != "n" {
			input = strings.Replace(input, "proxies: [n]", "proxies: [gone]", 1)
			input = strings.Replace(input, "fixed: n, ", "", 1)
		}
		q := fullPreview(t, h, input, p.ID)
		if _, e := h.Apply(q.Text); e != nil {
			t.Fatal(e)
		}
		assertRestoredSmartSource(t, h.doc)
		got := h.doc.config.Groups[0]
		if got.Name != "Auto" || got.Type != "smart" || !reflect.DeepEqual(got.Priority, map[string]float64{"n": 2, "gone": .5}) {
			t.Fatal("refresh lost type/named weights", got)
		}
	}
}

func TestRestoredSmartExplicitProbeZeroAndOtherTypesUntouched(t *testing.T) {
	root := legacySmartSeed(t)
	k := rawObject(root["kernel"])
	gs := rawArray(k, "groups")
	g := rawObject(gs[0])
	p := rawObject(g["probe"])
	p["interval"] = rawJSON("0s")
	g["probe"] = rawJSON(p)
	gs[0] = rawJSON(g)
	other := []json.RawMessage{
		rawJSON(map[string]any{"name": "select-kept", "type": "select", "members": []string{"n"}, "selected": "n"}),
		rawJSON(map[string]any{"name": "fallback-kept", "type": "fallback", "members": []string{"n"}, "fixed": "n", "probe": map[string]any{"url": "http://127.0.0.1:9/", "interval": "7m"}}),
		rawJSON(map[string]any{"name": "lb-kept", "type": "load-balance", "members": []string{"n"}, "strategy": "round-robin", "probe": map[string]any{"url": "http://127.0.0.1:9/"}}),
		rawJSON(map[string]any{"name": "relay-kept", "type": "relay", "members": []string{"n"}}),
	}
	gs = append(gs, other...)
	k["groups"] = rawJSON(gs)
	root["kernel"] = rawJSON(k)
	d, e := parseDocument(string(rawJSON(root)), t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	after, _ := sourceJSON(d)
	out := rawArray(rawObject(after["kernel"]), "groups")
	if !sameRawArray(out[1:], other) {
		t.Fatal("non-Smart types changed")
	}
	probe := rawObject(rawObject(out[0])["probe"])
	if string(probe["interval"]) != `"0s"` {
		t.Fatal("explicit probe zero lost")
	}
	if d.config.Groups[0].Probe.Interval.Value() != 5*time.Minute {
		t.Fatal("Smart projected default not 5m")
	}
}

func TestRestoredSmartSubscriptionCollisionRemapsWeightsFixedAndRules(t *testing.T) {
	h := fullHost(t)
	manual := fixture(t, map[string]any{"outbounds": []any{map[string]any{"name": "n", "type": "socks5", "server": "manual.invalid", "port": 99}}, "groups": []any{map[string]any{"name": "Auto", "type": "select", "members": []string{"direct"}}}, "routing": map[string]any{"final": "Auto"}})
	if _, e := h.Apply(manual); e != nil {
		t.Fatal(e)
	}
	remote := `proxies: [{name: n, type: socks5, server: remote.invalid, port: 1080}]
proxy-groups: [{name: Auto, type: smart, proxies: [n], fixed: n, priority: {n: 1.5}, url: 'http://127.0.0.1:9/', smart: {scope: group}}]
rules: ['DOMAIN,remote.invalid,Auto', 'MATCH,Auto']
`
	p := fullPreview(t, h, remote, "")
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	root, _ := sourceJSON(h.doc)
	subs, e := subscriptionsOf(root)
	if e != nil {
		t.Fatal(e)
	}
	node, groupName := subs[0].Names["n"], subs[0].Names["Auto"]
	if node == "n" || groupName == "Auto" {
		t.Fatal("collision fixture did not allocate stable names")
	}
	for range 2 {
		var found bool
		for _, g := range h.doc.config.Groups {
			if g.Name == groupName {
				found = true
				if g.Type != "smart" || g.Fixed != node || g.Priority[node] != 1.5 || len(g.Priority) != 1 || !reflect.DeepEqual(g.Members, []string{node}) {
					t.Fatal("remapped preferences lost", g)
				}
			}
		}
		if !found || h.doc.config.Routing.Final != groupName {
			t.Fatal("group references lost")
		}
		for _, o := range h.doc.config.Outbounds {
			if o.Name == "n" && o.Port != 99 {
				t.Fatal("manual node overwritten")
			}
		}
		q := fullPreview(t, h, remote, p.ID)
		if _, e := h.Apply(q.Text); e != nil {
			t.Fatal(e)
		}
	}
}
