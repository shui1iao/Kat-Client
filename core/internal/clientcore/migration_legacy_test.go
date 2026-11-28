package clientcore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/elevated"
	"github.com/shui1iao/Kat/internal/kernel"
	"gopkg.in/yaml.v3"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Explicitly simulates loading an old file before a running instance, not a
// public creation/edit API. This preserves server-provider compatibility tests.
func applyLegacyFixture(h *Host, text string, formats ...DocumentFormat) (any, *Error) {
	format := h.doc.format
	if len(formats) > 0 {
		format = formats[0]
	}
	d, e := parseDocument(text, h.workspace, format)
	if e != nil {
		return nil, e
	}
	root, _ := sourceJSON(d)
	var k map[string]json.RawMessage
	_ = json.Unmarshal(root["kernel"], &k)
	if len(rawArray(k, "providers")) > 0 && h.server == nil {
		if err := os.WriteFile(h.path, []byte(text), 0600); err != nil {
			return nil, fail("save_failed", "", "fixture write")
		}
		h.doc = d
		h.sourceInfo, _ = os.Lstat(h.path)
		return h.Document(), nil
	}
	return h.Apply(text, formats...)
}

func legacyGateText(t *testing.T, root map[string]json.RawMessage, format DocumentFormat) string {
	t.Helper()
	b, e := json.MarshalIndent(root, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if format == FormatJSON {
		return " " + string(b) + "\n"
	}
	var n yaml.Node
	if e := yaml.Unmarshal(b, &n); e != nil {
		t.Fatal(e)
	}
	b, e = yaml.Marshal(&n)
	if e != nil {
		t.Fatal(e)
	}
	return "# exact legacy source\n" + string(b)
}
func legacyGateModel(t *testing.T, root map[string]json.RawMessage, omitted bool) map[string]json.RawMessage {
	t.Helper()
	var copy map[string]json.RawMessage
	if e := json.Unmarshal(rawJSON(root), &copy); e != nil {
		t.Fatal(e)
	}
	var subs []map[string]json.RawMessage
	if e := json.Unmarshal(copy["subscriptions"], &subs); e != nil {
		t.Fatal(e)
	}
	if omitted {
		delete(subs[0], "model")
	} else {
		subs[0]["model"] = rawJSON(0)
	}
	copy["subscriptions"] = rawJSON(subs)
	return copy
}
func legacyGateFiles(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	e := filepath.WalkDir(dir, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		name, e := filepath.Rel(dir, path)
		if e != nil {
			return e
		}
		out[name] = string(b)
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func assertLegacyGateError(t *testing.T, e error) {
	t.Helper()
	var de *Error
	if !errors.As(e, &de) || de.Code != "legacy_smart_subscription_unsupported" || !strings.Contains(de.Message, "暂不支持") || !strings.Contains(de.Message, "Model<2") || !strings.Contains(de.Message, "未修改") {
		t.Fatal("missing readable narrow refusal", e)
	}
}

func TestRestoredSmartGateOpenPreservesAllBytesBeforeBackups(t *testing.T) {
	seed := legacySmartSeed(t)
	for _, format := range []DocumentFormat{FormatJSON, FormatYAML, FormatYML} {
		for _, omitted := range []bool{false, true} {
			t.Run(string(format)+map[bool]string{false: "/explicit-zero", true: "/omitted"}[omitted], func(t *testing.T) {
				dir := t.TempDir()
				initial, e := Open(dir)
				if e != nil {
					t.Fatal(e)
				}
				if e := initial.Close(); e != nil {
					t.Fatal(e)
				}
				if e := os.Remove(filepath.Join(dir, FormatJSON.filename())); e != nil {
					t.Fatal(e)
				}
				input := legacyGateText(t, legacyGateModel(t, seed, omitted), format)
				if e := os.WriteFile(filepath.Join(dir, format.filename()), []byte(input), 0600); e != nil {
					t.Fatal(e)
				}
				for name, value := range map[string]string{
					"traffic-history.json":                             "{\"total_up\":123,\"total_down\":456,\"daily\":[]}\n",
					"client-before-no-smart." + string(format):         "existing independent backup\n",
					"subscription-v1-before-upgrade." + string(format): "existing v1 backup\n",
					"connection-history.jsonl":                         "existing independent connection record\n",
				} {
					if e := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); e != nil {
						t.Fatal(e)
					}
				}
				before := legacyGateFiles(t, dir)
				h, e := Open(dir)
				if e == nil {
					h.Close()
					t.Fatal("unsafe legacy source opened")
				}
				assertLegacyGateError(t, e)
				after := legacyGateFiles(t, dir)
				if !reflect.DeepEqual(before, after) {
					t.Fatal("rejected Open changed source, backups, history or file list")
				}
			})
		}
	}
}

func TestRestoredSmartGateValidateApplyAndNativeImportKeepAcceptedRuntime(t *testing.T) {
	seed := legacyGateModel(t, legacySmartSeed(t), false)
	h := fullHost(t)
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	for _, format := range []DocumentFormat{FormatJSON, FormatYAML, FormatYML} {
		t.Run(string(format), func(t *testing.T) {
			input := legacyGateText(t, seed, format)
			before := legacyGateFiles(t, h.workspace)
			accepted := h.doc.text
			acceptedFormat := h.doc.format
			running := h.server
			generation := running.GenerationID()
			history, _ := json.Marshal(h.history)
			// Native import is otherwise draft-only; this unsafe combination must not
			// even return an apparently usable native candidate.
			if _, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"text": input})); e == nil {
				t.Fatal("native import accepted unsafe combination")
			} else {
				assertLegacyGateError(t, e)
			}
			if e := h.Validate(input, format); e == nil {
				t.Fatal("validate accepted unsafe combination")
			} else {
				assertLegacyGateError(t, e)
			}
			if _, e := h.Apply(input, format); e == nil {
				t.Fatal("apply accepted unsafe combination")
			} else {
				assertLegacyGateError(t, e)
			}
			afterHistory, _ := json.Marshal(h.history)
			if h.doc.text != accepted || h.doc.format != acceptedFormat || h.server != running || h.server.GenerationID() != generation || string(history) != string(afterHistory) || !reflect.DeepEqual(before, legacyGateFiles(t, h.workspace)) {
				t.Fatal("rejection changed accepted source, runtime, backups or history")
			}
		})
	}
}

func TestRestoredSmartGateDoesNotBlockExistingV1WithoutConversion(t *testing.T) {
	seed := legacySmartSeed(t)
	// Native URLTest is not converted or guessed back to Smart. Make an
	// explicit non-Smart v1 document, retaining the existing ownership path.
	normalized := map[string]json.RawMessage{}
	if e := json.Unmarshal(rawJSON(seed), &normalized); e != nil {
		t.Fatal(e)
	}
	kernel := rawObject(normalized["kernel"])
	gs := rawArray(kernel, "groups")
	for i, b := range gs {
		g := rawObject(b)
		g["type"] = rawJSON("url-test")
		delete(g, "smart")
		gs[i] = rawJSON(g)
	}
	kernel["groups"] = rawJSON(gs)
	normalized["kernel"] = rawJSON(kernel)
	var subs []map[string]json.RawMessage
	json.Unmarshal(normalized["subscriptions"], &subs)
	for _, sub := range subs {
		snap := rawObject(sub["snapshot"])
		sg := rawArray(snap, "groups")
		for i, b := range sg {
			g := rawObject(b)
			g["type"] = rawJSON("url-test")
			delete(g, "smart")
			sg[i] = rawJSON(g)
		}
		snap["groups"] = rawJSON(sg)
		sub["snapshot"] = rawJSON(snap)
		for _, key := range []string{"state"} {
			st := rawObject(sub[key])
			for n, b := range st {
				g := rawObject(b)
				delete(g, "smart")
				if g["type"] != nil {
					g["type"] = rawJSON("url-test")
				}
				st[n] = rawJSON(g)
			}
			sub[key] = rawJSON(st)
		}
		ov := rawObject(sub["overlay"])
		patches := rawObject(ov["groups"])
		for n, b := range patches {
			g := rawObject(b)
			delete(g, "smart")
			g["type"] = rawJSON("url-test")
			patches[n] = rawJSON(g)
		}
		ov["groups"] = rawJSON(patches)
		sub["overlay"] = rawJSON(ov)
	}
	normalized["subscriptions"] = rawJSON(subs)
	root := legacyGateModel(t, normalized, true)
	input := legacyGateText(t, root, FormatJSON)
	d, de := parseDocument(input, t.TempDir())
	if de != nil {
		t.Fatal("ordinary v1 unexpectedly blocked", de)
	}
	if d.text != input {
		t.Fatal("ordinary v1 source normalized unexpectedly")
	}
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, FormatJSON.filename()), []byte(input), 0600); e != nil {
		t.Fatal(e)
	}
	h, err := Open(dir)
	if err != nil {
		t.Fatal("existing v1 Open changed", err)
	}
	defer h.Close()
	accepted, _ := sourceJSON(h.doc)
	owners, err := subscriptionsOf(accepted)
	if err != nil || owners[0].Model != 2 {
		t.Fatal("existing v1 upgrade no longer runs", err)
	}
	if _, e := os.Stat(filepath.Join(dir, "subscription-v1-before-upgrade.json")); e != nil {
		t.Fatal("existing v1 backup missing", e)
	}
	if _, e := os.Stat(filepath.Join(dir, "client-before-no-smart.json")); !os.IsNotExist(e) {
		t.Fatal("no-conversion input created Smart backup")
	}
}

func TestRestoredSmartGateDoesNotRelaxMalformedLegacyFields(t *testing.T) {
	root := legacyGateModel(t, legacySmartSeed(t), false)
	k := rawObject(root["kernel"])
	gs := rawArray(k, "groups")
	g := rawObject(gs[0])
	g["smart"] = rawJSON(map[string]any{"unknown": true})
	gs[0] = rawJSON(g)
	k["groups"] = rawJSON(gs)
	root["kernel"] = rawJSON(k)
	if _, e := parseDocument(string(rawJSON(root)), t.TempDir()); e == nil || e.Code != "invalid_document" {
		t.Fatal("malformed legacy fields were relaxed", e)
	}
}

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

func TestStage5UpdateShutdownSyncsSourceAndHistoryAndPreservesAllUserData(t *testing.T) {
	dir := t.TempDir()
	h, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	port := func() int {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	hp, sp := port(), port()
	for hp == sp {
		sp = port()
	}
	docText := `{
  "schema_version": 1,
  "client": {
    "mode": "rule",
    "global_group": "auto-group",
    "probe_url": "http://127.0.0.1:1/probe",
    "http_port": ` + strconv.Itoa(hp) + `,
    "socks_port": ` + strconv.Itoa(sp) + `,
    "ipv6": true,
    "close_on_switch": false,
    "sniff": {"enabled": true, "override_destination": false, "tcp_ports": "80,443"}
  },
  "kernel": {
    "dns": {"server": "system"},
    "security": {"allow_loopback": true},
    "outbounds": [
      {"name": "node-a", "type": "socks5", "server": "127.0.0.1", "port": 1080},
      {"name": "node-b", "type": "socks5", "server": "127.0.0.1", "port": 1081}
    ],
    "groups": [
      {"name": "pick", "type": "select", "members": ["node-a", "node-b", "direct"], "selected": "node-a"},
      {"name": "auto-group", "type": "smart", "lazy": true, "fixed": "node-b", "priority": {"node-a": 1.2, "node-b": 0.8}, "smart": {"scope": "site"}, "probe": {"url": "http://127.0.0.1:1/probe", "timeout": "1s", "interval": "1h"}, "members": ["node-a", "node-b"]}
    ],
    "routing": {
      "rules": [
        {"domain_suffix": "example.com", "outbound": "pick"},
        {"ip_cidr": "10.0.0.0/8", "action": "direct"}
      ],
      "final": "auto-group"
    }
  }
}` + "\n"
	if _, de := h.Apply(docText); de != nil {
		h.Close()
		t.Fatal(de)
	}
	// Simulate cumulative traffic checkpoint from c49 / previous session.
	now := time.Now()
	h.mu.Lock()
	h.history.add(now, 12500, 34800)
	if saveErr := h.saveHistory(); saveErr != nil {
		h.mu.Unlock()
		h.Close()
		t.Fatal(saveErr)
	}
	h.mu.Unlock()

	// Write runtime selection state to verify runtime choices survive upgrade/handover.
	selBytes := []byte(`{"version":1,"groups":{"pick":{"selected":"direct","config_default":"node-a"}}}`)
	if err := os.WriteFile(filepath.Join(dir, "runtime.select.json"), selBytes, 0600); err != nil {
		h.Close()
		t.Fatal(err)
	}

	// Drive Host over TransportNamedPipe to verify named-pipe strict update shutdown & resume.
	c2sR, c2sW := io.Pipe()
	s2cR, s2cW := io.Pipe()
	serveDone := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		serveDone <- h.ServeTransport(ctx, c2sR, s2cW, TransportNamedPipe)
	}()
	reader := bufio.NewReader(s2cR)
	rpc := func(id, method string) map[string]json.RawMessage {
		t.Helper()
		req, _ := json.Marshal(map[string]any{"id": id, "method": method, "params": map[string]any{}})
		if _, err := c2sW.Write(append(req, byte(10))); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadBytes(byte(10))
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]json.RawMessage
		if err := json.Unmarshal(line, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	if r := rpc("1", "core.start"); string(r["ok"]) != "true" {
		t.Fatalf("core.start failed: %s", r["error"])
	}
	// First prepare-update, then verify normal requests are paused, then resume-update.
	prep1 := rpc("2", "host.prepare-update")
	if string(prep1["ok"]) != "true" {
		t.Fatalf("prepare-update 1 failed: %s", prep1["error"])
	}
	paused := rpc("3", "status")
	if string(paused["ok"]) != "false" {
		t.Fatal("status should be paused while updatePrepared")
	}
	resumed := rpc("4", "host.resume-update")
	if string(resumed["ok"]) != "true" {
		t.Fatalf("resume-update failed: %s", resumed["error"])
	}
	// Repeating resume while already admitted must remain idempotent.
	for _, id := range []string{"4a", "4b"} {
		if r := rpc(id, "host.resume-update"); string(r["ok"]) != "true" {
			t.Fatalf("duplicate resume failed: %s", r["error"])
		}
	}
	if r := rpc("5", "status"); string(r["ok"]) != "true" {
		t.Fatalf("status after resume failed: %s", r["error"])
	}

	// Add more traffic before final update shutdown.
	h.mu.Lock()
	h.history.add(now, 2500, 5200)
	h.mu.Unlock()

	prep2 := rpc("6", "host.prepare-update")
	if string(prep2["ok"]) != "true" {
		t.Fatalf("prepare-update 2 failed: %s", prep2["error"])
	}
	var ack struct {
		Prepared     bool                `json:"prepared"`
		SourceSaved  bool                `json:"source_saved"`
		HistorySaved bool                `json:"history_saved"`
		Checkpoint   elevated.Checkpoint `json:"checkpoint"`
	}
	if err := json.Unmarshal(prep2["result"], &ack); err != nil || !ack.Prepared || !ack.SourceSaved || !ack.HistorySaved || !ack.Checkpoint.Valid() {
		t.Fatalf("invalid prepare-update ACK: %+v err=%v", ack, err)
	}
	// Close pipe input (simulating Write::Close after persistence ACK) and wait for ServeTransport + Close.
	_ = c2sW.Close()
	if err := <-serveDone; err != nil {
		t.Fatalf("ServeTransport error on clean EOF: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Host.Close failed: %v", err)
	}

	// OpenHandover with committed checkpoint must succeed and preserve all user data and cumulative totals.
	next, err := OpenHandover(dir, ack.Checkpoint)
	if err != nil {
		t.Fatalf("OpenHandover failed: %v", err)
	}
	defer next.Close()

	if next.doc.text != docText {
		t.Fatal("accepted user document changed across handover")
	}
	if !next.doc.client.IPv6 || next.doc.client.HTTPPort != hp || next.doc.client.SOCKSPort != sp {
		t.Fatalf("client preferences lost: %+v", next.doc.client)
	}
	if len(next.doc.config.Groups) != 2 || len(next.doc.config.Outbounds) != 2 || len(next.doc.config.Routing.Rules) != 2 {
		t.Fatal("groups, outbounds or rules lost")
	}
	if next.history.TotalUp != 15000 || next.history.TotalDown != 40000 {
		t.Fatalf("traffic totals mismatch: got (%d, %d), want (15000, 40000)", next.history.TotalUp, next.history.TotalDown)
	}
	// Starting the new server and sampling must NOT double-count previously committed totals,
	// and new traffic must add on top of the committed checkpoint.
	if _, de := next.Start(); de != nil {
		t.Fatal(de)
	}
	next.mu.Lock()
	next.sampleLocked(now)
	if next.history.TotalUp != 15000 || next.history.TotalDown != 40000 {
		next.mu.Unlock()
		t.Fatalf("totals double-counted after Start+sample: (%d, %d)", next.history.TotalUp, next.history.TotalDown)
	}
	next.history.add(now, 500, 1200)
	if next.history.TotalUp != 15500 || next.history.TotalDown != 41200 {
		next.mu.Unlock()
		t.Fatalf("incremental traffic after checkpoint wrong: (%d, %d)", next.history.TotalUp, next.history.TotalDown)
	}
	next.mu.Unlock()
	if _, de := next.Stop(); de != nil {
		t.Fatal(de)
	}
	afterSel, err := os.ReadFile(filepath.Join(dir, "runtime.select.json"))
	if err != nil || !bytes.Contains(afterSel, []byte(`"selected": "direct"`)) {
		t.Fatalf("runtime selection not preserved: %s err=%v", afterSel, err)
	}
}

func legacyHost(t *testing.T, k map[string]any) *Host {
	t.Helper()
	workspace := t.TempDir()
	text := fixture(t, k)
	if e := os.WriteFile(filepath.Join(workspace, "kat-client.json"), []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
	h, e := Open(workspace)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { h.Close() })
	return h
}
func migratePreview(t *testing.T, h *Host, name string) subscriptionPreview {
	t.Helper()
	v, e := h.Request(context.Background(), "subscription.migrate", rawJSON(map[string]any{"name": name}))
	if e != nil {
		t.Fatal(e)
	}
	p, ok := v.(subscriptionPreview)
	if !ok || len(p.Issues) > 0 || p.Token == "" {
		t.Fatalf("bad migration %+v", v)
	}
	return p
}

const legacyNodes = "proxies:\n - {name: keep-a, type: socks5, server: example.org, port: 1080}\n - {name: drop-b, type: socks5, server: example.org, port: 1081}\n"

func TestR4LegacyMigrationHTTPFileFilterAndUse(t *testing.T) {
	for _, kind := range []string{"http", "file"} {
		for _, withUse := range []bool{true, false} {
			for _, filtered := range []bool{true, false} {
				t.Run(kind+"/"+uiJSON([]bool{withUse, filtered}), func(t *testing.T) {
					p := map[string]any{"name": "old", "type": kind}
					path := filepath.Join(t.TempDir(), "nodes")
					os.WriteFile(path, []byte(legacyNodes), 0600)
					if kind == "http" {
						p["url"] = "https://migration.invalid/sub"
						p["headers"] = map[string]string{"X-Source": "private"}
						p["interval"] = "2h"
						p["user_agent"] = "original-agent"
						p["timeout"] = "9s"
					} else {
						p["path"] = path
					}
					if filtered {
						p["filter"] = "keep"
						p["exclude_filter"] = "drop"
						p["exclude_type"] = "trojan"
					}
					k := map[string]any{"providers": []any{p}, "groups": []any{map[string]any{"name": "manual", "type": "select", "members": []string{"direct"}}}}
					if withUse {
						k["groups"].([]any)[0].(map[string]any)["use"] = []string{"old"}
					}
					h := legacyHost(t, k)
					h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
						return []byte(legacyNodes), nil
					}
					before := h.doc.text
					candidate := migratePreview(t, h, "old")
					if h.doc.text != before {
						t.Fatal("preview mutated accepted source")
					}
					if _, e := h.Apply(candidate.Text, candidate.Format); e != nil {
						t.Fatal(e)
					}
					root, _ := sourceJSON(h.doc)
					var kernel map[string]json.RawMessage
					json.Unmarshal(root["kernel"], &kernel)
					if len(rawArray(kernel, "providers")) != 0 {
						t.Fatal("provider survived success")
					}
					subs, e := subscriptionsOf(root)
					if e != nil || len(subs) != 1 || subs[0].Name != "old" {
						t.Fatal(subs, e)
					}
					want := 2
					if filtered {
						want = 1
					}
					if len(subs[0].Snapshot.Outbounds) != want {
						t.Fatal("filter changed", subs)
					}
					if kind == "http" && (subs[0].URL != p["url"] || subs[0].Interval != 7200 || subs[0].SourceOptions.Headers["X-Source"] != "private" || subs[0].SourceOptions.UserAgent != "original-agent") {
						t.Fatal("request settings lost")
					}
					g := map[string]json.RawMessage{}
					json.Unmarshal(rawArray(kernel, "groups")[0], &g)
					if g["use"] != nil {
						t.Fatal("use survived")
					}
					ms := []string{}
					json.Unmarshal(g["members"], &ms)
					expected := 1
					if withUse {
						expected += want
					}
					if len(ms) != expected || ms[0] != "direct" {
						t.Fatal("manual order/use changed", ms)
					}
					// Refresh migrated HTTP content uses the complete ownership path, not providers.
					if kind == "http" {
						v, e := h.previewSubscription(context.Background(), rawJSON(map[string]string{"id": subs[0].ID}))
						if e != nil {
							t.Fatal(e)
						}
						q := v.(subscriptionPreview)
						if len(q.Issues) > 0 {
							t.Fatal(q.Issues)
						}
						if _, e := h.Apply(q.Text); e != nil {
							t.Fatal(e)
						}
					}
				})
			}
		}
	}
}
func TestR4MigrationFailureRetainsBytesAndCanRetry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing")
	h := legacyHost(t, map[string]any{"providers": []any{map[string]any{"name": "old", "type": "file", "path": path}}, "groups": []any{map[string]any{"name": "g", "type": "select", "use": []string{"old"}}}})
	before := h.doc.text
	if _, e := h.previewLegacy(context.Background(), rawJSON(map[string]string{"name": "old"})); e == nil {
		t.Fatal("missing file succeeded")
	}
	b, _ := os.ReadFile(h.path)
	if string(b) != before || h.doc.text != before {
		t.Fatal("failure mutated document")
	}
	os.WriteFile(path, []byte("not a subscription"), 0600)
	if v, e := h.previewLegacy(context.Background(), rawJSON(map[string]string{"name": "old"})); e == nil && v.(subscriptionPreview).Token != "" {
		t.Fatal("invalid file accepted")
	}
	os.WriteFile(path, []byte(legacyNodes), 0600)
	p := migratePreview(t, h, "old")
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
}
func TestR4HTTPMigrationFailureAndAtomicStale(t *testing.T) {
	h := legacyHost(t, map[string]any{"providers": []any{map[string]any{"name": "old", "type": "http", "url": "https://migration.invalid/sub"}}})
	before := h.doc.text
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		return nil, errors.New("secret https://private.invalid/token")
	}
	if _, e := h.previewLegacy(context.Background(), rawJSON(map[string]string{"name": "old"})); e == nil || strings.Contains(e.Error(), "private.invalid") {
		t.Fatal(e)
	}
	if h.doc.text != before {
		t.Fatal("changed on network failure")
	}
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		return []byte(legacyNodes), nil
	}
	p := migratePreview(t, h, "old")
	next := strings.Replace(before, `"mode":"rule"`, `"mode":"direct"`, 1)
	if _, e := h.Apply(next); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Apply(p.Text); e == nil || e.Code != "candidate_expired" {
		t.Fatal("stale migration not rejected", e)
	}
}
func TestR4NoProviderNoOperationAndNewProviderRejected(t *testing.T) {
	h := newHost(t)
	before := h.doc.text
	b, _ := os.ReadFile(h.path)
	root, _ := sourceJSON(h.doc)
	var k map[string]json.RawMessage
	json.Unmarshal(root["kernel"], &k)
	if len(rawArray(k, "providers")) != 0 {
		t.Fatal("fixture")
	}
	// Calling an absent named conversion also cannot change source or stage data.
	if _, e := h.previewLegacy(context.Background(), rawJSON(map[string]string{"name": "absent"})); e == nil {
		t.Fatal("absent converted")
	}
	after, _ := os.ReadFile(h.path)
	if !reflect.DeepEqual(b, after) || h.doc.text != before {
		t.Fatal("no-op rewrote bytes")
	}
	text := strings.Replace(before, `"kernel":{}`, `"kernel":{"providers":[{"name":"new","type":"http","url":"https://migration.invalid/sub"}]}`, 1)
	for _, method := range []string{"document.validate", "document.apply"} {
		if _, e := h.Request(context.Background(), method, rawJSON(map[string]string{"text": text})); e == nil || e.Code != "legacy_provider_unsupported" || e.Message != "节点订阅已不再支持，请使用完整订阅" || e.Detail != nil {
			t.Fatal(method, e)
		}
	}
	if _, e := h.Request(context.Background(), "provider.refresh", rawJSON(map[string]string{"name": "new"})); e == nil || e.Code != "unknown_method" {
		t.Fatal(e)
	}
}
func TestR4LegacyUseCannotBeAddedOrEdited(t *testing.T) {
	h := legacyHost(t, map[string]any{"providers": []any{map[string]any{"name": "old", "type": "http", "url": "https://migration.invalid/sub"}}, "groups": []any{map[string]any{"name": "g", "type": "select", "members": []string{"direct"}}}})
	next := strings.Replace(h.doc.text, `"members":["direct"]`, `"members":["direct"],"use":["old"]`, 1)
	if e := h.Validate(next); e == nil || e.Code != "legacy_provider_unsupported" {
		t.Fatal(e)
	}
}
func TestR4ProbeAllIndependentBudgetsConcurrencyAndStopped(t *testing.T) {
	// Three waves at concurrency two must outlive ONE round budget, while
	// every individual target has ample local handshake/scheduling margin.
	// This distinguishes per-job budgets from a shared whole-batch deadline;
	// merely enlarging the old 80ms/100ms fixture would not establish that.
	const responseDelay = 1250 * time.Millisecond
	const roundBudget = 3 * time.Second
	var in, max atomic.Int32
	var traceMu sync.Mutex
	type requestTime struct{ Start, End time.Time }
	trace := []requestTime{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		n := in.Add(1)
		defer func() {
			in.Add(-1)
			traceMu.Lock()
			trace = append(trace, requestTime{start, time.Now()})
			traceMu.Unlock()
		}()
		for {
			m := max.Load()
			if n <= m || max.CompareAndSwap(m, n) {
				break
			}
		}
		select {
		case <-r.Context().Done():
		case <-time.After(responseDelay):
			w.WriteHeader(204)
		}
	}))
	defer target.Close()
	k := settingsKernel(t)
	o := k["outbounds"].([]any)[0].(map[string]any)
	outs := []any{}
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		q := map[string]any{}
		for k, v := range o {
			q[k] = v
		}
		q["name"] = n
		outs = append(outs, q)
	}
	k["outbounds"] = outs
	delete(k, "groups")
	// Exactly one HEAD per job: connection reuse is not the budget contract
	// under test and must not add a second timed server wait to this fixture.
	h, _ := startSettings(t, k, map[string]any{"probe_url": target.URL, "probe_timeout": "2s", "probe_round_timeout": "3s", "probe_concurrency": 2, "unified_delay": false})
	before := time.Now()
	round := beginAllProbeTest(t, h, context.Background())
	waitAllProbeTest(t, round)
	elapsed := time.Since(before)
	_, projected := round.projection()
	for _, r := range projected {
		t.Logf("node=%q code=%q stage=%q at=%s result=%+v", r.Name, r.ErrorCode, r.ErrorStage, r.At.Format(time.RFC3339Nano), r)
	}
	traceMu.Lock()
	times := append([]requestTime(nil), trace...)
	traceMu.Unlock()
	for i, r := range times {
		t.Logf("request=%d queue_plus_connect=%s start=%s end=%s duration=%s", i, r.Start.Sub(before), r.Start.Format(time.RFC3339Nano), r.End.Format(time.RFC3339Nano), r.End.Sub(r.Start))
	}
	if elapsed <= roundBudget || elapsed > 12*time.Second || max.Load() != 2 {
		t.Fatal("independent-wave budget/concurrency", elapsed, max.Load())
	}
	if len(projected) != 5 || len(times) != 5 {
		t.Fatal("missing/duplicate job or unexpected second measurement", projected, times)
	}
	seen := map[string]bool{}
	for _, r := range projected {
		if seen[r.Name] || r.At.IsZero() || r.ProbeMS == nil || r.ErrorCode != "" {
			t.Fatalf("queued node lost its own budget or result identity: %+v", r)
		}
		seen[r.Name] = true
	}
	if _, e := h.Stop(); e != nil {
		t.Fatal(e)
	}
	if _, e := h.probeAll(context.Background(), nil); e == nil || e.Code != "core_not_running" {
		t.Fatal(e)
	}
}

func TestR4MigrationIndependentAndYAMLNoOperation(t *testing.T) {
	for _, format := range []DocumentFormat{FormatYAML, FormatYML} {
		workspace := t.TempDir()
		before := yamlFixture(17890, 17891) + "# keep exact trailing comment\n"
		path := filepath.Join(workspace, format.filename())
		os.WriteFile(path, []byte(before), 0600)
		h, e := Open(workspace)
		if e != nil {
			t.Fatal(e)
		}
		// c16 explicitly migrates IPv6 once; no-provider reads thereafter stay exact.
		original, _ := os.ReadFile(filepath.Join(workspace, "client-before-c16-network."+string(format)))
		if string(original) != before {
			t.Fatal("c16 exact pre-migration backup")
		}
		before = h.doc.text
		h.Document()
		b, _ := os.ReadFile(path)
		if string(b) != before || h.doc.text != before {
			t.Fatal("no-provider YAML changed")
		}
		h.Close()
	}
	good := filepath.Join(t.TempDir(), "nodes")
	os.WriteFile(good, []byte(legacyNodes), 0600)
	h := legacyHost(t, map[string]any{"providers": []any{map[string]any{"name": "bad", "type": "file", "path": good + "-missing"}, map[string]any{"name": "good", "type": "file", "path": good}}, "groups": []any{map[string]any{"name": "g", "type": "select", "members": []string{"direct"}, "use": []string{"bad", "good"}}}})
	if _, e := h.previewLegacy(context.Background(), rawJSON(map[string]string{"name": "bad"})); e == nil {
		t.Fatal("missing provider accepted")
	}
	p := migratePreview(t, h, "good")
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	if len(h.doc.config.Providers) != 1 || h.doc.config.Providers[0].Name != "bad" {
		t.Fatal("independent failure lost")
	}
	if !reflect.DeepEqual(h.doc.config.Groups[0].Use, []string{"bad"}) {
		t.Fatal("pending reference changed")
	}
}
func TestR4MigrationRequestHeadersAndShorterTimeout(t *testing.T) {
	ctx := context.WithValue(context.Background(), legacyKey{}, &legacyConversion{Config: kernel.ProviderConfig{URL: "https://migration.invalid/sub", Headers: map[string]string{"X-Original": "keep"}, UserAgent: "original", Timeout: kernel.Duration(time.Second)}})
	ctx = context.WithValue(ctx, mainSubscriptionRequestKey{}, true)
	_, e := fetchImportBounded(ctx, "https://migration.invalid/sub", nil, func(*http.Transport) http.RoundTripper {
		return roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("X-Original") != "keep" || req.Header.Get("User-Agent") != "original" {
				t.Fatal("headers not preserved")
			}
			deadline, ok := req.Context().Deadline()
			if !ok || time.Until(deadline) > time.Second {
				t.Fatal("timeout enlarged")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(legacyNodes)), Header: http.Header{}}, nil
		})
	}, 1024)
	if e != nil {
		t.Fatal(e)
	}
}
func TestR4ProbeAllStopCancelsWithoutLateStatus(t *testing.T) {
	entered := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	defer target.Close()
	k := settingsKernel(t)
	delete(k, "groups")
	h, _ := startSettings(t, k, map[string]any{"probe_url": target.URL, "probe_timeout": "5s", "probe_round_timeout": "10s", "probe_concurrency": 1})
	round := beginAllProbeTest(t, h, context.Background())
	waitSignal(t, entered)
	before := time.Now()
	if _, e := h.Stop(); e != nil {
		t.Fatal(e)
	}
	waitAllProbeTest(t, round)
	if time.Since(before) > time.Second {
		t.Fatal("Stop blocked on all-probe")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.probes) != 0 || h.allRound != nil {
		t.Fatal("canceled round published stale results")
	}
}
func TestR4CloseAPIExactParametersAndMissingIDs(t *testing.T) {
	h := newHost(t)
	for _, raw := range []string{`{}`, `{"ids":null}`, `{"ids":[0]}`, `{"ids":[-1]}`, `{"ids":[1.5]}`, `{"ids":[9007199254740992]}`, `{"ids":[1],"all":true}`} {
		if _, e := h.Request(context.Background(), "connections.close", json.RawMessage(raw)); e == nil || e.Code != "invalid_params" {
			t.Fatal(raw, e)
		}
	}
	for _, raw := range []string{`{"ids":[]}`, `{"ids":[1,1,42]}`} {
		v, e := h.Request(context.Background(), "connections.close", json.RawMessage(raw))
		if e != nil || v.(map[string]int)["closed"] != 0 {
			t.Fatal(v, e)
		}
	}
}
