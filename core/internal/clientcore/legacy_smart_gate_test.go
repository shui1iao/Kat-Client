package clientcore

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

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
			generation := running.StatsView().Reload.Generation
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
			if h.doc.text != accepted || h.doc.format != acceptedFormat || h.server != running || h.server.StatsView().Reload.Generation != generation || string(history) != string(afterHistory) || !reflect.DeepEqual(before, legacyGateFiles(t, h.workspace)) {
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
