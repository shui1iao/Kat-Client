package clientcore

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func yamlFixture(hp, sp int) string {
	return fmt.Sprintf("# accepted source — not a serialized runtime\nschema_version: 1\nclient:\n  mode: rule # keep inline comment\n  global_group: ''\n  probe_url: http://127.0.0.1:1/probe\n  http_port: %d\n  socks_port: %d\nkernel:\n  dns: {server: system}\n  security: {allow_loopback: true}\n", hp, sp)
}

func TestYAMLStrictProjectionAndPrecision(t *testing.T) {
	text := "# original\nvalue: 9007199254740993\nlarge: 184467440737095516161\ndecimal: 0.123456789012345678901234567890\nfloat: +.5000000000000000000001\nexponent: 1.e+12\noctal: 0o17\nhex: 0x10\nbinary: 0b11\nstring: '2026-10-28'\nnull: null\n"
	// Mapping keys must be strings, including an otherwise legal null value.
	text = strings.Replace(text, "null: null", "'null': null", 1)
	text += "overflow_integer: " + strings.Repeat("9", 400) + "\noverflow_exponent: 1.234567890123456789e9999\noverflow_hex: 0x" + strings.Repeat("f", 100) + "\nquoted_number: '1e9999'\nexplicit_string: !!str 1e9999\n"
	b, err := yamlJSON([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{"value": "9007199254740993", "large": "184467440737095516161", "decimal": "0.123456789012345678901234567890", "float": "0.5000000000000000000001", "exponent": "1.0e+12", "octal": "15", "hex": "16", "binary": "3"} {
		if got := v[k].(json.Number).String(); got != want {
			t.Fatalf("%s: %q != %q", k, got, want)
		}
	}
	if v["overflow_integer"].(json.Number).String() != strings.Repeat("9", 400) || v["overflow_exponent"].(json.Number).String() != "1.234567890123456789e9999" || v["quoted_number"] != "1e9999" || v["explicit_string"] != "1e9999" {
		t.Fatal("resolver overflow lost number precision")
	}
	if _, ok := v["overflow_hex"].(json.Number); !ok {
		t.Fatal("resolver overflow coerced hex to string")
	}
	if v["string"] != "2026-10-28" || v["null"] != nil {
		t.Fatal(v)
	}
	full := strings.Replace(yamlFixture(7890, 7891), "  mode: rule", "  future_legal_client_field: {large: 9007199254740993, decimal: 0.123456789012345678901234567890}\n  mode: rule", 1)
	for _, f := range []DocumentFormat{FormatYAML, FormatYML} {
		d, e := parseDocument(full, t.TempDir(), f)
		if e != nil || d.text != full || d.format != f {
			t.Fatalf("%s: %v", f, e)
		}
	}
	// Kat validation remains the same, not generic YAML or another proxy schema.
	for _, full := range []string{
		"proxies: []\nproxy-groups: []\n", strings.Replace(yamlFixture(7890, 7891), "mode: rule", "mode: nonsense", 1),
		strings.Replace(yamlFixture(7890, 7891), "http_port: 7890", "http_port: '7890'", 1),
		strings.Replace(yamlFixture(7890, 7891), "security: {allow_loopback: true}", "unknown_kernel_field: true", 1),
		yamlFixture(7890, 7891) + "  routing: {final: missing-group}\n",
	} {
		if _, e := parseDocument(full, t.TempDir(), FormatYAML); e == nil {
			t.Fatalf("invalid Kat schema accepted: %q", full)
		}
	}
}
func TestYAMLRejectsAmbiguityAndUnsafeTypes(t *testing.T) {
	bad := []string{
		"a: 1\na: 2\n", "a: {x: 1, x: 2}", "a: {'x': 1, !!str x: 2}",
		"1: x", "true: x", "null: x", "? [a, b]\n: x", "? {a: b}\n: x",
		"a: &unused 1", "&root {a: 1}", "&key a: 1", "a: &x [*x]", "a: &x {b: 1}\nb: *x", "a: *missing",
		"a: {<<: {b: 1}}", "a: {'<<': {b: 1}}",
		"a: !custom x", "!custom {a: 1}", "a: !custom [1]", "!custom a: 1",
		"a: 2026-10-28", "a: !!binary YQ==", "a: !!set {x: null}", "a: !!timestamp 2026-10-28",
		"a: .inf", "a: -.Inf", "a: .NaN", "a: !!float nan", "a: !!bool yes", "a: !!int eight", "a: !!null wrong",
		"a: 1\n---\nb: 2", "a: 1\n---\n", "a: 1\n...\n---\n", "", "null", "[]", "scalar", "a: [1,", "a: \xff",
	}
	for i, text := range bad {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			if _, e := yamlJSON([]byte(text)); e == nil {
				t.Fatalf("accepted %q", text)
			}
		})
	}
	if _, e := yamlJSON([]byte("a: " + strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65))); e == nil {
		t.Fatal("depth limit")
	}
	if _, e := yamlJSON([]byte("a: [" + strings.Repeat("0,", maxYAMLNodes) + "0]")); e == nil {
		t.Fatal("node budget")
	}
	if _, e := parseDocument(yamlFixture(7890, 7891)+"#"+strings.Repeat("x", maxDocument), t.TempDir(), FormatYAML); e == nil || e.Code != "document_too_large" {
		t.Fatal("byte budget", e)
	}
	// Expansion by JSON escaping must also fit the existing protocol frame.
	if _, e := parseDocument(yamlFixture(7890, 7891)+"#"+strings.Repeat("\x01", maxDocument/2), t.TempDir(), FormatYAML); e == nil || e.Code != "document_too_large" {
		t.Fatal("frame budget", e)
	}
	for _, text := range []string{`{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`, "{\"a\":\"\xff\"}", initialDocument + "{}", strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65)} {
		if _, e := parseDocument(text, t.TempDir()); e == nil {
			t.Fatal("JSON strictness regressed")
		}
	}
}

func TestDocumentFormatIPCAndSafeValidation(t *testing.T) {
	h := newHost(t)
	yamlText := yamlFixture(7890, 7891) + "  outbounds: [{name: p, type: socks5, server: 127.0.0.1, port: 1234}]\n  groups: [{name: pick, type: select, members: [p]}]\n  routing: {rules: [{domain: example.invalid, outbound: pick}], final: pick}\n"
	for _, f := range []DocumentFormat{FormatYAML, FormatYML} {
		params, _ := json.Marshal(map[string]any{"text": yamlText, "format": f})
		result, e := h.Request(context.Background(), "document.validate", params)
		if e != nil {
			t.Fatal(e)
		}
		b, _ := json.Marshal(result)
		var got map[string]json.RawMessage
		_ = json.Unmarshal(b, &got)
		if len(got) != 4 || string(got["valid"]) != "true" || string(got["format"]) != fmt.Sprintf("%q", f) {
			t.Fatal(string(b))
		}
		var ports map[string]int
		_ = json.Unmarshal(got["ports"], &ports)
		var counts documentCounts
		_ = json.Unmarshal(got["counts"], &counts)
		if ports["http"] != 7890 || ports["socks"] != 7891 || counts != (documentCounts{1, 1, 1, 0}) {
			t.Fatal(string(b))
		}
	}
	for _, raw := range []string{`null`, `""`, `"YAML"`, `"toml"`, `1`, `true`, `{}`, `[]`} {
		for _, method := range []string{"document.validate", "document.apply"} {
			params := json.RawMessage(fmt.Sprintf(`{"text":%q,"format":%s}`, yamlText, raw))
			if _, e := h.Request(context.Background(), method, params); e == nil || e.Code != "invalid_params" {
				t.Fatalf("%s %s: %v", method, raw, e)
			}
		}
	}
	// Omitted format is JSON on a fresh workspace, then follows accepted YAML.
	params, _ := json.Marshal(map[string]any{"text": initialDocument})
	if _, e := h.Request(context.Background(), "document.validate", params); e != nil {
		t.Fatal(e)
	}
	params, _ = json.Marshal(map[string]any{"text": yamlText, "format": "yaml"})
	if _, e := h.Request(context.Background(), "document.apply", params); e != nil {
		t.Fatal(e)
	}
	params, _ = json.Marshal(map[string]any{"text": yamlText})
	r, e := h.Request(context.Background(), "document.validate", params)
	if e != nil || r.(map[string]any)["format"] != FormatYAML {
		t.Fatal(r, e)
	}
	r, e = h.Request(context.Background(), "document.get", nil)
	if e != nil || r.(map[string]any)["format"] != FormatYAML || r.(map[string]any)["text"] != yamlText {
		t.Fatal(r, e)
	}
	// Validation never activates a draft format or touches the accepted file.
	params, _ = json.Marshal(map[string]any{"text": initialDocument, "format": "json"})
	if _, e := h.Request(context.Background(), "document.validate", params); e != nil {
		t.Fatal(e)
	}
	if h.doc.format != FormatYAML {
		t.Fatal("validation activated a format")
	}
	if _, e := h.Apply(yamlText + "# no-op edits preserve every byte\n"); e != nil {
		t.Fatal(e)
	}
}

func TestDocumentCandidateSelectionAndConflict(t *testing.T) {
	for _, f := range documentFormats {
		t.Run(string(f), func(t *testing.T) {
			dir := t.TempDir()
			text := initialDocument
			if f != FormatJSON {
				text = yamlFixture(7890, 7891)
			}
			path := filepath.Join(dir, f.filename())
			if e := os.WriteFile(path, []byte(text), 0600); e != nil {
				t.Fatal(e)
			}
			h, e := Open(dir)
			if e != nil {
				t.Fatal(e)
			}
			defer h.Close()
			if h.doc.format != f || h.doc.client.IPv6 || h.path != path {
				t.Fatal("wrong candidate")
			}
			before, err := os.ReadFile(filepath.Join(dir, "client-before-c16-network."+string(f)))
			if err != nil || string(before) != text {
				t.Fatal("migration backup did not retain exact candidate", err)
			}
			found, e := documentCandidates(dir)
			if e != nil || len(found) != 1 {
				t.Fatal(found, e)
			}
		})
	}
	for _, pair := range [][]DocumentFormat{{FormatJSON, FormatYAML}, {FormatJSON, FormatYML}, {FormatYAML, FormatYML}, {FormatJSON, FormatYAML, FormatYML}} {
		dir := t.TempDir()
		for _, f := range pair {
			if e := os.WriteFile(filepath.Join(dir, f.filename()), []byte("invalid untouched"), 0600); e != nil {
				t.Fatal(e)
			}
		}
		h, e := Open(dir)
		if h != nil {
			h.Close()
			t.Fatal("conflict opened")
		}
		ce, ok := e.(*Error)
		if !ok || ce.Code != "configuration_conflict" {
			t.Fatal(e)
		}
		want := make([]string, len(pair))
		for i, f := range pair {
			want[i] = f.filename()
		}
		if ce.Message != strings.Join(want, ", ") || strings.Contains(ce.Message, dir) {
			t.Fatal(ce)
		}
		for _, f := range pair {
			b, _ := os.ReadFile(filepath.Join(dir, f.filename()))
			if string(b) != "invalid untouched" {
				t.Fatal("conflict modified")
			}
		}
	}
	for _, kind := range []string{"directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			h := newHost(t)
			dest := filepath.Join(h.workspace, FormatYAML.filename())
			if kind == "directory" {
				if e := os.Mkdir(dest, 0700); e != nil {
					t.Fatal(e)
				}
			} else {
				if e := os.Symlink(filepath.Join(h.workspace, "missing"), dest); e != nil {
					t.Skip(e)
				}
			}
			if _, e := h.Apply(yamlFixture(7890, 7891), FormatYAML); e == nil || e.Code != "configuration_conflict" {
				t.Fatal(e)
			}
			if _, e := os.Lstat(dest); e != nil {
				t.Fatal("destination removed", e)
			}
			b, _ := os.ReadFile(h.path)
			if string(b) != initialDocument {
				t.Fatal("source changed")
			}
		})
	}
	// A lone bad candidate must not trigger fresh JSON initialization.
	dir := t.TempDir()
	_ = os.Mkdir(filepath.Join(dir, FormatYML.filename()), 0700)
	if h, e := Open(dir); e == nil {
		h.Close()
		t.Fatal("directory opened")
	}
	if _, e := os.Stat(filepath.Join(dir, FormatJSON.filename())); !os.IsNotExist(e) {
		t.Fatal("auto migration")
	}
}

func TestDocumentConversionsPreserveSourceWithoutTemporaryBackups(t *testing.T) {
	h := newHost(t)
	previous := initialDocument
	for _, f := range []DocumentFormat{FormatYAML, FormatYML, FormatJSON} {
		text := yamlFixture(7890, 7891) + "# tail comment / raw token 0.1234567890123456789\n"
		if f == FormatJSON {
			text = " \n" + initialDocument
		}
		oldPath := h.path
		r, e := h.Apply(text, f)
		if e != nil {
			t.Fatal(e)
		}
		out := r.(map[string]any)
		if out["format"] != f || out["applied"] != false || out["text"] != text || out["path"] != h.path {
			t.Fatal(out)
		}
		if _, e := os.Lstat(oldPath); !os.IsNotExist(e) {
			t.Fatal("old candidate retained", e)
		}
		found, err := documentCandidates(h.workspace)
		if err != nil || len(found) != 1 || found[0] != f {
			t.Fatal(found, err)
		}
		b, err := os.ReadFile(h.path)
		if err != nil || string(b) != text {
			t.Fatal("raw source changed", err)
		}
		assertNoDocumentTemps(t, h.workspace)
		// A changed same-format save also releases its transaction material.
		text += "\n"
		if _, e := h.Apply(text); e != nil {
			t.Fatal(e)
		}
		b, err = os.ReadFile(h.path)
		if err != nil || string(b) != text {
			t.Fatal("same-format raw source changed", err)
		}
		assertNoDocumentTemps(t, h.workspace)
		info, _ := os.Stat(h.path)
		if _, e := h.Apply(text); e != nil {
			t.Fatal(e)
		}
		after, _ := os.Stat(h.path)
		if !os.SameFile(info, after) || !info.ModTime().Equal(after.ModTime()) {
			t.Fatal("no-op rewrote source")
		}
		assertNoDocumentTemps(t, h.workspace)
		previous = text
	}
	dir := h.workspace
	if e := h.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if reopened.doc.text != previous || reopened.doc.format != FormatJSON {
		t.Fatal("reopen changed accepted source")
	}
}
func TestDocumentExternalChangesNeverOverwritten(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprint(replace), func(t *testing.T) {
			h := newHost(t)
			external := "external edit, not necessarily valid"
			if replace {
				external = h.doc.text
				if e := atomicWrite(h.path, []byte(external)); e != nil {
					t.Fatal(e)
				}
			} else if e := os.WriteFile(h.path, []byte(external), 0600); e != nil {
				t.Fatal(e)
			}
			for _, f := range []DocumentFormat{FormatJSON, FormatYAML, FormatYML} {
				text := initialDocument
				if f != FormatJSON {
					text = yamlFixture(7890, 7891)
				}
				if _, e := h.Apply(text, f); e == nil || e.Code != "document_changed" {
					t.Fatal(e)
				}
				b, _ := os.ReadFile(h.path)
				if string(b) != external {
					t.Fatal("external edit overwritten")
				}
			}
			found, _ := documentCandidates(h.workspace)
			if len(found) != 1 || found[0] != FormatJSON {
				t.Fatal(found)
			}
		})
	}
	// Exclusive conversion publication must never clobber even a regular target.
	dir := t.TempDir()
	path := filepath.Join(dir, "dest")
	if e := os.WriteFile(path, []byte("external"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := exclusiveDocumentWrite(path, []byte("bad")); e == nil {
		t.Fatal("overwrote target")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "external" {
		t.Fatal("clobbered")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("temporary write leaked")
	}
}

// Keep io imported in this parser/IPC test file useful when checking EOF
// explicitly: projection is one JSON value, with no trailing bytes.
func TestYAMLProjectionSingleJSONValue(t *testing.T) {
	b, e := yamlJSON([]byte("a: [1, true, null, string]\n"))
	if e != nil {
		t.Fatal(e)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if e := d.Decode(new(any)); e != nil {
		t.Fatal(e)
	}
	if e := d.Decode(new(any)); e != io.EOF {
		t.Fatal(e)
	}
}

func TestDocumentConditionalReplacementDoesNotClobberExternalChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kat-client.json")
	if e := os.WriteFile(path, []byte(initialDocument), 0600); e != nil {
		t.Fatal(e)
	}
	info, e := os.Lstat(path)
	if e != nil {
		t.Fatal(e)
	}
	// Simulate a change after the save's initial comparison, before publication.
	if e := os.WriteFile(path, []byte("external"), 0600); e != nil {
		t.Fatal(e)
	}
	e = atomicWrite(path, []byte("replacement"), func() bool { return matchesSource(path, initialDocument, info) })
	if e != errSourceChanged {
		t.Fatal(e)
	}
	b, e := os.ReadFile(path)
	if e != nil || string(b) != "external" {
		t.Fatal("external change overwritten", e)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("staging file leaked")
	}
}

func assertNoDocumentTemps(t *testing.T, workspace string) {
	t.Helper()
	entries, err := os.ReadDir(workspace)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".kat-conversion-backup-") || strings.HasPrefix(entry.Name(), ".kat-write-") {
			t.Fatalf("temporary document material leaked: %s", entry.Name())
		}
	}
}

func TestDocumentTransactionBackupRetainedOnlyForFailedRollback(t *testing.T) {
	for _, f := range documentFormats {
		t.Run(string(f), func(t *testing.T) {
			h := newHost(t)
			original := h.doc.text
			text := yamlFixture(7890, 7891)
			if f == FormatJSON {
				text = " \n" + initialDocument
			}
			d, e := parseDocument(text, h.workspace, f)
			if e != nil {
				t.Fatal(e)
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			tx, e := h.saveDocumentLocked(d)
			if e != nil {
				t.Fatal(e)
			}
			b, err := os.ReadFile(tx.backup)
			if err != nil || string(b) != original {
				t.Fatal("missing transaction recovery copy", err)
			}
			// A non-cooperative target edit prevents a safe rollback. Do not
			// clobber it; retain exactly the old source for manual recovery.
			if err := os.WriteFile(tx.target, []byte("external target"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := tx.rollback(); err == nil {
				t.Fatal("unsafe rollback succeeded")
			}
			b, err = os.ReadFile(tx.backup)
			if err != nil || string(b) != original {
				t.Fatal("failed rollback lost recovery material", err)
			}
			b, err = os.ReadFile(tx.target)
			if err != nil || string(b) != "external target" {
				t.Fatal("external target overwritten", err)
			}
			if h.doc.text != original || h.server != nil {
				t.Fatal("failed rollback changed accepted state")
			}
		})
	}
}
