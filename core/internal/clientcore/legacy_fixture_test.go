package clientcore

import (
	"encoding/json"
	"os"
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
