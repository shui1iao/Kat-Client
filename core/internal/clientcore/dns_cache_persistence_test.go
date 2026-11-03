package clientcore

import (
	"fmt"
	"strings"
	"testing"
)

func TestDNSCache128SaveAndReopen(t *testing.T) {
	for _, format := range []DocumentFormat{FormatJSON, FormatYAML} {
		t.Run(string(format), func(t *testing.T) {
			root := t.TempDir()
			h, e := Open(root)
			if e != nil {
				t.Fatal(e)
			}
			text := fixture(t, map[string]any{"dns": map[string]any{"servers": []string{"8.8.8.8"}, "cache_entries": 128}})
			if format == FormatYAML {
				text = fmt.Sprintf("schema_version: 1\nclient:\n  mode: rule\n  probe_url: http://127.0.0.1:1/probe\n  http_port: %d\n  socks_port: %d\nkernel:\n  dns:\n    servers: [8.8.8.8]\n    cache_entries: 128\n", freePort(t), freePort(t))
			}
			if _, err := h.Apply(text, format); err != nil {
				h.Close()
				t.Fatal(err)
			}
			if h.doc.text != text {
				t.Fatal("accepted source changed cache input")
			}
			h.Close()
			reopened, e := Open(root)
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			if reopened.doc.text != text || reopened.doc.format != format {
				t.Fatal("cache source or format lost on reopening")
			}
			raw, err := sourceJSON(reopened.doc)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw["kernel"]), `"cache_entries":128`) {
				t.Fatal("128 not retained in DNS accepted source")
			}
		})
	}
}
