package clientcore

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFullSubscriptionReadResourceBoundedNoFollow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data")
	data := []byte("shared")
	if e := os.WriteFile(path, data, 0444); e != nil {
		t.Fatal(e)
	}
	if b, e := readSubscriptionResource(path, int64(len(data))); e != nil || !bytes.Equal(b, data) {
		t.Fatal("readable nonprivate regular file rejected")
	}
	for _, limit := range []int64{0, -1, int64(len(data) - 1), (64 << 20) + 1} {
		if _, e := readSubscriptionResource(path, limit); e == nil {
			t.Fatal("resource byte bound not enforced")
		}
	}
	if _, e := readSubscriptionResource(dir, 100); e == nil {
		t.Fatal("directory read as resource")
	}
	if _, e := readSubscriptionResource(filepath.Join(dir, "missing"), 100); e == nil {
		t.Fatal("missing resource accepted")
	}
	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(dir, "link")
		if e := os.Symlink(path, link); e != nil {
			t.Skip("symlink unavailable on this test host")
		}
		if _, e := readSubscriptionResource(link, 100); e == nil {
			t.Fatal("followed resource symlink")
		}
	})
}

func TestFullSubscriptionUniqueRuleBlock(t *testing.T) {
	a := rawJSON(map[string]string{"domain": "a.invalid", "action": "direct"})
	b := rawJSON(map[string]string{"domain": "b.invalid", "action": "reject"})
	for _, tc := range []struct {
		name       string
		all, block []byte
		want       int
	}{
		{"unique", rawJSON([]any{b, a}), rawJSON([]any{a}), 1},
		{"missing", rawJSON([]any{b}), rawJSON([]any{a}), -1},
		{"duplicate", rawJSON([]any{a, b, a}), rawJSON([]any{a}), -2},
		{"overlap", rawJSON([]any{a, a, a}), rawJSON([]any{a, a}), -2},
		{"multi-rule", rawJSON([]any{a, b, a, b}), rawJSON([]any{a, b}), -2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var all, block []json.RawMessage
			if json.Unmarshal(tc.all, &all) != nil || json.Unmarshal(tc.block, &block) != nil {
				t.Fatal("fixture")
			}
			if n := findRuleBlock(all, block); n != tc.want {
				t.Fatalf("rule block location=%d want=%d", n, tc.want)
			}
		})
	}
}
