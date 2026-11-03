//go:build !windows

package clientcore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSubscriptionCacheNoFollowAndRetry(t *testing.T) {
	h := fullHost(t)
	fixture, v := cacheFixture(t, h)
	id := ""
	old := ""
	outside := filepath.Join(t.TempDir(), "sentinel")
	if e := os.WriteFile(outside, []byte("preserve"), 0600); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		*v = i
		p := fullPreview(t, h, strings.Replace(fixture, "https://example.invalid/set", fmt.Sprintf("https://example.invalid/set/v%d", *v), 1), id)
		if _, e := h.Apply(p.Text); e != nil {
			t.Fatal(e)
		}
		id = p.ID
		if i == 0 {
			old = filepath.Dir(h.doc.config.RuleSets[0].Path)
			if e := os.Symlink(outside, filepath.Join(old, "link")); e != nil {
				t.Fatal(e)
			}
		}
	}
	if _, e := os.Stat(old); e != nil {
		t.Fatal("reparse-containing version traversed", e)
	}
	if b, e := os.ReadFile(outside); e != nil || string(b) != "preserve" {
		t.Fatal("outside cache modified")
	}
	if e := os.Remove(filepath.Join(old, "link")); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Apply(h.doc.text); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(old); !os.IsNotExist(e) {
		t.Fatal("failed deletion not retried")
	}
	unknown := filepath.Join(h.workspace, "subscription-not-a-version")
	if e := os.Mkdir(unknown, 0700); e != nil {
		t.Fatal(e)
	}
	linked := filepath.Join(h.workspace, "subscription-123456")
	if e := os.Symlink(filepath.Dir(outside), linked); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Apply(h.doc.text); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Lstat(linked); e != nil {
		t.Fatal("link itself should not be accepted for deletion")
	}
	if _, e := os.Stat(unknown); e != nil {
		t.Fatal("non-Kat directory deleted")
	}
}
