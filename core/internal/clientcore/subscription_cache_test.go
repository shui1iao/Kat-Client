package clientcore

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/shui1iao/Kat/internal/clientegress"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func cacheFixture(t *testing.T, h *Host) (string, *int) {
	t.Helper()
	version := new(int)
	fixture := strings.Replace(fullFixture, "rules:\n", `rule-providers:
  external: {type: http, behavior: classical, format: yaml, url: https://example.invalid/set}
rules:
  - RULE-SET,external,pick
`, 1)
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		return []byte(fmt.Sprintf("payload: ['DOMAIN,v%d.invalid']\n", *version)), nil
	}
	return fixture, version
}
func cacheDirs(t *testing.T, h *Host) []string {
	t.Helper()
	dirs, e := filepath.Glob(filepath.Join(h.workspace, "subscription-*"))
	if e != nil {
		t.Fatal(e)
	}
	versions := []string{}
	for _, path := range dirs {
		if info, e := os.Lstat(path); e == nil && info.IsDir() {
			versions = append(versions, path)
		}
	}
	return versions
}
func TestSubscriptionCacheIdenticalReuseAndCancel(t *testing.T) {
	h := fullHost(t)
	fixture, _ := cacheFixture(t, h)
	id := ""
	path := ""
	for i := 0; i < 12; i++ {
		p := fullPreview(t, h, fixture, id)
		if i > 0 && h.fullPending.Dir != "" {
			t.Fatal("identical bytes staged a new version")
		}
		if _, e := h.Apply(p.Text, p.Format); e != nil {
			t.Fatal(e)
		}
		id = p.ID
		if i == 0 {
			path = h.doc.config.RuleSets[0].Path
		}
		if h.doc.config.RuleSets[0].Path != path || len(cacheDirs(t, h)) != 1 {
			t.Fatal("identical refresh did not reuse version")
		}
	}
	p := fullPreview(t, h, fixture, id)
	if _, e := h.cancelSubscription(rawJSON(map[string]string{"token": p.Token})); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(path); e != nil {
		t.Fatal("cancel removed reused accepted resource", e)
	}
}
func TestSubscriptionCacheTwelveChangesBoundedAndBackupReferences(t *testing.T) {
	h := fullHost(t)
	fixture, version := cacheFixture(t, h)
	id := ""
	backups := filepath.Join(h.workspace, "backups")
	if e := os.Mkdir(backups, 0700); e != nil {
		t.Fatal(e)
	}
	retained := []string{}
	firstPath := ""
	for i := 0; i < 14; i++ {
		if i > 0 {
			sum := sha256.Sum256([]byte(h.doc.text))
			name := filepath.Join(backups, fmt.Sprintf("%x.json", sum))
			if e := os.WriteFile(name, []byte(h.doc.text), 0600); e != nil {
				t.Fatal(e)
			}
			retained = append(retained, name)
			if len(retained) > 10 {
				if e := os.Remove(retained[0]); e != nil {
					t.Fatal(e)
				}
				retained = retained[1:]
			}
		}
		*version = i
		p := fullPreview(t, h, strings.Replace(fixture, "https://example.invalid/set", fmt.Sprintf("https://example.invalid/set/v%d", *version), 1), id)
		if _, e := h.Apply(p.Text, p.Format); e != nil {
			t.Fatal(e)
		}
		id = p.ID
		if i == 0 {
			firstPath = h.doc.config.RuleSets[0].Path
		}
		if n := len(cacheDirs(t, h)); n > 11 {
			t.Fatalf("refresh %d retained %d versions, expected <= current + ten backups", i+1, n)
		}
		for _, name := range retained {
			b, e := os.ReadFile(name)
			if e != nil {
				t.Fatal(e)
			}
			refs, e := h.resourceRefs(string(b), FormatJSON)
			if e != nil {
				t.Fatal(e)
			}
			for dir := range refs {
				if _, e := os.Stat(filepath.Join(h.workspace, dir, "set-0")); e != nil {
					t.Fatal("backup resource removed", e)
				}
			}
		}
	}
	if _, e := os.Stat(firstPath); !os.IsNotExist(e) {
		t.Fatal("unreferenced accepted old version not reclaimed")
	}
	if e := os.RemoveAll(backups); e != nil {
		t.Fatal(e)
	}
	*version = 14
	p := fullPreview(t, h, fixture, id)
	if _, e := h.Apply(p.Text, p.Format); e != nil {
		t.Fatal(e)
	}
	if n := len(cacheDirs(t, h)); n != 2 {
		t.Fatalf("current plus previous expected 2, got %d", n)
	}
}
func TestSubscriptionCachePendingAndInUseArePreserved(t *testing.T) {
	h := fullHost(t)
	fixture, v := cacheFixture(t, h)
	id := ""
	var oldest string
	for i := 0; i < 3; i++ {
		*v = i
		p := fullPreview(t, h, strings.Replace(fixture, "https://example.invalid/set", fmt.Sprintf("https://example.invalid/set/v%d", *v), 1), id)
		if _, e := h.Apply(p.Text, p.Format); e != nil {
			t.Fatal(e)
		}
		id = p.ID
		if i == 0 {
			oldest = filepath.Dir(h.doc.config.RuleSets[0].Path)
			h.resourceUsing = map[string]int{oldest: 1}
		}
	}
	if _, e := os.Stat(oldest); e != nil {
		t.Fatal("in-use version removed", e)
	}
	delete(h.resourceUsing, oldest)
	*v = 3
	p := fullPreview(t, h, strings.Replace(fixture, "https://example.invalid/set", fmt.Sprintf("https://example.invalid/set/v%d", *v), 1), id)
	pending := h.fullPending.Dir
	// An ordinary successful edit must retain the staged pending version.
	if _, e := h.Apply(h.doc.text, h.doc.format); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(pending); e != nil {
		t.Fatal("pending version removed", e)
	}
	if _, e := os.Stat(oldest); !os.IsNotExist(e) {
		t.Fatal("released version retained")
	}
	if _, e := h.cancelSubscription(rawJSON(map[string]string{"token": p.Token})); e != nil {
		t.Fatal(e)
	}
}
func TestSubscriptionCacheMaintenanceFailureDoesNotRejectPublish(t *testing.T) {
	h := fullHost(t)
	fixture, v := cacheFixture(t, h)
	p := fullPreview(t, h, fixture, "")
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(h.workspace, "backups"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(h.workspace, "backups", "unreadable.json"), []byte("invalid"), 0600); e != nil {
		t.Fatal(e)
	}
	*v = 1
	q := fullPreview(t, h, fixture, p.ID)
	if _, e := h.Apply(q.Text); e != nil {
		t.Fatal("maintenance changed publication result", e)
	}
	if h.doc.text != q.Text {
		t.Fatal("publication lost")
	}
	events := h.logs.read(0, 2000)
	found := false
	for _, e := range events.Entries {
		if e.Event == "subscription_cache_cleanup_failed" {
			found = true
		}
	}
	if !found {
		t.Fatal("maintenance failure not recorded")
	}
}
