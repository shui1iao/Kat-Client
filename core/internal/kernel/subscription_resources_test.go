package kernel

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSubscriptionResourcesKeepRetainedGeneration(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, "old.yaml")
	newPath := filepath.Join(dir, "new.yaml")
	for _, p := range []string{oldPath, newPath} {
		if e := os.WriteFile(p, []byte("payload: ['DOMAIN,example.org']\n"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	base := socksCfg("127.0.0.1:0")
	base.RuleSets = []RuleSetConfig{{Name: "old", Format: "yaml", Behavior: "classical", Path: oldPath}}
	next := base
	s := startReloadable(t, base, &next)
	old := s.current()
	if !old.tryRef() {
		t.Fatal("live generation unavailable")
	}
	defer old.unref()
	next.RuleSets = []RuleSetConfig{{Name: "new", Format: "yaml", Behavior: "classical", Path: newPath}}
	if _, e := s.ApplyConfig(next); e != nil {
		t.Fatal(e)
	}
	paths := s.SubscriptionResourcePaths()
	seen := map[string]bool{}
	for _, p := range paths {
		seen[p] = true
	}
	if !seen[oldPath] || !seen[newPath] {
		t.Fatal("current or retained generation references missing", paths)
	}
}
