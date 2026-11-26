package route

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMmapIndexRuleSetRoundtripAndAutoRebuild(t *testing.T) {
	dir := t.TempDir()
	cacheDir := filepath.Join(dir, "cache")
	t.Setenv("KAT_ROUTE_INDEX_CACHE_DIR", cacheDir)

	srcPath := filepath.Join(dir, "rules.txt")
	content1 := "payload:\n  - DOMAIN,exact.example.com\n  - DOMAIN-SUFFIX,google.com\n  - DOMAIN-KEYWORD,openai\n  - IP-CIDR,1.2.3.0/24\n  - IP-CIDR6,2001:db8::/32,no-resolve\n  - PROCESS-NAME,chrome.exe\n  - IP-ASN,4134\n"
	if err := os.WriteFile(srcPath, []byte(content1), 0o600); err != nil {
		t.Fatal(err)
	}

	s := &source{
		kind:     "rule_set",
		name:     "test",
		path:     srcPath,
		stamp:    "text|0",
		maxBytes: 1 << 20,
		parse: func(b []byte) (any, error) {
			return parseRuleSetAs(FormatYAML, "classical", b, 1000, parseEnv{geoip: true, asn: true})
		},
	}

	// Cold load: parses and writes .kidx, then remaps.
	p1 := preloadLocal(s)
	if p1.readErr != nil || p1.parseErr != nil || p1.val == nil {
		t.Fatalf("cold preload failed: read=%v parse=%v", p1.readErr, p1.parseErr)
	}
	sd1 := p1.val.(*setData)
	if !sd1.dom.match("exact.example.com") || !sd1.dom.match("mail.google.com") || !sd1.dom.match("api.openai.org") {
		t.Fatal("cold mmap rule_set domain match failed")
	}
	if !sd1.ip.contains(netip.MustParseAddr("1.2.3.4")) || !sd1.ipNR.contains(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("cold mmap rule_set ip match failed")
	}

	// Clear in-process cache to force hot mmap load from disk without parsing!
	parsedCache.Lock()
	parsedCache.m = nil
	parsedCache.Unlock()

	parseCalled := false
	s.parse = func(b []byte) (any, error) {
		parseCalled = true
		return parseRuleSetAs(FormatYAML, "classical", b, 1000, parseEnv{geoip: true, asn: true})
	}
	p2 := preloadLocal(s)
	if parseCalled {
		t.Fatal("expected hot mmap hit without calling s.parse")
	}
	sd2 := p2.val.(*setData)
	if !sd2.dom.match("exact.example.com") || !sd2.dom.match("mail.google.com") || !sd2.ip.contains(netip.MustParseAddr("1.2.3.4")) {
		t.Fatal("hot mmap rule_set match failed")
	}

	// Mutate source file with SAME length & SAME mtime -> fast content hash must detect and rebuild!
	fiOld, _ := os.Stat(srcPath)
	content2 := "payload:\n  - DOMAIN,other.example.com\n  - DOMAIN-SUFFIX,github.com\n  - DOMAIN-KEYWORD,claude\n  - IP-CIDR,5.6.7.0/24\n  - IP-CIDR6,2001:db9::/32,no-resolve\n  - PROCESS-NAME,firefox.ex\n  - IP-ASN,4809\n"
	if len(content2) != len(content1) {
		t.Fatalf("test fixture len mismatch %d != %d", len(content2), len(content1))
	}
	if err := os.WriteFile(srcPath, []byte(content2), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(srcPath, fiOld.ModTime(), fiOld.ModTime())
	parsedCache.Lock()
	parsedCache.m = nil
	parsedCache.Unlock()

	p3 := preloadLocal(s)
	if !parseCalled {
		t.Fatal("expected content change (same size & mtime) to invalidate mmap index and rebuild")
	}
	sd3 := p3.val.(*setData)
	if sd3.dom.match("mail.google.com") || !sd3.dom.match("api.github.com") || !sd3.ip.contains(netip.MustParseAddr("5.6.7.8")) {
		t.Fatal("rebuilt mmap rule_set match failed")
	}

	// Corrupt cache file -> must gracefully rebuild without error.
	idxPath, _, _ := kidxPathFor(s)
	if err := os.WriteFile(idxPath, []byte("CORRUPT_HEADER_DATA"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(srcPath, time.Now(), time.Now())
	parsedCache.Lock()
	parsedCache.m = nil
	parsedCache.Unlock()
	parseCalled = false
	p4 := preloadLocal(s)
	if !parseCalled || p4.parseErr != nil || p4.val == nil {
		t.Fatalf("corrupted cache recovery failed: parseCalled=%v err=%v", parseCalled, p4.parseErr)
	}
}
