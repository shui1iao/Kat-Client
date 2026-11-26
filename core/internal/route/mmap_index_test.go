package route

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
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
	baseIdxPath, _, _ := kidxPathFor(s)
	fiCur, _ := os.Stat(srcPath)
	fhCur, _ := computeSourceFastHashFromFile(srcPath, fiCur.Size())
	idxPath := kidxVersionedPath(baseIdxPath, fhCur)
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

func TestSubscriptionValidationPromotesAndReusesMmap(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KAT_ROUTE_INDEX_CACHE_DIR", filepath.Join(dir, "cache"))

	srcPath := filepath.Join(dir, "sub-rules.yaml")
	body := []byte("payload:\n  - DOMAIN,a.example.com\n  - DOMAIN-SUFFIX,openai.com\n  - IP-CIDR,10.20.0.0/16\n")
	if err := os.WriteFile(srcPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(srcPath)
	if err != nil {
		t.Fatal(err)
	}
	rso := RuleSetOptions{Name: "sub", Format: FormatYAML, Behavior: "classical", Path: srcPath}
	deps := SubscriptionSetDependencies{}

	// Cold subscription validation: must promote to KIDX0003 mmap before caching.
	if _, hit, _ := ValidateSubscriptionSetFile(rso, fi, deps); hit {
		t.Fatal("expected cold ValidateSubscriptionSetFile miss")
	}
	n, err := ValidateSubscriptionSetWithDependencies(rso, body, deps)
	if err != nil || n != 3 {
		t.Fatalf("cold validation failed: n=%d err=%v", n, err)
	}
	CacheRecordStat(srcPath, "rule_set", "rule_set|yaml|classical|000", fi)

	// Engine startup must inherit the mmap-backed setData (0 heap sets).
	eng, err := NewEngine(Options{
		RuleSets: []RuleSetOptions{rso},
		Rules:    []Rule{{RuleSet: "sub", Outbound: "proxy"}},
		Final:    "direct",
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	st := eng.MemoryStats()
	if st.MmapSets != 1 || st.HeapSets != 0 {
		t.Fatalf("expected 1 mmap set / 0 heap sets after cold subscription validation, got %+v", st)
	}

	// Simulate fresh process restart (empty parsedCache): ValidateSubscriptionSetFile
	// must hit the persisted KIDX0003 mmap directly without reading/parsing raw bytes.
	parsedCache.Lock()
	parsedCache.m = nil
	parsedCache.Unlock()

	n2, hit, err := ValidateSubscriptionSetFile(rso, fi, deps)
	if err != nil || !hit || n2 != 3 {
		t.Fatalf("warm ValidateSubscriptionSetFile failed: n=%d hit=%v err=%v", n2, hit, err)
	}
	eng2, err := NewEngine(Options{
		RuleSets: []RuleSetOptions{rso},
		Rules:    []Rule{{RuleSet: "sub", Outbound: "proxy"}},
		Final:    "direct",
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	st2 := eng2.MemoryStats()
	if st2.MmapSets != 1 || st2.HeapSets != 0 {
		t.Fatalf("expected 1 mmap set / 0 heap sets after warm restart, got %+v", st2)
	}
}

func TestBackgroundUpdateSwitchesToMmap(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KAT_ROUTE_INDEX_CACHE_DIR", filepath.Join(dir, "cache"))

	srcPath := filepath.Join(dir, "remote.yaml")
	v1 := []byte("payload:\n  - DOMAIN,old.example.com\n")
	v2 := []byte("payload:\n  - DOMAIN,new.example.com\n  - DOMAIN-SUFFIX,github.com\n")
	if err := os.WriteFile(srcPath, v1, 0o600); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(v2)
	}))
	defer srv.Close()

	dial := func(via string) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
		return (&net.Dialer{}).DialContext, nil
	}
	eng, err := NewEngine(Options{
		RuleSets: []RuleSetOptions{{
			Name:     "remote",
			Format:   FormatYAML,
			Behavior: "classical",
			Path:     srcPath,
			URL:      srv.URL + "/rules.yaml",
		}},
		Rules: []Rule{{RuleSet: "remote", Outbound: "proxy"}},
		Final: "direct",
	}, dial, nil)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	eng.rootCAs = pool

	if st := eng.MemoryStats(); st.MmapSets != 1 || st.HeapSets != 0 {
		t.Fatalf("initial engine expected mmap=1 heap=0, got %+v", st)
	}
	if !eng.update(context.Background(), eng.sources[0]) {
		t.Fatal("background update failed")
	}
	if st := eng.MemoryStats(); st.MmapSets != 1 || st.HeapSets != 0 {
		t.Fatalf("after background update expected mmap=1 heap=0, got %+v", st)
	}
	d, err := eng.Decide(context.Background(), Metadata{Host: "api.github.com", Network: "tcp"}, nil)
	if err != nil || d.Kind != Proxy || d.Outbound != "proxy" {
		t.Fatalf("expected updated rule set to match api.github.com, got %+v", d)
	}
}
