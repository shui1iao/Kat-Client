package route

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestReferencedOutboundsIncludesGeositeAndASN(t *testing.T) {
	o := Options{
		Final: "final-out",
		Rules: []Rule{
			{Domain: "a.example.com", Outbound: "rule-out"},
		},
		RuleSets: []RuleSetOptions{
			{Name: "rs1", Format: FormatDomain, Path: "/tmp/rs1.txt", URL: "https://example.com/rs1.txt", Via: "rs-via"},
		},
		GeoIP:   &GeoIPOptions{Path: "/tmp/geoip.mmdb", URL: "https://example.com/geoip.mmdb", Via: "geoip-via"},
		Geosite: &GeoIPOptions{Path: "/tmp/geosite.dat", URL: "https://example.com/geosite.dat", Via: "geosite-via"},
		ASN:     &GeoIPOptions{Path: "/tmp/asn.mmdb", URL: "https://example.com/asn.mmdb", Via: "asn-via"},
	}
	if err := o.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got := o.ReferencedOutbounds()
	want := []string{"rule-out", "final-out", "rs-via", "geoip-via", "geosite-via", "asn-via"}
	if !slices.Equal(got, want) {
		t.Fatalf("ReferencedOutbounds() = %v, want %v", got, want)
	}
}

func TestParseRuleSetStreamLinesAndFormats(t *testing.T) {
	raw := []byte("\xef\xbb\xbf# comment 1\n\n; comment 2\n// comment 3\nkeep.example.com\n+.sub.example.com\n")
	d, err := parseRuleSetAs(FormatDomain, "", raw, maxSetEntries, fullEnv)
	if err != nil {
		t.Fatalf("parseRuleSetAs domain: %v", err)
	}
	if !d.dom.match("keep.example.com") || !d.dom.match("a.sub.example.com") {
		t.Fatal("expected domain entries to match")
	}

	unsup := []byte("# line 1\n\nDOMAIN,ok.example.com\nPROCESS-PATH,/usr/bin/curl\n")
	_, err = parseRuleSetAs(FormatClassical, "", unsup, maxSetEntries, fullEnv)
	if err == nil || !strings.Contains(err.Error(), "line 4:") {
		t.Fatalf("expected unsupported error at line 4, got %v", err)
	}

	if _, err := parseRuleSetAs(FormatYAML, "domain", []byte("payload:\n  - a.example.com\x00\n"), maxSetEntries, fullEnv); err == nil {
		t.Fatal("expected NUL in YAML to fail checkText")
	}
	if _, err := parseRuleSetAs(FormatSingBoxJSON, "", []byte("{\"version\":1,\"rules\":[]}\x00"), maxSetEntries, fullEnv); err == nil {
		t.Fatal("expected NUL in SingBoxJSON to fail checkText")
	}
}

func TestParseRuleSetDoesNotPinRawBuffer(t *testing.T) {
	var sb strings.Builder
	padding := strings.Repeat("x", 180)
	for i := 0; i < 15000; i++ {
		fmt.Fprintf(&sb, "# comment %d %s\n", i, padding)
	}
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&sb, "IP-CIDR,10.%d.%d.0/24,no-resolve\n", (i>>8)&0xff, i&0xff)
	}
	sb.WriteString("DOMAIN-SUFFIX,keep.example.com\n")
	raw := []byte(sb.String())

	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	sets := make([]*setData, 10)
	for i := range sets {
		b := bytes.Clone(raw)
		d, err := parseRuleSetAs(FormatClassical, "", b, maxSetEntries, fullEnv)
		if err != nil {
			t.Fatalf("parseRuleSetAs: %v", err)
		}
		if !d.dom.match("a.keep.example.com") {
			t.Fatal("expected domain suffix to match")
		}
		sets[i] = d
	}
	// Keep the shared fixture alive across both measurements: releasing it here
	// would subtract its bytes and understate the retained parsed-set memory.
	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	var retained int64
	if after.HeapAlloc > before.HeapAlloc {
		retained = int64(after.HeapAlloc - before.HeapAlloc)
	}
	t.Logf("10 sets retained HeapAlloc delta = %d bytes (%.2f MiB)", retained, float64(retained)/(1024*1024))
	// 10 raw buffers would be ~31 MiB; unpinned 10 sets with 5000 IPv4 CIDRs + 1 domain each is < 2 MiB.
	if retained > 4<<20 {
		t.Fatalf("retained heap %d bytes (> 4 MiB) indicates raw text buffers are still pinned", retained)
	}
	runtime.KeepAlive(sets)
	runtime.KeepAlive(raw)
}

func buildBenchDomainText(n int) []byte {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "# comment line for entry %d with extra padding text\n+.host-%d.example.com\n", i, i)
	}
	return []byte(sb.String())
}

func buildBenchYAMLText(n int) []byte {
	var sb strings.Builder
	sb.WriteString("payload:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "  - '+.host-%d.example.com'\n", i)
	}
	return []byte(sb.String())
}

func buildBenchSingBoxJSON(n int) []byte {
	var sb strings.Builder
	sb.WriteString(`{"version":1,"rules":[{"domain_suffix":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		fmt.Fprintf(&sb, `"host-%d.example.com"`, i)
	}
	sb.WriteString(`]}]}`)
	return []byte(sb.String())
}

func protoBytes(field uint64, val []byte) []byte {
	var out []byte
	out = binary.AppendUvarint(out, (field<<3)|2)
	out = binary.AppendUvarint(out, uint64(len(val)))
	out = append(out, val...)
	return out
}

func protoVarint(field, val uint64) []byte {
	var out []byte
	out = binary.AppendUvarint(out, (field<<3)|0)
	out = binary.AppendUvarint(out, val)
	return out
}

func buildBenchGeositeDB(total, matching int) *siteDB {
	var entry bytes.Buffer
	entry.Write(protoBytes(1, []byte("TEST")))
	for i := 0; i < total; i++ {
		var dom bytes.Buffer
		dom.Write(protoVarint(1, 2))
		dom.Write(protoBytes(2, []byte(fmt.Sprintf("host-%d.example.com", i))))
		if i < matching {
			attr := protoBytes(1, []byte("cn"))
			dom.Write(protoBytes(3, attr))
		} else {
			attr := protoBytes(1, []byte("ads"))
			dom.Write(protoBytes(3, attr))
		}
		entry.Write(protoBytes(2, dom.Bytes()))
	}
	raw := protoBytes(1, entry.Bytes())
	db, err := parseGeositeDB(raw)
	if err != nil {
		panic(err)
	}
	return db
}

func BenchmarkParseRuleSetDomain(b *testing.B) {
	raw := buildBenchDomainText(2000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parseRuleSetAs(FormatDomain, "", raw, maxSetEntries, fullEnv); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseRuleSetYAML(b *testing.B) {
	raw := buildBenchYAMLText(1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parseRuleSetAs(FormatYAML, "domain", raw, maxSetEntries, fullEnv); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseRuleSetSingBoxJSON(b *testing.B) {
	raw := buildBenchSingBoxJSON(1000)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parseRuleSetAs(FormatSingBoxJSON, "", raw, maxSetEntries, fullEnv); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGeositeCompileFiltered(b *testing.B) {
	db := buildBenchGeositeDB(1000, 50)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m := db.compile("test@cn")
		if m.missing {
			b.Fatal("unexpected missing")
		}
	}
}
