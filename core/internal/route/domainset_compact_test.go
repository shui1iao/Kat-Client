package route

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"testing"
)

func TestDomainSetCompactParityAndMemoryReduction(t *testing.T) {
	var d domainSet
	for i := 0; i < 10000; i++ {
		if !d.addDomainEntry(fmt.Sprintf("exact-%d.example.com", i), dialMihom) {
			t.Fatalf("add exact %d failed", i)
		}
		if !d.addDomainEntry(fmt.Sprintf("+.suf-%d.example.org", i), dialMihom) {
			t.Fatalf("add suffix %d failed", i)
		}
		if !d.addDomainEntry(fmt.Sprintf(".sub-%d.example.net", i), dialMihom) {
			t.Fatalf("add sub %d failed", i)
		}
	}
	if !d.addDomainEntry("*.wild.example.io", dialMihom) {
		t.Fatal("add wild1 failed")
	}
	d.compact()
	if d.exact != nil || d.suffix != nil || d.sub != nil || d.wild1 != nil {
		t.Fatal("expected maps released after compact")
	}
	if d.pExact.count() != 10000 || d.pSuffix.count() != 10000 || d.pSub.count() != 10000 || d.pWild1.count() != 1 {
		t.Fatalf("unexpected packed counts: %d %d %d %d", d.pExact.count(), d.pSuffix.count(), d.pSub.count(), d.pWild1.count())
	}

	// Verify exact / suffix / sub / wild1 semantics match original behavior
	cases := []struct {
		host string
		want bool
	}{
		{"exact-0.example.com", true},
		{"exact-9999.example.com", true},
		{"a.exact-0.example.com", false},
		{"suf-42.example.org", true},
		{"a.b.suf-42.example.org", true},
		{"sub-42.example.net", false},
		{"a.sub-42.example.net", true},
		{"a.b.sub-42.example.net", true},
		{"one.wild.example.io", true},
		{"two.one.wild.example.io", false},
		{"wild.example.io", false},
		{"miss.example.com", false},
	}
	for _, tc := range cases {
		if got := d.match(tc.host); got != tc.want {
			t.Fatalf("match(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}

	// Quick resident size sanity check: 30k entries should stay well under 2 MiB packed
	packedBytes := len(d.pExact.data) + len(d.pSuffix.data) + len(d.pSub.data) +
		(len(d.pExact.offs)+len(d.pSuffix.offs)+len(d.pSub.offs))*4
	if packedBytes > 2<<20 {
		t.Fatalf("packedBytes unexpectedly high: %d", packedBytes)
	}
	runtime.GC()
	debug.FreeOSMemory()
}
