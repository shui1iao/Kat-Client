package clientcore

import (
	"encoding/json"
	"github.com/shui1iao/Kat/internal/kernel"
	"strings"
	"testing"
	"time"
)

func TestDNSLogsAndCacheNeverMarshalNullSlices(t *testing.T) {
	var ring dnsRing
	ring.record(kernel.DNSEvent{
		Time:       time.Now(),
		Name:       "ipv6-off.example.com",
		QType:      "AAAA",
		Addresses:  nil,
		Server:     "IPv6 已关闭",
		DurationMS: 0,
		Outcome:    "nodata",
		Source:     "tun",
	})
	ring.record(kernel.DNSEvent{
		Time:       time.Now(),
		Name:       "https-rr.example.com",
		QType:      "HTTPS",
		Addresses:  []string{},
		Server:     "HTTPS https://dns.google/dns-query",
		DurationMS: 18,
		Outcome:    "ok",
		Source:     "tun",
	})
	reply := ring.read(0, 50)
	b, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, `"addresses":null`) || strings.Contains(s, `"entries":null`) {
		t.Fatalf("unexpected null slice in DNSLogsReply JSON: %s", s)
	}
	if strings.Count(s, `"addresses":[]`) != 2 {
		t.Fatalf("expected 2 empty address arrays, got: %s", s)
	}
}
