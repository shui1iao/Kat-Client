package kernel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestChainStripIdempotent(t *testing.T) {
	type retainedKey struct{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, retainedKey{}, "keep")
	ctx = withHops(withInbound(ctx, 0), &hops{})
	got := strip(ctx)
	for range 4 {
		if again := strip(got); again != got {
			t.Fatal("repeated strip rebuilt an identical context")
		}
	}
	if isClient(got) || got.Value(hopsKey{}).(*hops) != nil || got.Value(retainedKey{}) != "keep" {
		t.Fatal("underlay context isolation changed")
	}
	if !isClient(ctx) {
		t.Fatal("parent context mutated")
	}
	cancel()
	if !errors.Is(got.Err(), context.Canceled) {
		t.Fatal("cancel lost")
	}
}
func TestValidateRejectsUnknownGeositeAndASNVia(t *testing.T) {
	for _, tc := range []struct {
		name    string
		geosite *GeositeConfig
		asn     *ASNConfig
	}{
		{
			name:    "unknown geosite via",
			geosite: &GeositeConfig{Path: "/tmp/geosite.dat", URL: "https://example.com/geosite.dat", Via: "missing-out"},
		},
		{
			name: "unknown asn via",
			asn:  &ASNConfig{Path: "/tmp/asn.mmdb", URL: "https://example.com/asn.mmdb", Via: "missing-out"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Inbounds: []Inbound{
					{Protocol: "socks5", Listen: "127.0.0.1:1080"},
				},
				Geosite: tc.geosite,
				ASN:     tc.asn,
			}
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "routing refers to an unknown outbound or group") {
				t.Fatalf("Validate() = %v, want unknown outbound or group error", err)
			}
		})
	}
}

func BenchmarkDNSNameNormalized(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s, err := dnsName("sub.api.example.com")
		if err != nil || s != "sub.api.example.com" {
			b.Fatalf("got (%q, %v)", s, err)
		}
	}
}
