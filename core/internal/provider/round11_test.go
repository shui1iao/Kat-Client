package provider

import (
	"testing"
	"time"
)

func TestR11MihomoSubscriptionHealthDefaultsAndOverrides(t *testing.T) {
	f, e := ParseFull([]byte("proxies:\n - {name: n, type: socks5, server: example.org, port: 1080}\nproxy-groups:\n - {name: HK, type: url-test, include-all: true, filter: n}\n - {name: Final, type: fallback, proxies: [HK]}\nrules:\n - MATCH,Final\n"), "https://custom.invalid/probe")
	if e != nil {
		t.Fatal(e)
	}
	for _, g := range f.Groups {
		if g.Probe.URL != "https://www.gstatic.com/generate_204" || g.Probe.Interval.Value() != 0 || g.Lazy != nil || g.Tolerance != 0 {
			t.Fatal("not official default", g.Name)
		}
	}
	f, e = ParseFull([]byte("proxies:\n - {name: n, type: socks5, server: example.org, port: 1080}\nproxy-groups:\n - {name: HK, type: url-test, proxies: [n], url: 'https://other.invalid/204', interval: 45, lazy: false, tolerance: 50}\nrules:\n - MATCH,HK\n"), "")
	if e != nil {
		t.Fatal(e)
	}
	g := f.Groups[0]
	if g.Probe.URL != "https://other.invalid/204" || g.Probe.Interval.Value() != 45*time.Second || g.Lazy == nil || *g.Lazy || g.Tolerance.Value() != 50*time.Millisecond {
		t.Fatal("custom values lost")
	}
}

func TestK1MihomoExplicitZeroTolerancePreserved(t *testing.T) {
	f, e := ParseFull([]byte("proxies:\n - {name: n, type: socks5, server: example.org, port: 1080}\nproxy-groups:\n - {name: Auto, type: url-test, proxies: [n], tolerance: 0}\nrules: ['MATCH,Auto']\n"), "")
	if e != nil {
		t.Fatal(e)
	}
	if len(f.Groups) != 1 || !f.Groups[0].ToleranceSet || f.Groups[0].Tolerance != 0 {
		t.Fatal("explicit zero lost")
	}
}
