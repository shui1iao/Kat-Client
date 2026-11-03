package provider

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSmartRestoreFullNativeAndStrict(t *testing.T) {
	seed := `proxies: [{name: n, type: socks5, server: 127.0.0.1, port: 9}]
proxy-groups: [{name: S, type: smart, proxies: [n], include-all-proxies: true, filter: '.*', fixed: n, priority: {n: 0.5, gone: 2}, smart: {scope: site, exploration_rate: 0.05, adaptive_dial: false}, tolerance: 0, damping: {relative_improvement: 0, min_dwell: 0s}, url: 'http://127.0.0.1:9/', interval: 0}]
rules: ['MATCH,S']
`
	f, e := ParseFull([]byte(seed), "http://127.0.0.1:9/")
	if e != nil {
		t.Fatal(e)
	}
	g := f.Groups[0]
	if g.Type != "smart" || g.Smart == nil || g.Smart.Scope != "site" || g.Smart.ExplorationRate != .05 || g.Smart.AdaptiveDial == nil || *g.Smart.AdaptiveDial || g.Fixed != "n" || g.Priority["gone"] != 2 || !g.ToleranceSet || g.Tolerance != 0 {
		t.Fatal("native Smart import lost fields", g)
	}
	b, _ := json.Marshal(g)
	if !strings.Contains(string(b), `"type":"smart"`) {
		t.Fatal("Smart converted")
	}
	for _, bad := range []string{strings.Replace(seed, "scope: site", "scope: other", 1), strings.Replace(seed, "exploration_rate: 0.05", "exploration_rate: 0.051", 1), strings.Replace(seed, "adaptive_dial: false", "adaptive_dial: bad", 1), strings.Replace(seed, "scope: site", "unknown: true", 1), strings.Replace(seed, "fixed: n", "unknown: true", 1)} {
		if _, e := ParseFull([]byte(bad), ""); e == nil {
			t.Fatal("invalid accepted")
		}
	}
}
