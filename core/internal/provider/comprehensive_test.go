package provider

import (
	"testing"
)

func TestReservedSubscriptionNamesNeverBecomeBuiltins(t *testing.T) {
	for _, name := range []string{"direct", "reject"} {
		t.Run(name, func(t *testing.T) {
			r, e := Parse([]byte("socks5://127.0.0.1:1234#"+name), FormatAuto)
			if e != nil || len(r.Nodes) != 1 {
				t.Fatal("valid source node not parsed")
			}
			os, gs, roots, e := r.Materialize("", "https://example.invalid/", nil, nil)
			if e != nil || len(os) != 1 || len(gs) != 0 || len(roots) != 1 || roots[0] != os[0].Name || os[0].Name == "direct" || os[0].Name == "reject" || os[0].Server != "127.0.0.1" {
				t.Fatal("source proxy name was interpreted as a built-in route instead of consistently aliased")
			}
		})
	}
}
func FuzzSubscriptionMaterialize(f *testing.F) {
	for _, s := range []string{"socks5://127.0.0.1:1#direct", "socks5://127.0.0.1:1#reject", closureFixture, "proxies: []", "[]", "socks5://127.0.0.1:1234#normal"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 64<<10 {
			t.Skip()
		}
		r, e := Parse(b, FormatAuto)
		if e != nil {
			return
		}
		os, gs, roots, e := r.Materialize("fuzz", "https://example.invalid/", nil, nil)
		if e != nil {
			return
		}
		if len(os) != len(r.Nodes) || len(roots) != len(r.Nodes) {
			t.Fatal("unfiltered materialization lost a parsed node")
		}
		seen := map[string]bool{"direct": true, "reject": true}
		for _, o := range os {
			if seen[o.Name] || Validate(o) != nil {
				t.Fatal("invalid or duplicate projection")
			}
			seen[o.Name] = true
		}
		for _, g := range gs {
			if seen[g.Name] {
				t.Fatal("duplicate group")
			}
			seen[g.Name] = true
		}
		for _, n := range roots {
			if !seen[n] {
				t.Fatal("unbound root")
			}
		}
	})
}
