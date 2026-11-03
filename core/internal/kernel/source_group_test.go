package kernel

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound/group"
)

func sourceGroupConfig() Config {
	c := socksCfg("127.0.0.1:0")
	for _, n := range []string{"a", "b", "c", "manual", "other"} {
		c.Outbounds = append(c.Outbounds, OutboundConfig{Name: n, Type: "socks5", Server: "127.0.0.1", Port: 9})
	}
	c.Groups = []GroupConfig{
		{Name: "target", Type: "select", Members: []string{"manual", "nested"}, IncludeGroup: "source"},
		{Name: "source", Type: "select", Members: []string{"b", "nested", "a"}, Selected: "a"},
		{Name: "nested", Type: "select", Members: []string{"c", "b", "direct"}, Selected: "b"},
	}
	c.Routing = &RoutingOptions{Final: "target"}
	return c
}
func sourceMembers(c Config, name string) []string {
	for _, g := range c.Groups {
		if g.Name == name {
			return g.Members
		}
	}
	return nil
}
func TestSourceGroupExpansionOrderFiltersAndLegacy(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		for _, tc := range []struct {
			name, filter, exclude string
			want                  []string
		}{
			{"all", "", "", []string{"manual", "nested", "b", "c", "direct", "a"}},
			{"match", "^(a|c)$", "", []string{"manual", "nested", "c", "a"}},
			{"none", "^missing$", "", []string{"manual", "nested"}},
			{"exclude", "", "b|direct", []string{"manual", "nested", "c", "a"}},
			{"case", "(?i)^B$", "", []string{"manual", "nested", "b"}},
		} {
			t.Run(fmt.Sprintf("%s/reverse=%v", tc.name, reverse), func(t *testing.T) {
				c := sourceGroupConfig()
				c.Groups[0].Filter = tc.filter
				c.Groups[0].ExcludeFilter = tc.exclude
				if reverse {
					c.Groups[0], c.Groups[2] = c.Groups[2], c.Groups[0]
				}
				if e := c.Validate(); e != nil {
					t.Fatal(e)
				}
				if _, e := expandProviders(&c, nil); e != nil {
					t.Fatal(e)
				}
				if e := c.Validate(); e != nil {
					t.Fatal(e)
				}
				if got := sourceMembers(c, "target"); !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("got %v want %v", got, tc.want)
				}
				// Choosing one source member never limits the source to Current().
				if got := sourceMembers(c, "source"); !reflect.DeepEqual(got, []string{"b", "nested", "a"}) {
					t.Fatal(got)
				}
			})
		}
	}
	c := sourceGroupConfig()
	c.Groups[0].IncludeAllProxies = true
	if _, e := expandProviders(&c, nil); e != nil {
		t.Fatal(e)
	}
	if got := sourceMembers(c, "target"); !reflect.DeepEqual(got, []string{"manual", "nested", "b", "c", "direct", "a", "other"}) {
		t.Fatal(got)
	}
	// A source may itself include another source, declared later.
	c = sourceGroupConfig()
	c.Groups[1].IncludeGroup = "nested"
	c.Groups[1].Members = []string{"a"}
	c.Groups[1].Selected = ""
	if _, e := expandProviders(&c, nil); e != nil {
		t.Fatal(e)
	}
	if got := sourceMembers(c, "target"); !reflect.DeepEqual(got, []string{"manual", "nested", "a", "c", "b", "direct"}) {
		t.Fatal(got)
	}
	// Old documents without the new field retain their written nested groups.
	c = sourceGroupConfig()
	c.Groups[0].IncludeGroup = ""
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	if _, e := expandProviders(&c, nil); e != nil {
		t.Fatal(e)
	}
	if got := sourceMembers(c, "target"); !reflect.DeepEqual(got, []string{"manual", "nested"}) {
		t.Fatal(got)
	}
}
func TestSourceGroupInvalidDependenciesAndSafety(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Config)
	}{
		{"self", func(c *Config) { c.Groups[0].IncludeGroup = "target" }},
		{"two-includes", func(c *Config) { c.Groups[1].IncludeGroup = "target" }},
		{"mixed-nesting", func(c *Config) { c.Groups[2].Members = []string{"target"} }},
		{"mixed-via", func(c *Config) { c.Outbounds[0].Via = "target" }},
		{"missing", func(c *Config) { c.Groups[0].IncludeGroup = "missing" }},
		{"outbound-not-group", func(c *Config) { c.Groups[0].IncludeGroup = "a" }},
		{"direct-not-group", func(c *Config) { c.Groups[0].IncludeGroup = "direct" }},
		{"invalid-filter", func(c *Config) { c.Groups[0].Filter = "[" }},
		{"invalid-exclude", func(c *Config) { c.Groups[0].ExcludeFilter = "[" }},
		{"relay-target", func(c *Config) { c.Groups[0].Type = "relay"; c.Groups[0].Members = []string{"a"} }},
		{"relay-source", func(c *Config) { c.Groups[1] = GroupConfig{Name: "source", Type: "relay", Members: []string{"a", "b"}} }},
		{"nested-relay-source", func(c *Config) { c.Groups[2] = GroupConfig{Name: "nested", Type: "relay", Members: []string{"a", "b"}} }},
		{"duplicate-manual", func(c *Config) { c.Groups[0].Members = []string{"a", "a"} }},
		{"manual-limit", func(c *Config) { c.Groups[0].Members = make([]string, 65) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := sourceGroupConfig()
			tc.edit(&c)
			if e := c.Validate(); e == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	c := sourceGroupConfig()
	c.Groups[1].Members = []string{"direct", "reject"}
	c.Groups[1].Selected = ""
	c.Groups[0] = GroupConfig{Name: "target", Type: "url-test", IncludeGroup: "source", Probe: &group.ProbeOptions{URL: "http://127.0.0.1:9/"}}
	if _, _, e := CheckProviders(c); e == nil {
		t.Fatal("automatic group inherited reject")
	}
	c.Groups[0].ExcludeFilter = "reject"
	if _, _, e := CheckProviders(c); e != nil {
		t.Fatal("filtered reject must not poison automatic group", e)
	}
}
func TestSourceGroupProviderRefreshAndLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source")
	write := func(body string) {
		t.Helper()
		if e := os.WriteFile(path, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(providerURI("first", 9) + providerURI("second", 9))
	c := socksCfg("127.0.0.1:0")
	c.Providers = []ProviderConfig{{Name: "p", Type: "file", Path: path, Interval: Duration(time.Hour)}}
	c.Groups = []GroupConfig{{Name: "target", Type: "select", IncludeGroup: "source"}, {Name: "source", Type: "select", Use: []string{"p"}}}
	c.Routing = &RoutingOptions{Final: "target"}
	s := groupsStart(t, c)
	if got := sourceMembers(s.CurrentConfig(), "target"); !reflect.DeepEqual(got, []string{"first", "second"}) {
		t.Fatal(got)
	}
	if e := s.Select("target", "second"); e != nil {
		t.Fatal(e)
	}
	write(providerURI("third", 9) + providerURI("second", 9))
	if _, e := s.RefreshProvider(context.Background(), "p"); e != nil {
		t.Fatal(e)
	}
	if got := sourceMembers(s.CurrentConfig(), "target"); !reflect.DeepEqual(got, []string{"third", "second"}) {
		t.Fatal(got)
	}
	for _, g := range s.SelectGroups() {
		if g.Name == "target" && g.Current != "second" {
			t.Fatal("live selection lost", g)
		}
	}
	write(providerURI("fourth", 9))
	if _, e := s.RefreshProvider(context.Background(), "p"); e != nil {
		t.Fatal(e)
	}
	if got := sourceMembers(s.CurrentConfig(), "target"); !reflect.DeepEqual(got, []string{"fourth"}) {
		t.Fatal(got)
	}
	// Provider change re-expands from raw references, never a frozen member list.
	c.Groups[1].Members = []string{"direct"}
	if _, e := s.ApplyConfig(c); e != nil {
		t.Fatal(e)
	}
	if got := sourceMembers(s.CurrentConfig(), "target"); !reflect.DeepEqual(got, []string{"direct", "fourth"}) {
		t.Fatal(got)
	}
	gen := s.StatsView().Reload.Generation
	c.Groups[1].Members = []string{"target"}
	if _, e := s.ApplyConfig(c); e == nil {
		t.Fatal("cyclic reload accepted")
	}
	if s.StatsView().Reload.Generation != gen || !reflect.DeepEqual(sourceMembers(s.CurrentConfig(), "target"), []string{"direct", "fourth"}) {
		t.Fatal("invalid reload changed state")
	}
	// The existing 1024 expanded-member cap includes written members.
	var body strings.Builder
	for i := 0; i < 1100; i++ {
		body.WriteString(providerURI(fmt.Sprintf("n%04d", i), 9))
	}
	write(body.String())
	c.Groups[1].Members = nil
	c.Groups[0].Members = []string{"direct"}
	if _, e := s.ApplyConfig(c); e != nil {
		t.Fatal(e)
	}
	got := sourceMembers(s.CurrentConfig(), "target")
	if len(got) != 1024 || got[0] != "direct" || got[1023] != "n1022" {
		t.Fatal(len(got), got[0], got[len(got)-1])
	}
}
func TestSourceGroupFixedWeightsAndSelectionRemainConfigured(t *testing.T) {
	c := sourceGroupConfig()
	c.Groups[0] = GroupConfig{Name: "target", Type: "url-test", IncludeGroup: "source", Fixed: "a", Priority: map[string]float64{"a": 2, "other": 3}, Probe: &group.ProbeOptions{URL: "http://127.0.0.1:9/"}}
	s := groupsStart(t, c)
	if got := s.CurrentConfig().Groups[0]; got.Fixed != "a" || got.Priority["other"] != 3 {
		t.Fatal(got)
	}
	c.Groups[1].Members = []string{"b"}
	c.Groups[1].Selected = ""
	if _, e := s.ApplyConfig(c); e != nil {
		t.Fatal(e)
	}
	got := s.CurrentConfig().Groups[0]
	if got.Fixed != "a" || got.Priority["a"] != 2 || got.Priority["other"] != 3 {
		t.Fatal("dynamic disappearance rewrote soft fixed/weights", got)
	}
}
