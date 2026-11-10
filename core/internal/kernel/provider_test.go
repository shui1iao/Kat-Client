package kernel

import (
	"context"

	"fmt"
	"net"

	"os"
	"path/filepath"
	"reflect"
	"strings"

	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/group"
)

func groupsStart(t *testing.T, c Config) *Server {
	t.Helper()
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		s.Close(ctx)
	})
	return s
}
func providerURI(name string, port int) string {
	return fmt.Sprintf("socks5://127.0.0.1:%d#%s\n", port, name)
}

func TestProviderFileExpansionFiltersAndReports(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nodes.yaml")
	os.WriteFile(p, []byte("proxies:\n  - {name: 香港 1, type: socks5, server: 127.0.0.1, port: 9, udp: true}\n  - {name: 香港过期, type: socks5, server: 127.0.0.1, port: 9}\n  - {name: 香港 1, type: anytls, server: 127.0.0.1, port: 9, password: fixture, client-fingerprint: chrome, tfo: true}\n  - {name: unsupported, type: vmess}\n"), 0600)
	c := socksCfg("127.0.0.1:0")
	c.Providers = []ProviderConfig{{Name: "p", Type: "file", Path: p}}
	c.Outbounds = []OutboundConfig{{Name: "written", Type: "socks5", Server: "127.0.0.1", Port: 9}, {Name: "香港 1", Type: "socks5", Server: "127.0.0.1", Port: 9}}
	// Written names keep the existing alphabet. Use a valid explicit outbound as the filter exception.
	c.Outbounds = c.Outbounds[:1]
	c.Groups = []GroupConfig{{Name: "filtered", Type: "select", Members: []string{"written"}, Use: []string{"p"}, Filter: "香港", ExcludeFilter: "过期", ExcludeType: "anytls"}, {Name: "all", Type: "select", IncludeAll: true}, {Name: "proxies", Type: "select", IncludeAllProxies: true}, {Name: "providers", Type: "select", IncludeAllProviders: true}}
	reps, gs, e := CheckProviders(c)
	if e != nil {
		t.Fatal(e)
	}
	if len(reps) != 1 || len(reps[0].Nodes) != 3 || len(reps[0].Skipped) != 1 || len(reps[0].Renamed) != 1 || len(reps[0].Ignored) != 1 || len(reps[0].Fingerprints) != 1 {
		t.Fatalf("report: %+v", reps)
	}
	if gs[0].Members != 2 || gs[1].Members != 4 || gs[2].Members != 1 || gs[3].Members != 3 {
		t.Fatal(gs)
	}
	s := groupsStart(t, c)
	if !reflect.DeepEqual(s.SelectGroups()[0].Members, []string{"written", "香港 1"}) {
		t.Fatal(s.SelectGroups())
	}
	// File without interval is re-read on reload, and empty failure retains old nodes.
	os.WriteFile(p, []byte("proxies: []\n"), 0600)
	s.SetConfigLoader(func() (Config, error) { return c, nil })
	if _, e := s.Reload("test"); e != nil {
		t.Fatal(e)
	}
	if len(s.SelectGroups()[0].Members) != 2 {
		t.Fatal("file empty dropped old")
	}
	t.Logf("dynamic filters exclude expired/anytls but retain explicit written; reports=%+v groups=%+v", reps, gs)
}
func TestRelayEquivalentViaTCPUDPAndValidation(t *testing.T) {
	target := outbound.Addr{Host: "127.0.0.1", Port: rcEchoTCP(t)}
	udp := outbound.Addr{Host: "127.0.0.1", Port: rcEchoUDP(t)}
	c := socksCfg("127.0.0.1:0")
	names := []string{"a", "b", "c", "d"}
	for _, name := range names {
		up := groupsStart(t, socksCfg("127.0.0.1:0"))
		c.Outbounds = append(c.Outbounds, OutboundConfig{Name: name, Type: "socks5", Server: "127.0.0.1", Port: uint16(up.Addresses()[0].(*net.TCPAddr).Port)})
	}
	for n := 1; n <= 4; n++ {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			c0 := c
			c0.Groups = []GroupConfig{{Name: "relay", Type: group.TypeRelay, Members: names[:n]}}
			s := groupsStart(t, c0)
			r := s.rt.nodes["relay"]
			if e := rcTCPEcho(r, target); e != nil {
				t.Fatal(e)
			}
			pc, e := r.ListenPacket(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if e = rcUDPEcho(pc, udp); e != nil {
				t.Fatal(e)
			}
			pc.Close()
			v := c
			v.Outbounds = append([]OutboundConfig(nil), c.Outbounds...)
			for i := 1; i < n; i++ {
				v.Outbounds[i].Via = names[i-1]
			}
			sv := groupsStart(t, v)
			ob := sv.rt.nodes[names[n-1]]
			if e := rcTCPEcho(ob, target); e != nil {
				t.Fatal(e)
			}
			pv, e := ob.ListenPacket(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if e = rcUDPEcho(pv, udp); e != nil {
				t.Fatal(e)
			}
			pv.Close()
			t.Logf("relay/via %d hops TCP+UDP identical success", n)
		})
	}
	for label, mut := range map[string]func(*Config){"too deep": func(c *Config) {
		c.Outbounds[0].Via = "b"
		c.Groups = []GroupConfig{{Name: "r", Type: group.TypeRelay, Members: []string{"a", "c", "d", "b"}}}
	}, "cycle": func(c *Config) {
		c.Outbounds[0].Via = "r"
		c.Groups = []GroupConfig{{Name: "r", Type: group.TypeRelay, Members: []string{"a", "b"}}}
	}, "illegal member": func(c *Config) {
		c.Groups = []GroupConfig{{Name: "g", Type: "select", Members: []string{"a"}}, {Name: "r", Type: "relay", Members: []string{"a", "g"}}}
	}, "subsequent via": func(c *Config) {
		c.Outbounds[1].Via = "a"
		c.Groups = []GroupConfig{{Name: "r", Type: "relay", Members: []string{"a", "b"}}}
	}} {
		x := c
		x.Outbounds = append([]OutboundConfig(nil), c.Outbounds...)
		mut(&x)
		e := x.Validate()
		if e == nil {
			t.Fatal(label, "accepted")
		}
		if label == "too deep" && !strings.Contains(e.Error(), "deeper than 4") {
			t.Fatal(e)
		}
		t.Log(label, e)
	}
}

func TestProviderSelectPersistenceRestartAndDefaultChange(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "nodes.txt")
	os.WriteFile(file, []byte(providerURI("a", 9)+providerURI("b", 9)), 0600)
	c := socksCfg("127.0.0.1:0")
	c.Stats = &StatsOptions{File: filepath.Join(dir, "x.stats.json")}
	c.Providers = []ProviderConfig{{Name: "p", Type: "file", Path: file}}
	c.Groups = []GroupConfig{{Name: "pick", Type: "select", Use: []string{"p"}}}
	s := groupsStart(t, c)
	if e := s.Select("pick", "b"); e != nil {
		t.Fatal(e)
	}
	closeNow(t, s)
	os.WriteFile(file, []byte(providerURI("c", 9)+providerURI("b", 9)), 0600)
	s2 := groupsStart(t, c)
	v := s2.SelectGroups()[0]
	if v.Current != "b" || v.Source != "runtime" || v.Default != "" {
		t.Fatal("provider first-node change reset persisted choice", v)
	}
	closeNow(t, s2)
	c.Groups = []GroupConfig{{Name: "pick", Type: "select", Use: []string{"p"}, Selected: "c"}}
	s3 := groupsStart(t, c)
	v = s3.SelectGroups()[0]
	if v.Current != "c" || v.Source != "config" || v.Default != "c" {
		t.Fatal("explicit default change not respected", v)
	}
	t.Log("persisted dynamic select survives provider first-node change across restart; explicit configured default still wins")
}

func TestProviderAllUnsupportedStillReported(t *testing.T) {
	file := filepath.Join(t.TempDir(), "nodes.yaml")
	os.WriteFile(file, []byte("proxies:\n - {name: unsupported-vmess, type: vmess}\n - {name: unsupported-plugin, type: ss, plugin: obfs}\n"), 0600)
	c := socksCfg("127.0.0.1:0")
	c.Providers = []ProviderConfig{{Name: "p", Type: "file", Path: file}}
	c.Groups = []GroupConfig{{Name: "g", Type: "select", Use: []string{"p"}}}
	reps, _, e := CheckProviders(c)
	if e != nil || len(reps) != 1 || len(reps[0].Skipped) != 2 || reps[0].Error != "no usable node" {
		t.Fatal(reps, e)
	}
	s := groupsStart(t, c)
	if len(s.SelectGroups()[0].Members) != 0 {
		t.Fatal("unsupported nodes installed")
	}
	t.Logf("all unsupported: error=%q individual skipped=%+v", reps[0].Error, reps[0].Skipped)
}
