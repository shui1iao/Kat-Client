package kernel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/provider"
	"github.com/shui1iao/Kat/internal/stats"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func substoreBody(front, tail int, probe string) string {
	return fmt.Sprintf(`proxies:
 - {name: "front A", type: ss, server: 127.0.0.1, port: %d, cipher: aes-128-gcm, password: fixture, udp: true, plugin: obfs, plugin-opts: {mode: http, host: example.com}}
 - {name: tail, type: ss, server: 127.0.0.1, port: %d, cipher: 2022-blake3-aes-128-gcm, password: QUFBQUFBQUFBQUFBQUFBQQ==, udp: true, dialer-proxy: upstream}
proxy-groups:
 - {name: upstream, type: url-test, include-all: true, filter: "^front", url: %q}
 - {name: unrelated, type: select, proxies: [missing]}
`, front, tail, probe)
}
func assertSubstoreGraph(t *testing.T, c Config, n, ob, via, groups, members int) {
	t.Helper()
	gotOb, gotVia, gotGroups := 0, 0, 0
	names := map[string]bool{}
	for _, o := range c.Outbounds {
		names[o.Name] = true
		if o.Obfs != nil {
			gotOb++
		}
		if o.Via != "" {
			gotVia++
		}
	}
	for _, g := range c.Groups {
		names[g.Name] = true
		if g.Type == "url-test" {
			gotGroups++
			if len(g.Members) != members {
				t.Fatal("dependency member count")
			}
		}
	}
	for _, o := range c.Outbounds {
		if o.Via != "" && !names[o.Via] {
			t.Fatal("broken via")
		}
	}
	for _, g := range c.Groups {
		for _, m := range g.Members {
			if !names[m] {
				t.Fatal("broken member")
			}
		}
	}
	if len(c.Outbounds) != n || gotOb != ob || gotVia != via || gotGroups != groups {
		t.Fatal("graph option counts")
	}
}
func TestSubstoreAuthorizedCacheRestart(t *testing.T) {
	path := os.Getenv("KAT_AUTHORIZED_SUBSCRIPTION")
	if path == "" {
		t.Skip("private input not supplied")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("private input unavailable")
	}
	dir := t.TempDir()
	cache := filepath.Join(dir, "authorized.cache")
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Content-Type", "text/plain"); w.Write(b) }))
	defer sub.Close()
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Log = &LogOptions{Level: "error"}
	c.Providers = []ProviderConfig{{Name: "authorized", Type: "http", URL: sub.URL, Path: cache, Interval: Duration(time.Hour), DependencyProbeURL: "https://example.invalid/"}}
	c.Groups = []GroupConfig{{Name: "pick", Type: "select", Use: []string{"authorized"}}}
	var original Config
	for i := 0; i < 2; i++ {
		s, e := Start(c)
		if e != nil {
			t.Fatal("private cached graph start")
		}
		if i == 0 {
			if _, e := s.RefreshProvider(context.Background(), "authorized"); e != nil {
				s.Close(context.Background())
				t.Fatal("private HTTP provider refresh")
			}
		}
		cfg := s.CurrentConfig()
		assertSubstoreGraph(t, cfg, 22, 18, 3, 1, 4)
		if i == 0 {
			original = cfg
		} else if !reflect.DeepEqual(original.Outbounds, cfg.Outbounds) || !reflect.DeepEqual(original.Groups, cfg.Groups) {
			t.Fatal("cache graph changed")
		}
		s.Close(context.Background())
		disk, e := os.ReadFile(cache)
		if e != nil || !bytes.Equal(disk, b) {
			t.Fatal("private cache not original bytes")
		}
	}
	t.Log("private HTTP dynamic provider + original cache restart: 22 / 18 obfs / 3 via / 1 group / 4 members")
}
func TestSubstoreRefreshTransaction(t *testing.T) {
	var mu sync.Mutex
	body := substoreBody(1234, 2345, "http://127.0.0.1:1/")
	status := 200
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	defer sub.Close()
	cache := filepath.Join(t.TempDir(), "last.cache")
	os.WriteFile(cache, []byte(body), 0600)
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Log = &LogOptions{Level: "error"}
	c.Providers = []ProviderConfig{{Name: "p", Type: "http", URL: sub.URL, Path: cache, Interval: Duration(time.Hour), Filter: "^tail"}}
	c.Groups = []GroupConfig{{Name: "pick", Type: "select", Use: []string{"p"}}}
	s := groupsStart(t, c)
	p := s.core.providers["p"]
	before := s.StatsView().Reload.Generation
	mu.Lock()
	body = strings.Replace(body, "name: tail,", "name: tail2,", 1)
	good := body
	mu.Unlock()
	if _, e := s.RefreshProvider(context.Background(), "p"); e != nil {
		t.Fatal("valid refresh")
	}
	if s.StatsView().Reload.Generation != before+1 {
		t.Fatal("double generation")
	}
	assertSubstoreGraph(t, s.CurrentConfig(), 2, 1, 1, 1, 1)
	if len(s.SelectGroups()[0].Members) != 1 {
		t.Fatal("dependency-only node exposed as root")
	}
	goodRes, _ := p.snapshot()
	goodHash := p.hash
	gen := s.StatsView().Reload.Generation
	check := func() {
		t.Helper()
		res, _ := p.snapshot()
		disk, _ := os.ReadFile(cache)
		if !reflect.DeepEqual(res, goodRes) || p.hash != goodHash || string(disk) != good || s.StatsView().Reload.Generation != gen {
			t.Fatal("failed candidate changed accepted snapshot/cache/runtime")
		}
	}
	for _, bad := range []string{"proxies: [", strings.Replace(good, "dialer-proxy: upstream", "dialer-proxy: missing", 1), strings.Replace(good, "filter: \"^front\"", "filter: \".*\"", 1), "proxies: []"} {
		mu.Lock()
		body = bad
		mu.Unlock()
		if _, e := s.RefreshProvider(context.Background(), "p"); e == nil {
			t.Fatal("invalid candidate succeeded")
		}
		check()
	}
	mu.Lock()
	body = good
	status = 503
	mu.Unlock()
	if _, e := s.RefreshProvider(context.Background(), "p"); e == nil {
		t.Fatal("fetch failure")
	}
	check()
	// Exercise the SAME locked transaction at the prepare failure boundary.
	next, e := decodeConfig(s.current().cfg.raw)
	if e != nil {
		t.Fatal(e)
	}
	next.Stats = &StatsOptions{File: filepath.Join(t.TempDir(), "busy.json")}
	release, e := stats.Lock(next.Stats.File)
	if e != nil {
		t.Fatal(e)
	}
	defer release()
	b := []byte(strings.Replace(good, "name: tail2,", "name: tail3,", 1))
	r, e := provider.Parse(b, provider.FormatAuto)
	if e != nil {
		t.Fatal("candidate parse")
	}
	q := &providerCandidate{p: p, res: r, body: b, hash: sha256.Sum256(b)}
	s.core.reloadMu.Lock()
	_, e = s.reloadCandidateLocked("provider", false, &next, q)
	s.core.reloadMu.Unlock()
	var re *ReloadError
	if !errors.As(e, &re) || re.Stage != "stats" {
		t.Fatal("stats prepare failure not induced")
	}
	check()
	// A replaced source must reject this late completed fetch before expansion.
	old := s.core.providers["p"]
	s.core.provMu.Lock()
	s.core.providers["p"] = newProviderRT(s.core, c.Providers[0], "")
	s.core.provMu.Unlock()
	_, e = s.reloadProvider(context.Background(), q)
	s.core.provMu.Lock()
	s.core.providers["p"] = old
	s.core.provMu.Unlock()
	if e == nil {
		t.Fatal("stale source accepted")
	}
	check()
	os.Chtimes(cache, time.Now(), time.Now())
	other, e := Start(c)
	if e != nil {
		t.Fatal("last good cache restart")
	}
	defer other.Close(context.Background())
	assertSubstoreGraph(t, other.CurrentConfig(), 2, 1, 1, 1, 1)
}
func independentObfsPeer(t *testing.T, target string) string {
	t.Helper()
	bin := os.Getenv("KAT_INTEROP_OBFS_PEER")
	if bin == "" {
		t.Skip("set independent mihomo obfs peer")
	}
	cmd := exec.Command(bin, target)
	stdout, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = cmd.Start(); e != nil {
		t.Fatal("peer start")
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	line, e := bufio.NewReader(stdout).ReadString('\n')
	if e != nil {
		t.Fatal("peer ready")
	}
	addr := strings.TrimSpace(line)
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatal("non-loopback peer")
	}
	return addr
}
func TestSubstoreIndependentObfsViaURLTestTCPUDP(t *testing.T) {
	frontCfg := socksCfg()
	frontCfg.DNS = &DNSOptions{Server: "system"}
	frontCfg.Inbounds = []Inbound{{Protocol: "shadowsocks", Listen: "127.0.0.1:0", SS: &SSOptions{Method: "aes-128-gcm", Password: "fixture", Salts2017: 32, TCPSalts: 32, Sessions: 8}}}
	front := groupsStart(t, frontCfg)
	peer := independentObfsPeer(t, front.Addresses()[0].String())
	_, pstr, _ := net.SplitHostPort(peer)
	var frontPort int
	fmt.Sscan(pstr, &frontPort)
	tailCfg := socksCfg()
	tailCfg.DNS = &DNSOptions{Server: "system"}
	in := ssIn()
	in.Listen = "127.0.0.1:0"
	tailCfg.Inbounds = []Inbound{in}
	tail := groupsStart(t, tailCfg)
	tailPort := tail.Addresses()[0].(*net.TCPAddr).Port
	probe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer probe.Close()
	var mu sync.Mutex
	body := substoreBody(frontPort, tailPort, probe.URL)
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { mu.Lock(); defer mu.Unlock(); fmt.Fprint(w, body) }))
	defer sub.Close()
	cache := filepath.Join(t.TempDir(), "graph.cache")
	os.WriteFile(cache, []byte(body), 0600)
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Providers = []ProviderConfig{{Name: "p", Type: "http", URL: sub.URL, Path: cache, Interval: Duration(time.Hour), Filter: "^tail"}}
	c.Groups = []GroupConfig{{Name: "pick", Type: "select", Use: []string{"p"}}}
	c.Routing = &RoutingOptions{Final: "pick"}
	s := groupsStart(t, c)
	assertSubstoreGraph(t, s.CurrentConfig(), 2, 1, 1, 1, 1)
	target := echoTCP(t)
	conn, ok := socksTo(t, s.Addresses()[0].String(), target)
	if !ok {
		t.Fatal("true obfs front -> url-test -> SS2022 TCP connect")
	}
	defer conn.Close()
	if !echoOnce(conn, "independent-obfs-chain") {
		t.Fatal("true SS chain echo")
	}
	for _, g := range s.CurrentConfig().Groups {
		if g.Type == "url-test" {
			round, e := s.ProbeGroup(context.Background(), g.Name, probe.URL)
			if e != nil || len(round) != 1 || round[0].Error != "" || round[0].ProbeMS == nil {
				t.Fatal("independent obfs dependency group HTTP probe")
			}
		}
	}
	tailName := s.SelectGroups()[0].Members[0]
	if result, e := s.ProbeNode(context.Background(), tailName, probe.URL); e != nil || result.Error != "" || result.ProbeMS == nil {
		t.Fatal("via SS2022 actual HTTP probe")
	}
	// A new generation must also work when the first actual use is native
	// UDP, without a manual warm-up or copied health from the previous graph.
	if _, e := s.ApplyConfig(c); e != nil {
		t.Fatal("cold UDP generation")
	}
	ob := s.current().rt.nodes[tailName]
	pc, e := ob.ListenPacket(context.Background())
	if e != nil {
		t.Fatal("native UDP chain")
	}
	defer pc.Close()
	udp, _ := echoUDP(t)
	if !udpRoundTrip(pc, outbound.Addr{Host: udp.Host, Port: udp.Port}, []byte("native-udp-through-both-SS")) {
		t.Fatal("native UDP chain echo")
	}
	// The production SS tcpConn must still send its header on first Read,
	// then propagate CloseWrite through url-test, SS and obfs to the target.
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	targetDone := make(chan bool, 1)
	go func() {
		c, e := ln.Accept()
		if e != nil {
			targetDone <- false
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(3 * time.Second))
		c.Write([]byte("greeting"))
		b, e := io.ReadAll(c)
		if e != nil || string(b) != "payload" {
			targetDone <- false
			return
		}
		_, e = c.Write([]byte("after-fin"))
		targetDone <- e == nil
	}()
	serverFirst, e := ob.DialTCP(context.Background(), outbound.Addr{Host: "127.0.0.1", Port: uint16(ln.Addr().(*net.TCPAddr).Port)})
	if e != nil {
		t.Fatal("server first dial")
	}
	defer serverFirst.Close()
	serverFirst.SetDeadline(time.Now().Add(3 * time.Second))
	banner := make([]byte, 8)
	if _, e = io.ReadFull(serverFirst, banner); e != nil || string(banner) != "greeting" {
		t.Fatal("read-before-write")
	}
	serverFirst.Write([]byte("payload"))
	cw, ok := serverFirst.(interface{ CloseWrite() error })
	if !ok || cw.CloseWrite() != nil {
		t.Fatal("half-close capability lost")
	}
	reply := make([]byte, 9)
	if _, e = io.ReadFull(serverFirst, reply); e != nil || string(reply) != "after-fin" {
		t.Fatal("half-close response")
	}
	if !<-targetDone {
		t.Fatal("half-close target")
	}
	gen := s.StatsView().Reload.Generation
	mu.Lock()
	body = strings.Replace(body, "name: tail,", "name: tail2,", 1)
	mu.Unlock()
	if _, e := s.RefreshProvider(context.Background(), "p"); e != nil {
		t.Fatal("chain refresh")
	}
	if s.StatsView().Reload.Generation != gen+1 || !echoOnce(conn, "old-flow-survives") {
		t.Fatal("generation or retained stream")
	}
	t.Log("independent mihomo server: SS2017-obfs -> url-test -> SS2022 cold TCP + cold native UDP, refresh once and retained stream")
}
func TestSubstoreLateFetchAfterSourceReplacement(t *testing.T) {
	initial := substoreBody(1234, 2345, "http://127.0.0.1:1/")
	late := strings.Replace(initial, "name: tail,", "name: late,", 1)
	newBody := strings.Replace(initial, "name: tail,", "name: current,", 1)
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	oldHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		select {
		case <-release:
			fmt.Fprint(w, late)
		case <-r.Context().Done():
		}
	}))
	defer oldHTTP.Close()
	newHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, newBody) }))
	defer newHTTP.Close()
	dir := t.TempDir()
	oldCache := filepath.Join(dir, "old.cache")
	newCache := filepath.Join(dir, "new.cache")
	os.WriteFile(oldCache, []byte(initial), 0600)
	os.WriteFile(newCache, []byte(newBody), 0600)
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Log = &LogOptions{Level: "error"}
	c.Providers = []ProviderConfig{{Name: "p", Type: "http", URL: oldHTTP.URL, Path: oldCache, Interval: Duration(time.Hour)}}
	c.Groups = []GroupConfig{{Name: "pick", Type: "select", Use: []string{"p"}}}
	s := groupsStart(t, c)
	old := s.core.providers["p"]
	done := make(chan error, 1)
	go func() { done <- old.update(context.Background()) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("old fetch not started")
	}
	next, e := decodeConfig(s.current().cfg.raw)
	if e != nil {
		t.Fatal(e)
	}
	next.Providers[0].URL = newHTTP.URL
	next.Providers[0].Path = newCache
	b, _ := json.Marshal(next)
	next, e = decodeConfig(b)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.ApplyConfig(next); e != nil {
		t.Fatal("replace source during fetch")
	}
	gen := s.StatsView().Reload.Generation
	active := s.core.providers["p"]
	accepted, _ := active.snapshot()
	unblock()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("late old source accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("stale fetch blocked reload")
	}
	after, _ := active.snapshot()
	disk, _ := os.ReadFile(oldCache)
	newDisk, _ := os.ReadFile(newCache)
	if !reflect.DeepEqual(after, accepted) || s.StatsView().Reload.Generation != gen || string(disk) != initial || string(newDisk) != newBody {
		t.Fatal("late source corrupted accepted state")
	}
}
func TestSubstoreCacheWarningAfterCommit(t *testing.T) {
	oldBody := substoreBody(1234, 2345, "http://127.0.0.1:1/")
	newBody := strings.Replace(oldBody, "name: tail,", "name: changed,", 1)
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, newBody) }))
	defer sub.Close()
	cache := filepath.Join(t.TempDir(), "cache")
	os.WriteFile(cache, []byte(oldBody), 0600)
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Log = &LogOptions{Level: "error"}
	c.Providers = []ProviderConfig{{Name: "p", Type: "http", URL: sub.URL, Path: cache, Interval: Duration(time.Hour)}}
	c.Groups = []GroupConfig{{Name: "pick", Type: "select", Use: []string{"p"}}}
	s := groupsStart(t, c)
	p := s.core.providers["p"]
	gen := s.StatsView().Reload.Generation
	// Inject an actual cache filesystem error: parent is the previous regular
	// cache file, so MkdirAll cannot create a staging directory beneath it.
	p.cache = filepath.Join(cache, "blocked")
	defer func() { p.cache = cache }()
	if _, e := s.RefreshProvider(context.Background(), "p"); e != nil {
		t.Fatal("cache warning incorrectly reported runtime failure")
	}
	accepted, _ := p.snapshot()
	disk, _ := os.ReadFile(cache)
	if s.StatsView().Reload.Generation != gen+1 || accepted.Nodes[1].Options.Name != "changed" || string(disk) != oldBody {
		t.Fatal("cache warning semantics")
	}
}
func TestSubstoreKernelRequiresProbeURLSource(t *testing.T) {
	body := strings.Replace(substoreBody(1, 2, "http://127.0.0.1:1/"), ", url: \"http://127.0.0.1:1/\"", "", 1)
	path := filepath.Join(t.TempDir(), "source.yaml")
	os.WriteFile(path, []byte(body), 0600)
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Log = &LogOptions{Level: "error"}
	c.Providers = []ProviderConfig{{Name: "p", Type: "file", Path: path}}
	c.Groups = []GroupConfig{{Name: "pick", Type: "select", Use: []string{"p"}}}
	if s, e := Start(c); e == nil {
		s.Close(context.Background())
		t.Fatal("kernel invented missing dependency URL")
	}
	c.Providers[0].DependencyProbeURL = "http://127.0.0.1:1/"
	s, e := Start(c)
	if e != nil {
		t.Fatal("explicit fallback failed")
	}
	s.Close(context.Background())
}
func TestSubstoreProviderTotalLimitRejectsGraph(t *testing.T) {
	r, e := provider.Parse([]byte(substoreBody(1, 2, "http://127.0.0.1:1/")), provider.FormatAuto)
	if e != nil {
		t.Fatal("fixture")
	}
	for i := len(r.Nodes); i < provider.MaxNodes; i++ {
		r.Nodes = append(r.Nodes, provider.Node{Options: outbound.Options{Name: fmt.Sprintf("extra%d", i), Type: "socks5", Server: "127.0.0.1", Port: 1}})
	}
	c := socksCfg("127.0.0.1:0")
	provs := map[string]*providerRT{}
	for i := 0; i < 5; i++ {
		pc := ProviderConfig{Name: fmt.Sprintf("p%d", i), Type: "http", URL: "http://127.0.0.1:1/"}
		c.Providers = append(c.Providers, pc)
		p := newProviderRT(nil, pc, "")
		p.res, p.loaded = r, true
		provs[pc.Name] = p
	}
	if _, e := expandProviders(&c, provs); e == nil {
		t.Fatal("total limit silently truncated dependency graph")
	}
}
