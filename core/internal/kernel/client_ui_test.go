package kernel

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestUIConnectionsClosedRingAndTotal(t *testing.T) {
	var mu sync.Mutex
	events := []ConnectionEvent{}
	s := startTest(t, Inbound{Protocol: "socks5"}, func(c *Config) {
		c.SetConnectionSink(func(e ConnectionEvent) { mu.Lock(); events = append(events, e); mu.Unlock() })
	})
	// Desktop tracking works without changing the legacy details_enabled option.
	if s.detailsOn.Load() {
		t.Fatal("legacy option changed")
	}
	ctx := withSniff(context.Background(), &sniffResult{host: "sniff.example"})
	f, _ := s.newFlow(ctx, "tcp", Address{Host: "192.0.2.1", Port: 443})
	f.route(0, []string{"direct"})
	f.connectionOutcome(nil)
	active, closed := s.ClientConnections(500)
	if len(active) != 1 || active[0].Host != "sniff.example" || len(closed) != 0 {
		t.Fatal(active, closed)
	}
	f.addUp(13)
	f.addDown(17)
	f.end("ok")
	f.end("ok")
	for i := 0; i < 516; i++ {
		network := "tcp"
		if i%2 == 0 {
			network = "udp"
		}
		g, _ := s.newFlow(context.Background(), network, Address{Host: "target.example", Port: 80})
		if network == "tcp" {
			g.route(0, []string{"reject"})
			g.connectionOutcome(errRouteReject)
		} else {
			g.udpDecided(Address{Host: "target.example", Port: 80}, 0, []string{"direct"})
			g.udpDecided(Address{Host: "target.example", Port: 80}, 0, []string{"direct"})
		}
		g.end("ok")
	}
	active, closed = s.ClientConnections(500)
	if len(active) != 0 || len(closed) != 500 || s.TotalConnections() != 517 {
		t.Fatal(len(active), len(closed), s.TotalConnections())
	}
	if closed[0].ID != 517 || closed[499].ID != 18 || closed[0].End.Before(closed[0].Start) || closed[0].DurationMS < 0 {
		t.Fatal("closed order/end")
	}
	_, small := s.ClientConnections(200)
	if len(small) != 200 {
		t.Fatal("limit")
	}
	closed[0].Chain[0] = "changed"
	_, again := s.ClientConnections(1)
	if again[0].Chain[0] == "changed" {
		t.Fatal("alias")
	}
	mu.Lock()
	n := len(events)
	mu.Unlock()
	if n != 1034 {
		t.Fatal("UDP decisions duplicated", n)
	}
	// The snapshot labels and order are the original registry labels.
	sn := s.StatsView().Cumulative
	if sn.Rules[0].Name != "final->direct" || sn.Rules[0].Hits != 517 || sn.Rules[0].Up != 13 || sn.Rules[0].Down != 17 {
		t.Fatal(sn.Rules)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	_, closed = s.ClientConnections(500)
	if len(closed) != 0 {
		t.Fatal("stop retained closed history")
	}
}

func TestUIConnectionsConcurrentSnapshots(t *testing.T) {
	s := startTest(t, Inbound{Protocol: "socks5"}, func(c *Config) { c.SetConnectionSink(func(ConnectionEvent) {}) })
	var wg sync.WaitGroup
	for j := 0; j < 4; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 250; i++ {
				f, _ := s.newFlow(context.Background(), "tcp", Address{Host: "target.example", Port: 443})
				f.route(0, []string{"direct"})
				f.sniffHost(withSniff(context.Background(), &sniffResult{host: "tls.example"}))
				f.connectionOutcome(nil)
				s.ClientConnections(500)
				f.end("ok")
			}
		}()
	}
	wg.Wait()
	a, c := s.ClientConnections(500)
	if len(a) != 0 || len(c) != 500 || s.TotalConnections() != 1000 {
		t.Fatal(len(a), len(c), s.TotalConnections())
	}
}

func TestUIDNSQueryProvenanceCacheAndFilter(t *testing.T) {
	first := newDNSFixture(t, func(w []byte) []byte { return familyReply(w, "fail") })
	second := newDNSFixture(t, func(w []byte) []byte { return dnsReply(w, []string{"192.0.2.1", "2001:db8::1"}, 30) })
	s := startTest(t, Inbound{Protocol: "socks5"}, func(c *Config) { c.DNS = &DNSOptions{Servers: []string{first.address(), second.address()}} })
	r, err := s.QueryDNS(context.Background(), "Target.Example.", "A")
	if err != nil || r.Name != "target.example" || r.Server != "UDP "+second.address() || r.Cached || len(r.Addresses) != 1 || r.Addresses[0].Type != "A" {
		t.Fatal(r, err)
	}
	count := second.count.Load()
	// Ordinary traffic and the IPC query share exactly the same cache entry.
	ips, err := s.lookup(context.Background(), "target.example")
	if err != nil || len(ips) != 2 || second.count.Load() != count {
		t.Fatal(ips, err)
	}
	r, err = s.QueryDNS(context.Background(), "target.example", "AAAA")
	if err != nil || !r.Cached || r.Server != "UDP "+second.address() || len(r.Addresses) != 1 || r.Addresses[0].Type != "AAAA" || second.count.Load() != count {
		t.Fatal(r, err)
	}
	for _, name := range []string{"", "bad name", "a..b", "-bad.example", "https://private/token"} {
		if _, err := s.QueryDNS(context.Background(), name, "both"); !errors.Is(err, ErrDNSInvalidName) {
			t.Fatal(name, err)
		}
	}
	c, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = s.QueryDNS(c, "uncached.example", "both"); err == nil {
		t.Fatal("canceled query accepted")
	}
	if err = s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.QueryDNS(context.Background(), "target.example", "both"); !errors.Is(err, ErrCoreNotRunning) {
		t.Fatal(err)
	}
}

func TestUIDNSSystemNeverCached(t *testing.T) {
	r := configuredDNS(t, "system", 0)
	calls := 0
	r.bootstrap = func(context.Context, string, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("192.0.2.2")}, nil
	}
	for i := 0; i < 2; i++ {
		ips, server, cached, err := r.lookupAnswer(context.Background(), "system.example")
		if err != nil || server != "system" || cached || !reflect.DeepEqual(ips, []netip.Addr{netip.MustParseAddr("192.0.2.2")}) {
			t.Fatal(ips, server, cached, err)
		}
	}
	if calls != 2 || len(r.cache) != 0 {
		t.Fatal("system semantics changed")
	}
}

func TestUISniffReloadSharesAttributionCacheWithoutCopylock(t *testing.T) {
	in := Inbound{Protocol: "socks5", Listen: "127.0.0.1:7891", Name: "kat-client"}
	ctx := withInboundMeta(context.Background(), &in, nil, nil)
	m := inboundMetaOf(ctx)
	calls := 0
	m.process.once.Do(func() { calls++ })
	acc := &Server{cfg: Config{Inbounds: []Inbound{in}}}
	in.Sniff = &SniffOptions{Enabled: true}
	cur := &Server{cfg: Config{Inbounds: []Inbound{in}}}
	ctx = withInbound(ctx, 0)
	n := inboundMetaOf(cur.currentInboundMeta(ctx, acc))
	if n == m || n.process != m.process || n.sniff != in.Sniff {
		t.Fatal("reload lost metadata/cache sharing")
	}
	n.process.once.Do(func() { calls++ })
	if calls != 1 {
		t.Fatal("reload repeated cached attribution")
	}
}

func TestUIConnectionSetupFailureWithoutRoute(t *testing.T) {
	events := []ConnectionEvent{}
	s := startTest(t, Inbound{Protocol: "socks5"}, func(c *Config) { c.SetConnectionSink(func(e ConnectionEvent) { events = append(events, e) }) })
	f, _ := s.newFlow(context.Background(), "udp", Address{})
	f.end("udp_socket_failed")
	if len(events) != 2 || events[0].Outcome != "error" || events[0].Code != "udp_socket_failed" || !events[1].Ended || events[1].End == nil || events[1].FlowID != events[0].FlowID {
		t.Fatal(events)
	}
	g, _ := s.newFlow(context.Background(), "udp", Address{})
	g.udpFailure(Address{Host: "udp.example", Port: 443}, 0, []string{"direct"}, "udp_setup_failed")
	g.end("error")
	if len(events) != 4 || events[2].Target != "udp.example:443" || events[2].Rule != "final->direct" || !events[3].Ended || events[3].FlowID != events[2].FlowID {
		t.Fatal(events)
	}
}
