package kernel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"github.com/shui1iao/Kat/internal/procattr"
	"github.com/shui1iao/Kat/internal/route"
	"github.com/shui1iao/Kat/internal/tunstack"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestK3ProcessDetailsKnownUnknownAndPSL(t *testing.T) {
	old := lookupApplication
	defer func() { lookupApplication = old }()
	for _, status := range []string{"known", "ambiguous", "unknown", "denied"} {
		lookupApplication = func(context.Context, procattr.Query) procattr.Identity {
			return procattr.Identity{Name: "browser.exe", Path: `C:\Program Files\Browser\browser.exe`, Status: status}
		}
		ctx := withInboundMeta(context.Background(), &Inbound{Protocol: "socks5"}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7891}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 23456})
		s := &Server{core: &core{connectionSink: func(ConnectionEvent) {}, started: time.Now()}}
		f := &flow{s: s, network: "tcp"}
		addr := Address{Host: "api.example.co.uk", Port: 443}
		f.initDetails(ctx, addr)
		f.scheduleDetails(ctx, addr)
		waitFor(t, func() bool { return f.info(time.Now()).ProcessStatus == status })
		ci := f.info(time.Now())
		if ci.DomainSuffix != "example.co.uk" {
			t.Fatal(ci.DomainSuffix)
		}
		if status == "known" {
			if ci.ProcessName != "browser.exe" || ci.ProcessPath == "" {
				t.Fatal(ci)
			}
		} else if ci.ProcessName != "" || ci.ProcessPath != "" {
			t.Fatal("untrusted attribution leaked", ci)
		}
	}
}

func stage4ProcessContext(parent context.Context, protocol tunstack.Protocol) context.Context {
	src, dst := netip.MustParseAddrPort("192.0.2.1:6000"), netip.MustParseAddrPort("203.0.113.1:443")
	ctx := withInboundMeta(parent, &Inbound{Protocol: "tun"}, net.TCPAddrFromAddrPort(dst), net.TCPAddrFromAddrPort(src))
	return context.WithValue(ctx, tunFlowKey{}, tunstack.Flow{Source: src, Destination: dst, Protocol: protocol})
}

func TestStage4ProcessOriginalTupleAndTCPLifetime(t *testing.T) {
	old, oldTUN := lookupApplication, lookupTUNApplication
	defer func() { lookupApplication, lookupTUNApplication = old, oldTUN }()
	lookupApplication = func(context.Context, procattr.Query) procattr.Identity {
		t.Fatal("TUN reached ordinary proxy lookup")
		return procattr.Identity{}
	}
	calls := 0
	lookupTUNApplication = func(_ context.Context, q procattr.Query) procattr.Identity {
		calls++
		if q.Source != netip.MustParseAddrPort("192.0.2.1:6000") || q.Destination != netip.MustParseAddrPort("203.0.113.1:443") || q.Target != q.Destination || q.ControlSource.IsValid() || q.ControlDestination.IsValid() {
			t.Fatal("original tuple rewritten", q)
		}
		return procattr.Identity{Status: "known", Name: "app.exe", Path: `C:\Apps\app.exe`, PID: uint32(calls), Stamp: uint64(calls)}
	}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := stage4ProcessContext(parent, tunstack.TCP)
	target := Address{"198.51.100.5", 8443} // resolved/rewritten rule target, NOT OS tuple
	first := processIdentity(ctx, "tcp", target)()
	second := processIdentity(ctx, "tcp", target)()
	if calls != 1 || first != second {
		t.Fatal("TCP did not share same live-flow proof", calls, first, second)
	}
	newFlow := processIdentity(stage4ProcessContext(context.Background(), tunstack.TCP), "tcp", target)()
	if calls != 2 || newFlow.PID == first.PID {
		t.Fatal("TCP proof leaked into another flow", calls, newFlow)
	}
	cancel()
	ended := processIdentity(ctx, "tcp", target)()
	if ended.Status != "unknown" || ended.PID != 0 || ended.Name != "" || calls != 2 {
		t.Fatal("ended TCP retained proof", ended, calls)
	}
	// A valid trusted tuple without an inbound cache must not panic or use a
	// previous connection's identity.
	tuple, _ := tunFlowOf(ctx)
	bare := context.WithValue(context.Background(), tunFlowKey{}, tuple)
	processIdentity(bare, "tcp", target)()
	if calls != 3 {
		t.Fatal("bare TUN context reused another flow", calls)
	}
}

func TestStage4ProcessUDPPerDatagramAndQuery(t *testing.T) {
	old := lookupTUNApplication
	defer func() { lookupTUNApplication = old }()
	calls := 0
	ids := []procattr.Identity{
		{Status: "known", Name: "same.exe", Path: `C:\Apps\same.exe`, PID: 9, Stamp: 100},
		{Status: "ambiguous", Cause: "process:ambiguous"},
		{Status: "unknown", Cause: "process:unknown"},
		{Status: "known", Name: "same.exe", Path: `D:\Other\same.exe`, PID: 9, Stamp: 101},
	}
	lookupTUNApplication = func(_ context.Context, q procattr.Query) procattr.Identity {
		if q.Network != "udp" || q.Destination != netip.MustParseAddrPort("203.0.113.1:443") {
			t.Fatal(q)
		}
		id := ids[calls%len(ids)]
		calls++
		return id
	}
	ctx := stage4ProcessContext(context.Background(), tunstack.UDP)
	for i, want := range ids {
		packetCtx := context.WithValue(ctx, packetProcessKey{}, &packetProcess{})
		// Independent rule/display closures share ONLY the packet's once cell.
		one := processIdentity(packetCtx, "udp", Address{"198.51.100.5", 8443})()
		two := processIdentity(packetCtx, "udp", Address{"sniff.example", 443})()
		if one != want || two != want || calls != i+1 {
			t.Fatal("UDP evidence reused or queried twice", one, two, calls)
		}
	}
	processIdentity(ctx, "udp", Address{})()
	processIdentity(ctx, "udp", Address{})()
	if calls != 6 {
		t.Fatal("UDP without a per-datagram cell cached positive", calls)
	}
}

func TestStage4ProcessUnavailableKeepsSkipAndTriState(t *testing.T) {
	old := lookupTUNApplication
	defer func() { lookupTUNApplication = old }()
	for _, tc := range []struct {
		name         string
		ext          RouteRuleExt
		reject, skip bool
		calls        int
	}{
		{"unknown process", RouteRuleExt{ProcessName: "app.exe"}, false, true, 1},
		{"not unknown", RouteRuleExt{Not: &route.Rule{ProcessName: "app.exe"}}, false, true, 1},
		{"or true", RouteRuleExt{Or: []route.Rule{{ProcessName: "app.exe"}, {Network: "tcp"}}}, true, false, 0},
		{"and false", RouteRuleExt{And: []route.Rule{{ProcessName: "app.exe"}, {Network: "udp"}}}, false, false, 0},
		{"and unknown", RouteRuleExt{And: []route.Rule{{ProcessName: "app.exe"}, {Network: "tcp"}}}, false, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			lookupTUNApplication = func(context.Context, procattr.Query) procattr.Identity {
				calls++
				return procattr.Identity{Status: "ambiguous", Cause: "process:ambiguous"}
			}
			var log bytes.Buffer
			s := &Server{cfg: Config{Routing: &RoutingOptions{Rules: []RouteRule{{RouteRuleExt: tc.ext, Action: "reject"}}}}, core: &core{events: &eventLog{write: func(b []byte) error { _, e := log.Write(b); return e }}}}
			d, _, err := s.decide(stage4ProcessContext(context.Background(), tunstack.TCP), "tcp", Address{"203.0.113.1", 443}, netip.MustParseAddr("192.0.2.1"))
			if errors.Is(err, errRouteReject) != tc.reject || !tc.reject && (err != nil || d.Kind != route.Direct) || calls != tc.calls {
				t.Fatal(d, err, calls)
			}
			if strings.Contains(log.String(), "process_rule_skipped") != tc.skip || tc.skip && !strings.Contains(log.String(), "cause=process:ambiguous") {
				t.Fatal(log.String())
			}
		})
	}
}

func (r RouteRule) matchDomain(name string) bool {
	return name != "" && (r.Domain == name || r.DomainSuffix != "" && (name == r.DomainSuffix || strings.HasSuffix(name, "."+r.DomainSuffix)))
}
func (s *Server) routeDirect(name string, ip netip.Addr) bool {
	if s.cfg.Routing == nil {
		return true
	}
	ip = ip.Unmap()
	for _, r := range s.cfg.Routing.Rules {
		if r.matchDomain(name) || r.IPCIDR != "" && r.prefix.Contains(ip) {
			return r.Action == "direct"
		}
	}
	return true
}

func TestRestoredSmartKernelDecodeCreatesNativeRuntime(t *testing.T) {
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Groups = []GroupConfig{{Name: "kept-name", Type: "url-test", Members: []string{"direct"}, Fixed: "direct", Priority: map[string]float64{"direct": 1.5}, Probe: &group.ProbeOptions{URL: "http://127.0.0.1:9/"}}}
	b, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	legacy := strings.Replace(string(b), `"type":"url-test"`, `"type":"smart","smart":{"scope":"site"}`, 1)
	decoded, e := DecodeConfig([]byte(legacy))
	if e != nil {
		t.Fatal(e)
	}
	if decoded.Groups[0].Type != "smart" {
		t.Fatal(decoded.Groups)
	}
	s, e := Start(decoded)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	if snap := s.GroupSnapshots(); len(snap) != 1 || snap[0].Name != "kept-name" || snap[0].Type != "smart" || snap[0].Fixed != "direct" || snap[0].Current != "direct" || snap[0].Members[0].Priority != 1.5 {
		t.Fatal(snap)
	}
	if _, e := DecodeConfig([]byte(strings.Replace(legacy, `"scope":"site"`, `"unknown":true`, 1))); e == nil {
		t.Fatal("unknown legacy field accepted")
	}
}

func TestRound2FlowDetailsAndEnd(t *testing.T) {
	oldLookup := lookupApplication
	defer func() { lookupApplication = oldLookup }()
	lookupApplication = func(context.Context, procattr.Query) procattr.Identity {
		return procattr.Identity{Name: "client.exe", Path: `C:\App\client.exe`, Status: "known"}
	}
	events := []ConnectionEvent{}
	s := startTest(t, Inbound{Protocol: "socks5"}, func(c *Config) { c.SetConnectionSink(func(e ConnectionEvent) { events = append(events, e) }) })
	ctx := withInboundMeta(context.Background(), &Inbound{Protocol: "socks5"}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1080}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345})
	f, _ := s.newFlow(ctx, "tcp", Address{Host: "example.test", Port: 443})
	waitFor(t, func() bool {
		a, _ := s.ClientConnections(500)
		return len(a) == 1 && a[0].InboundKind == "socks" && a[0].SourceAddr == "127.0.0.1:12345"
	})
	f.route(0, []string{"direct"})
	f.dialIPs([]netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("1.2.3.5")}, netip.MustParseAddr("1.2.3.5"))
	f.connectionOutcome(errors.New("Get https://u:pw@bad.test/path?token=SECRET: connection refused"))
	a, _ := s.ClientConnections(500)
	if len(a) != 1 || a[0].FlowID == "" || a[0].FlowID != events[0].FlowID || a[0].DestIP != "1.2.3.5" || len(a[0].DestIPs) != 2 || a[0].SourceAddr != "127.0.0.1:12345" || a[0].InboundKind != "socks" {
		t.Fatalf("%+v", a)
	}
	if strings.Contains(events[0].ErrorText, "SECRET") || strings.Contains(events[0].ErrorText, "u:pw") {
		t.Fatal("error leaked")
	}
	f.addUp(123)
	f.addDown(456)
	f.end("ok")
	last := events[len(events)-1]
	if !last.Ended || last.End == nil || last.Up != 123 || last.Down != 456 || last.Start.IsZero() || last.FlowID != events[0].FlowID || last.Outcome != "error" {
		t.Fatalf("%+v", last)
	}
	_, closed := s.ClientConnections(1)
	if closed[0].FlowID != last.FlowID {
		t.Fatal("closed mismatch")
	}
}
func TestRound2OriginalKernelLog(t *testing.T) {
	var got []KernelLogEvent
	c := &Config{}
	c.SetClientLogSink(func(ClientLogEvent) {})
	c.SetKernelLogSink(func(e KernelLogEvent) { got = append(got, e) })
	l, _ := newClientLogger(&LogOptions{Level: "info"}, c.clientLog)
	l.kernelSink = c.clientKernelLog
	l.emit(levelDebug, []byte("not collected"))
	l.emit(levelWarn, []byte("custom failure https://user:pw@host/path?token=secret token=hidden\n"))
	if len(got) != 1 || got[0].Level != "warn" || strings.Contains(got[0].Message, "hidden") || strings.Contains(got[0].Message, "?token") {
		t.Fatal(got)
	}
	_ = time.Second
}
func TestRound2PrivateDetailsDoNotExpandServerAPI(t *testing.T) {
	s := startTest(t, Inbound{Protocol: "socks5"}, nil)
	f, _ := s.newFlow(context.Background(), "tcp", Address{Host: "example.test", Port: 443})
	f.dialIPs([]netip.Addr{netip.MustParseAddr("1.2.3.4")}, netip.MustParseAddr("1.2.3.4"))
	f.setError(errors.New("private reason"))
	ci := f.info(time.Now())
	if ci.FlowID != "" || ci.DestIP != "" || ci.ErrorText != "" || ci.SourceAddr != "" {
		t.Fatal("expanded ordinary management API")
	}
	f.end("ok")
}
func TestRound2ErrorStagesConservative(t *testing.T) {
	for _, x := range []struct {
		err  error
		want string
	}{{context.Canceled, "canceled"}, {errRouteReject, "rule_reject"}, {&net.DNSError{Err: "no such host", Name: "x.test"}, "dns"}, {&net.OpError{Op: "dial", Err: errors.New("connection refused")}, "connect"}, {errors.New("proxy handshake refused"), "proxy_handshake"}, {errors.New("tls: server rejected connection"), "tls"}, {errors.New("unclassified EOF"), ""}} {
		if got := errorStage(x.err); got != x.want {
			t.Fatal(got, x.want)
		}
	}
}
