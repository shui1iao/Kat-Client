package kernel

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/shui1iao/Kat/internal/procattr"
	"github.com/shui1iao/Kat/internal/route"
	"github.com/shui1iao/Kat/internal/tunstack"
)

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
