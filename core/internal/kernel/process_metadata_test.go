package kernel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/procattr"
	"github.com/shui1iao/Kat/internal/route"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestProcessMetadataTCPAndUDPCurrentIdentity(t *testing.T) {
	old := lookupApplication
	defer func() { lookupApplication = old }()
	calls := 0
	pid := uint32(1)
	lookupApplication = func(_ context.Context, q procattr.Query) procattr.Identity {
		calls++
		if q.ControlSource != netip.MustParseAddrPort("127.0.0.1:20000") || q.ControlDestination.Port() != 7891 {
			t.Fatal(q)
		}
		if q.Network == "udp" && q.Source.Port() != 30000 {
			t.Fatal(q)
		}
		return procattr.Identity{Name: map[uint32]string{1: "a.exe", 2: "b.exe"}[pid], Status: "known", PID: pid, Stamp: uint64(pid)}
	}
	ctx := withInboundMeta(context.Background(), &Inbound{Name: "test", Protocol: "socks5"}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7891}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20000})
	tcp := processMetadata(ctx, "tcp", Address{"1.1.1.1", 443})
	name, _ := tcp()
	if name != "a.exe" {
		t.Fatal(name)
	}
	pid = 2
	name, _ = tcp()
	if name != "a.exe" || calls != 1 {
		t.Fatal("existing TCP flow identity changed", name, calls)
	}
	ctx = context.WithValue(ctx, udpProcessKey{}, udpProcessTuple{source: netip.MustParseAddrPort("127.0.0.1:30000"), destination: netip.MustParseAddrPort("127.0.0.1:30001")})
	udp := processMetadata(ctx, "udp", Address{"1.1.1.1", 443})
	name, _ = udp()
	if name != "b.exe" {
		t.Fatal(name)
	}
	pid = 1
	name, _ = udp()
	if name != "a.exe" || calls != 3 {
		t.Fatal("UDP owner cached across reuse", name, calls)
	}
}
func TestProcessMetadataOrderedDecisionAndDiagnostic(t *testing.T) {
	old := lookupApplication
	defer func() { lookupApplication = old }()
	calls := 0
	lookupApplication = func(context.Context, procattr.Query) procattr.Identity {
		calls++
		return procattr.Identity{Status: "ambiguous"}
	}
	var log bytes.Buffer
	s := &Server{cfg: Config{Routing: &RoutingOptions{Rules: []RouteRule{{Domain: "known.example", Action: "reject"}, {RouteRuleExt: RouteRuleExt{ProcessName: "app.exe"}, Action: "reject"}}}}, core: &core{events: &eventLog{write: func(b []byte) error { _, e := log.Write(b); return e }}}}
	ctx := withInboundMeta(context.Background(), &Inbound{Protocol: "socks5"}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7891}, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20000})
	_, _, err := s.decide(ctx, "tcp", Address{"known.example", 443}, netip.MustParseAddr("127.0.0.1"))
	if !errors.Is(err, errRouteReject) || calls != 0 {
		t.Fatal(err, calls)
	}
	d, _, err := s.decide(ctx, "tcp", Address{"1.1.1.1", 443}, netip.MustParseAddr("127.0.0.1"))
	var attr *route.ProcessUnavailableError
	if !errors.As(err, &attr) || d.Kind != route.Reject || calls != 1 {
		t.Fatal(d, err, calls)
	}
	if !strings.Contains(log.String(), "process_attribution_failed reason=ambiguous rule=2") {
		t.Fatal(log.String())
	}
}

func TestProcessKernelJSONSchemaToRoute(t *testing.T) {
	for _, text := range []string{`{"routing":{"rules":[{"process_name":"App.EXE","action":"reject"}]}}`, `{"routing":{"rules":[{"and":[{"process_name":"app.exe"},{"network":"tcp"}],"action":"reject"}]}}`} {
		var c Config
		if err := json.Unmarshal([]byte(text), &c); err != nil {
			t.Fatal(err)
		}
		o := c.routeOptions()
		if err := o.Validate(); err != nil {
			t.Fatal(err)
		}
		e, err := route.NewEngine(o, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		d, err := e.Decide(context.Background(), route.Metadata{IP: netip.MustParseAddr("1.1.1.1"), Network: "tcp", ProcessName: "APP.exe", ProcessStatus: "known"}, nil)
		if err != nil || d.Kind != route.Reject || d.Rule != 1 {
			t.Fatal(d, err)
		}
	}
}
