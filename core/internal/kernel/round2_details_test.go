package kernel

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/procattr"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

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
