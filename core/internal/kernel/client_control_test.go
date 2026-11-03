package kernel

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestClientControlRealProbe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer target.Close()
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Security = &SecurityOptions{AllowLoopback: true}
	c.Groups = []GroupConfig{{Name: "auto", Type: "url-test", Members: []string{"direct"}, Probe: &group.ProbeOptions{URL: target.URL}}}
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	r, e := s.ProbeNode(context.Background(), "direct", target.URL)
	if e != nil || r.ProbeMS == nil || r.Error != "" {
		t.Fatal("real node HTTP probe failed")
	}
	rs, e := s.ProbeGroup(context.Background(), "auto", target.URL)
	if e != nil || len(rs) != 1 || rs[0].ProbeMS == nil {
		t.Fatal("real group HTTP probe failed")
	}
	snap := s.GroupSnapshots()
	if len(snap) != 1 || !snap[0].Members[0].Probed || !snap[0].Members[0].ProbeOK {
		t.Fatal("manual result not in core state")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, e = s.ProbeNode(ctx, "direct", target.URL)
	if e != nil || r.ProbeMS != nil || r.Error == "" {
		t.Fatal("canceled probe")
	}
	if _, e = s.ProbeNode(context.Background(), "auto", target.URL); e == nil {
		t.Fatal("node probe accepted a group")
	}
}

func TestClientEgressCoversDirectAndLaterGeneration(t *testing.T) {
	var calls atomic.Int64
	hooks := &ClientEgress{Control: func(_ context.Context, _ string, address string, _ syscall.RawConn) error {
		host, _, e := net.SplitHostPort(address)
		if e != nil {
			return e
		}
		ip, e := netip.ParseAddr(host)
		if e != nil || !ip.Unmap().IsLoopback() {
			return errors.New("test forbids non-loopback socket")
		}
		calls.Add(1)
		return nil
	}, PacketControl: func(string, *net.UDPConn) error { return errors.New("no remote packets") }, Bootstrap: func(_ context.Context, _ string, _ string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}}
	c := socksCfg("127.0.0.1:0")
	c.Security = &SecurityOptions{AllowLoopback: true}
	c.DNS = &DNSOptions{Server: "system"}
	c.SetClientEgress(hooks)
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	target := echoTCP(t)
	conn, ok := socksTo(t, s.Addresses()[0].String(), target)
	if !ok || !echoOnce(conn, "controlled") {
		t.Fatal("controlled direct TCP")
	}
	conn.Close()
	if calls.Load() == 0 {
		t.Fatal("legacy TCP bypassed hook")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ips, e := s.lookup(ctx, "bootstrap.invalid")
	if e != nil || len(ips) != 1 || !ips[0].IsLoopback() {
		t.Fatal("uncontrolled system bootstrap")
	}
	// Provider-triggered reload carries the non-JSON client hook.
	if _, e = s.reload("provider", false); e != nil {
		t.Fatal(e)
	}
	if s.current().cfg.clientEgress != hooks {
		t.Fatal("later generation lost egress")
	}
	control, u, relay := socksAssociate(t, s, 0)
	defer control.Close()
	defer u.Close()
	udpTarget, _ := echoUDP(t)
	socksUDPSend(t, u, relay, udpTarget, []byte("controlled-udp"), 0)
	if string(socksUDPRead(t, u)) != "controlled-udp" {
		t.Fatal("controlled UDP path")
	}
	next := s.current().cfg
	next.SetClientEgress(nil)
	if _, e = s.ApplyConfig(next); e != nil {
		t.Fatal(e)
	}
	if s.current().cfg.clientEgress != nil {
		t.Fatal("disable failed")
	}
}
