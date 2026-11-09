package kernel

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/procattr"
	"github.com/shui1iao/Kat/internal/tunstack"
	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// Two real IP stacks exchange complete L3 packets. There is no proxy listener
// in this link and no SOCKS/katflow registration; external sockets bind local assigned addresses; no remote host is contacted.
type c50Device struct {
	link                *channel.Endpoint
	ctx                 context.Context
	cancel              context.CancelFunc
	closes              atomic.Int64
	failRead, failWrite atomic.Bool
}

func (d *c50Device) ReadPacket(b []byte) (int, error) {
	if d.failRead.Load() {
		return 0, errors.New("injected device read failure")
	}
	p := d.link.ReadContext(d.ctx)
	if p == nil {
		return 0, net.ErrClosed
	}
	defer p.DecRef()
	v := p.ToBuffer()
	defer v.Release()
	wire := v.Flatten()
	if len(wire) > len(b) {
		return 0, io.ErrShortBuffer
	}
	return copy(b, wire), nil
}
func (d *c50Device) WritePacket(b []byte) error {
	if d.failWrite.Load() {
		return errors.New("injected device write failure")
	}
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), b...))})
	defer p.DecRef()
	if header.IPVersion(b) == 6 {
		d.link.InjectInbound(ipv6.ProtocolNumber, p)
	} else {
		d.link.InjectInbound(ipv4.ProtocolNumber, p)
	}
	return nil
}
func (d *c50Device) Close() error { d.closes.Add(1); d.cancel(); return nil }

type c50Peer struct {
	s     *stack.Stack
	dev   *c50Device
	plane *tunstack.Runtime
}

func c50Link(t *testing.T, in tunstack.Ingress, gate func() bool, epoch func() uint64) *c50Peer {
	t.Helper()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6}})
	link := channel.New(1024, tunstack.MTU, "")
	if e := s.CreateNIC(1, link); e != nil {
		t.Fatal(e)
	}
	for _, v := range []struct {
		ip    string
		proto tcpip.NetworkProtocolNumber
		bits  int
	}{{"10.50.0.2", ipv4.ProtocolNumber, 24}, {"fd50::2", ipv6.ProtocolNumber, 64}} {
		a := netip.MustParseAddr(v.ip)
		if e := s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: v.proto, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(a.AsSlice()), PrefixLen: v.bits}}, stack.AddressProperties{}); e != nil {
			t.Fatal(e)
		}
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	ctx, cancel := context.WithCancel(context.Background())
	d := &c50Device{link: link, ctx: ctx, cancel: cancel}
	p, e := tunstack.StartReady(context.Background(), tunstack.Config{Device: d, Ingress: in, Admitting: gate, Epoch: epoch})
	if e != nil {
		s.Destroy()
		t.Fatal(e)
	}
	peer := &c50Peer{s: s, dev: d, plane: p}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.Close(ctx)
		select {
		case <-p.Done():
		case <-ctx.Done():
			t.Error("plane shutdown not joined")
		}
		s.Destroy()
		if d.closes.Load() != 1 {
			t.Errorf("device close count=%d", d.closes.Load())
		}
	})
	return peer
}
func (p *c50Peer) tcp(t *testing.T, target netip.AddrPort) *gonet.TCPConn {
	t.Helper()
	proto := ipv4.ProtocolNumber
	if target.Addr().Is6() {
		proto = ipv6.ProtocolNumber
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, e := gonet.DialContextTCP(ctx, p.s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(target.Addr().AsSlice()), Port: target.Port()}, proto)
	if e != nil {
		t.Fatal(e)
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	return c
}
func (p *c50Peer) udp(t *testing.T, port uint16, target netip.AddrPort) *gonet.UDPConn {
	t.Helper()
	src := netip.MustParseAddr("10.50.0.2")
	proto := ipv4.ProtocolNumber
	if target.Addr().Is6() {
		src = netip.MustParseAddr("fd50::2")
		proto = ipv6.ProtocolNumber
	}
	c, e := gonet.DialUDP(p.s, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(src.AsSlice()), Port: port}, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(target.Addr().AsSlice()), Port: target.Port()}, proto)
	if e != nil {
		t.Fatal(e)
	}
	_ = c.SetDeadline(time.Now().Add(time.Second))
	return c
}
func c50Ingress(t *testing.T, s *Server) *TUNIngress {
	t.Helper()
	in, e := s.NewTUNIngress()
	if e != nil {
		t.Fatal(e)
	}
	return in
}
func c50Server(t *testing.T, r *c49DNSRecords, edit func(*Config)) *Server {
	return startTest(t, Inbound{Protocol: "socks5", Name: "kat-client"}, func(c *Config) {
		c.SetClientIPv6(true)
		if r != nil {
			c.SetConnectionSink(r.event)
			c.SetClientLogSink(r.log)
		}
		if edit != nil {
			edit(c)
		}
	})
}
func TestC50TUNTCPHalfClose(t *testing.T) {
	var records c49DNSRecords
	s := c50Server(t, &records, nil)
	payload := bytes.Repeat([]byte("halfclose-original-tuple"), 1000)
	target := sinkTCP(t, "tcp4", net.JoinHostPort(c50LocalIP(t, false), "0"), func(c net.Conn) {
		b, e := io.ReadAll(c)
		if e == nil && bytes.Equal(b, payload) {
			_, _ = c.Write(append([]byte("after-eof:"), b...))
		}
	})
	p := c50Link(t, c50Ingress(t, s), func() bool { return true }, func() uint64 { return 17 })
	c := p.tcp(t, netip.MustParseAddrPort(target.String()))
	defer c.Close()
	if _, e := c.Write(payload); e != nil {
		t.Fatal(e)
	}
	if e := c.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(c)
	if e != nil || !bytes.Equal(got, append([]byte("after-eof:"), payload...)) {
		t.Fatalf("down after upload EOF: n=%d err=%v", len(got), e)
	}
	waitFor(t, func() bool { _, ok := records.terminal(); return ok })
	end, _ := records.terminal()
	if end.InboundKind != "tun" || !strings.HasPrefix(end.SourceAddr, "10.50.0.2:") || end.Target != target.String() || end.Up != uint64(len(payload)) || end.Down != uint64(len(got)) || end.Outcome != "ok" {
		t.Fatalf("bad tuple/measurement: %+v", end)
	}
	snap := s.reg.Snapshot()
	if snap.Total.Up != end.Up || snap.Total.Down != end.Down || s.reg.Inbound("tun").Load().Up != end.Up {
		t.Fatalf("double/missing metering %+v", snap.Total)
	}
}
func TestC50TUNUDPBothFamiliesAndIdle(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			var records c49DNSRecords
			s := c50Server(t, &records, func(c *Config) { c.Limits.UDPIdle = Duration(180 * time.Millisecond) })
			addr := net.JoinHostPort(c50LocalIP(t, network == "udp6"), "0")
			u, e := net.ListenPacket(network, addr)
			if e != nil {
				t.Fatal(e)
			}
			defer u.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				b := make([]byte, 65535)
				for {
					n, src, e := u.ReadFrom(b)
					if e != nil {
						return
					}
					_, _ = u.WriteTo(append([]byte("reply:"), b[:n]...), src)
				}
			}()
			defer func() { u.Close(); <-done }()
			p := c50Link(t, c50Ingress(t, s), func() bool { return true }, func() uint64 { return 18 })
			c := p.udp(t, 40001, netip.MustParseAddrPort(u.LocalAddr().String()))
			defer c.Close()
			for i := 0; i < 3; i++ {
				_, e = c.Write([]byte("hello"))
				if e != nil {
					t.Fatal(e)
				}
				b := make([]byte, 100)
				n, src, e := c.ReadFrom(b)
				if e != nil || string(b[:n]) != "reply:hello" || src.String() != u.LocalAddr().String() {
					t.Fatalf("real UDP reply: %q from=%v err=%v", b[:n], src, e)
				}
				time.Sleep(70 * time.Millisecond)
			}
			waitFor(t, func() bool { _, ok := records.terminal(); return ok })
			end, _ := records.terminal()
			if end.Target != u.LocalAddr().String() || end.InboundKind != "tun" || end.Up != 15 || end.Down != 33 || end.Outcome != "ok" {
				t.Fatalf("UDP metering %+v", end)
			}
		})
	}
}
func TestC50TUNDNSActivityAndErrorAccounting(t *testing.T) {
	var records c49DNSRecords
	var lookup atomic.Int64
	old := lookupTUNApplication
	lookupTUNApplication = func(context.Context, procattr.Query) procattr.Identity {
		lookup.Add(1)
		return procattr.Identity{Status: "unsupported"}
	}
	defer func() { lookupTUNApplication = old }()
	var fail atomic.Bool
	s := c50Server(t, &records, func(c *Config) {
		c.Limits.UDPIdle = Duration(180 * time.Millisecond)
		c.SetClientEgress(&ClientEgress{SystemQuery: func(_ context.Context, b []byte) ([]byte, error) {
			if fail.Load() {
				return nil, errors.New("real upstream fixture failure")
			}
			return dnsReply(b, []string{"203.0.113.50"}, 0), nil
		}})
	})
	p := c50Link(t, c50Ingress(t, s), func() bool { return true }, func() uint64 { return 19 })
	c := p.udp(t, 40002, netip.MustParseAddrPort("198.18.0.2:53"))
	defer c.Close()
	var up, down uint64
	for i := 0; i < 7; i++ {
		if i == 2 {
			fail.Store(true)
		}
		if i == 3 {
			fail.Store(false)
		}
		q := c49DNSQuery(t, uint16(i+1))
		_, e := c.Write(q)
		if e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 65535)
		n, e := c.Read(b)
		if e != nil {
			t.Fatal(e)
		}
		var m dnsmessage.Message
		if m.Unpack(b[:n]) != nil || i == 2 && m.RCode != dnsmessage.RCodeServerFailure {
			t.Fatalf("DNS real RCODE %+v", m.Header)
		}
		up += uint64(len(q))
		down += uint64(n)
		time.Sleep(60 * time.Millisecond)
	}
	waitFor(t, func() bool {
		records.mu.Lock()
		defer records.mu.Unlock()
		n := 0
		for _, v := range records.events {
			if v.Ended {
				n++
			}
		}
		return n == 7
	})
	records.mu.Lock()
	var sumUp, sumDown uint64
	failures := 0
	for _, end := range records.events {
		if !end.Ended {
			continue
		}
		sumUp += end.Up
		sumDown += end.Down
		if end.Target != "198.18.0.2:53" || end.Rule != "dns" || end.Network != "udp" || end.InboundKind != "tun" || end.DNSQueryType != 1 {
			t.Fatalf("DNS metadata %+v", end)
		}
		if end.Outcome == "error" && end.Code == "dns_query_failed" {
			failures++
		}
	}
	records.mu.Unlock()
	if sumUp != up || sumDown != down || failures != 1 {
		t.Fatalf("query accounting up=%d down=%d failures=%d", sumUp, sumDown, failures)
	}
	if lookup.Load() != 0 {
		t.Fatalf("DNS display process calls=%d", lookup.Load())
	}
	total := s.reg.Snapshot()
	if total.Total.Up != up || total.Total.Down != down || s.reg.Outbound("direct").Load().Up != 0 || s.reg.Inbound("tun").Load().Down != down {
		t.Fatalf("DNS meter duplication %+v", total.Total)
	}
	records.mu.Lock()
	defer records.mu.Unlock()
	for _, l := range records.logs {
		wire, _ := json.Marshal(l)
		if strings.Contains(string(wire), c49DNSName) {
			t.Fatal("question leaked to public log")
		}
	}
}
func TestC50TUNDNSTCPAndFailures(t *testing.T) {
	var records c49DNSRecords
	s := c50Server(t, &records, func(c *Config) {
		c.SetClientEgress(&ClientEgress{SystemQuery: func(_ context.Context, b []byte) ([]byte, error) {
			return dnsReply(b, []string{"203.0.113.51"}, 0), nil
		}})
	})
	p := c50Link(t, c50Ingress(t, s), func() bool { return true }, func() uint64 { return 20 })
	c := p.tcp(t, netip.MustParseAddrPort("198.18.0.2:53"))
	q := c49DNSQuery(t, 100)
	wire := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	wire = append(wire, q...)
	if _, e := c.Write(wire); e != nil {
		t.Fatal(e)
	}
	if e := c.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(c)
	c.Close()
	if e != nil || len(b) < 14 || int(binary.BigEndian.Uint16(b[:2])) != len(b)-2 {
		t.Fatalf("DNS TCP framing/eof len=%d err=%v", len(b), e)
	}
	waitFor(t, func() bool { _, ok := records.terminal(); return ok })
	end, _ := records.terminal()
	if end.Target != "198.18.0.2:53" || end.Network != "tcp" || end.Up != uint64(len(q)) || end.Down != uint64(len(b)-2) || end.Rule != "dns" {
		t.Fatalf("DNS TCP details %+v", end)
	}
	// Direct callback failures are deterministic: malformed query and failed client output.
	ctx := context.WithValue(s.trafficContext(), tunFlowKey{}, tunstack.Flow{Source: netip.MustParseAddrPort("10.50.0.2:40003"), Destination: netip.MustParseAddrPort("198.18.0.2:53"), Protocol: tunstack.UDP})
	for _, tc := range []struct {
		name   string
		q      []byte
		output func([]byte) error
		code   string
	}{{"malformed", []byte{1}, func([]byte) error { return nil }, "dns_query_failed"}, {"write", q, func([]byte) error { return io.ErrClosedPipe }, "dns_response_failed"}} {
		t.Run(tc.name, func(t *testing.T) {
			f, fc := s.newFlow(ctx, "udp", Address{})
			e := s.tunDNSQuery(fc, f, c49DNSTarget, tc.q, false, tc.output)
			if e == nil {
				t.Fatal("failure hidden")
			}
			f.end("ok")
			end, _ := records.terminal()
			if end.Target == "" || end.Code != tc.code || end.Outcome != "error" || end.Down != 0 {
				t.Fatalf("failure metering %+v", end)
			}
		})
	}
}

type c50Callbacks struct {
	flows chan tunstack.Flow
	calls atomic.Int64
}

func (h *c50Callbacks) HandleTCP(ctx context.Context, f tunstack.Flow, c tunstack.TCPConn) error {
	h.calls.Add(1)
	h.flows <- f
	_, e := io.Copy(c, c)
	return e
}
func (h *c50Callbacks) HandleUDP(ctx context.Context, f tunstack.Flow, c net.Conn) error {
	h.calls.Add(1)
	h.flows <- f
	b := make([]byte, 65535)
	n, e := c.Read(b)
	if e == nil {
		_, e = c.Write(b[:n])
	}
	return e
}
func TestC50TUNAdmissionResumeEpochAndHealth(t *testing.T) {
	var gate atomic.Bool
	gate.Store(true)
	var epoch atomic.Uint64
	epoch.Store(21)
	h := &c50Callbacks{flows: make(chan tunstack.Flow, 64)}
	p := c50Link(t, h, gate.Load, epoch.Load)
	target := netip.MustParseAddrPort("203.0.113.50:4444")
	send := func(port uint16, want bool) {
		c := p.udp(t, port, target)
		defer c.Close()
		_, e := c.Write([]byte("epoch"))
		if e != nil {
			t.Fatal(e)
		}
		if want {
			select {
			case f := <-h.flows:
				if f.Epoch != epoch.Load() || f.Protocol != tunstack.UDP || f.Source.Port() != port || f.Destination != target {
					t.Fatalf("untrusted epoch/tuple %+v", f)
				}
			case <-time.After(time.Second):
				t.Fatal("no callback")
			}
			b := make([]byte, 100)
			if _, e = c.Read(b); e != nil {
				t.Fatal(e)
			}
		} else {
			select {
			case f := <-h.flows:
				t.Fatalf("callback after fence %+v", f)
			case <-time.After(60 * time.Millisecond):
			}
		}
	}
	send(41000, true)
	gate.Store(false)
	p.plane.Quiesce()
	before := h.calls.Load()
	epoch.Store(22)
	send(41001, false)
	if h.calls.Load() != before {
		t.Fatal("admission crossed Quiesce")
	}
	if e := p.plane.Resume(); e != nil {
		t.Fatal(e)
	}
	send(41004, false) // local resume must not bypass still-closed OS gate
	gate.Store(true)
	if e := p.plane.Resume(); e != nil {
		t.Fatal(e)
	}
	send(41002, true)
	p.dev.failWrite.Store(true)
	c := p.udp(t, 41003, target)
	defer c.Close()
	_, _ = c.Write([]byte("fatal"))
	select {
	case <-p.plane.Failed():
	case <-time.After(time.Second):
		t.Fatal("device write failure hidden")
	}
	var f *tunstack.Failure
	if !errors.As(p.plane.Err(), &f) || f.Code != "TUN_DEVICE_WRITE_FAILED" {
		t.Fatalf("wrong fatal %v", p.plane.Err())
	}
	if e := p.plane.Resume(); e == nil {
		t.Fatal("fatal runtime resumed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := p.plane.Close(ctx); e != nil {
		t.Fatalf("cleanup failed: %v", e)
	}
	if p.plane.Err() == nil {
		t.Fatal("cleanup erased fatal health")
	}
	select {
	case <-p.plane.Done():
	default:
		t.Fatal("close did not join")
	}
	if p.dev.closes.Load() != 1 {
		t.Fatal("multiple device Close owners")
	}
}
func TestC50TUNReadFailureAndStartupOwnership(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d := &c50Device{ctx: ctx, cancel: cancel}
	startup, cancelStartup := context.WithCancel(context.Background())
	cancelStartup()
	_, e := tunstack.StartReady(startup, tunstack.Config{Device: d, Ingress: &c50Callbacks{}, Admitting: func() bool { return true }, Epoch: func() uint64 { return 1 }})
	if !errors.Is(e, context.Canceled) || d.closes.Load() != 1 {
		t.Fatalf("startup ownership close=%d err=%v", d.closes.Load(), e)
	}
	h := &c50Callbacks{flows: make(chan tunstack.Flow, 8)}
	p := c50Link(t, h, func() bool { return true }, func() uint64 { return 1 })
	p.dev.failRead.Store(true)
	c := p.udp(t, 41010, netip.MustParseAddrPort("203.0.113.50:4444"))
	defer c.Close()
	_, _ = c.Write([]byte("trigger blocked reader"))
	select {
	case <-p.plane.Failed():
	case <-time.After(time.Second):
		t.Fatal("device read failure hidden")
	}
	var f *tunstack.Failure
	if !errors.As(p.plane.Err(), &f) || f.Code != "TUN_DEVICE_READ_FAILED" {
		t.Fatal(p.plane.Err())
	}
}

type c50FailUDP struct{ outbound.Outbound }

func (c50FailUDP) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return nil, errors.New("UDP setup fixture failure")
}
func TestC50TUNUDPErrorQueueAndCancel(t *testing.T) {
	var r c49DNSRecords
	s := c50Server(t, &r, func(c *Config) { c.Limits.UDPIdle = Duration(120 * time.Millisecond) })
	s.rt.nodes["direct"] = c50FailUDP{s.rt.nodes["direct"]}
	p := c50Link(t, c50Ingress(t, s), func() bool { return true }, func() uint64 { return 23 })
	c := p.udp(t, 41020, netip.MustParseAddrPort("203.0.113.50:4444"))
	defer c.Close()
	_, _ = c.Write([]byte("fail"))
	waitFor(t, r.failed)
	waitFor(t, func() bool { _, ok := r.terminal(); return ok })
	end, _ := r.terminal()
	if end.Target != "203.0.113.50:4444" || end.Outcome != "error" || end.Code != "udp_setup_failed" || end.Up != 0 || end.Down != 0 {
		t.Fatalf("UDP error false success %+v", end)
	}
	ctx, cancel := context.WithCancel(s.ctx)
	a := &udpAssociation{server: s, ctx: ctx, queue: make(chan packet, 1)}
	a.enqueue(packet{payload: []byte{1, 2, 3}})
	a.enqueue(packet{payload: []byte{4}})
	if len(a.queue) != 1 || a.queuedBytes.Load() != 3 {
		t.Fatal("queue not bounded")
	}
	cancel()
	a.enqueue(packet{payload: []byte{5}})
	if len(a.queue) != 1 || a.queuedBytes.Load() != 3 {
		t.Fatal("cancel enqueue")
	}
	stop, done := context.WithTimeout(context.Background(), time.Second)
	defer done()
	if e := p.plane.Close(stop); e != nil {
		t.Fatal(e)
	}
	if s.Stats().Active != 0 || s.Stats().UDP != 0 {
		t.Fatal("cancel failed to release budget")
	}
}
func TestC50TUNProcessOriginalTuple(t *testing.T) {
	old, oldTUN := lookupApplication, lookupTUNApplication
	defer func() { lookupApplication = old; lookupTUNApplication = oldTUN }()
	lookupApplication = func(context.Context, procattr.Query) procattr.Identity {
		t.Error("TUN reached legacy proxy attribution")
		return procattr.Identity{}
	}
	var calls int
	src := netip.MustParseAddrPort("10.50.0.2:45000")
	dst := netip.MustParseAddrPort("203.0.113.50:443")
	lookupTUNApplication = func(_ context.Context, q procattr.Query) procattr.Identity {
		calls++
		if q.Source != src || q.Destination != dst || q.ControlSource.IsValid() || q.ControlDestination.IsValid() {
			t.Errorf("wrong tuple %+v", q)
		}
		return procattr.Identity{Status: "unsupported", Cause: "process:unsupported"}
	}
	ctx := withInboundMeta(context.Background(), &Inbound{Protocol: "tun"}, net.TCPAddrFromAddrPort(dst), net.TCPAddrFromAddrPort(src))
	ctx = context.WithValue(ctx, tunFlowKey{}, tunstack.Flow{Source: src, Destination: dst, Protocol: tunstack.TCP})
	lookup := processIdentity(ctx, "tcp", Address{dst.Addr().String(), dst.Port()})
	lookup()
	lookup()
	if calls != 1 {
		t.Fatal("TCP lifetime cache lost")
	}
	lookup = processIdentity(ctx, "udp", Address{dst.Addr().String(), dst.Port()})
	lookup()
	lookup()
	if calls != 3 {
		t.Fatal("UDP identity incorrectly cached")
	}
}

// Using an assigned local address avoids netstack martian-loopback policy.
// Sockets terminate on this same Hytron host; this is not an external test.
func c50LocalIP(t *testing.T, v6 bool) string {
	t.Helper()
	addrs, e := net.InterfaceAddrs()
	if e != nil {
		t.Fatal(e)
	}
	for _, a := range addrs {
		p, e := netip.ParsePrefix(a.String())
		if e != nil {
			continue
		}
		ip := p.Addr()
		if ip.Is6() == v6 && ip.IsGlobalUnicast() && !ip.IsLoopback() {
			return ip.String()
		}
	}
	t.Fatalf("no assigned local IPv6=%v address for bounded socket fixture", v6)
	return ""
}

type c50HeldIngress struct {
	entered chan struct{}
	release chan struct{}
}

func (h *c50HeldIngress) HandleTCP(context.Context, tunstack.Flow, tunstack.TCPConn) error {
	return nil
}
func (h *c50HeldIngress) HandleUDP(context.Context, tunstack.Flow, net.Conn) error {
	close(h.entered)
	<-h.release
	return nil
}
func TestC50TUNCloseDeadlineNotFalseComplete(t *testing.T) {
	h := &c50HeldIngress{entered: make(chan struct{}), release: make(chan struct{})}
	p := c50Link(t, h, func() bool { return true }, func() uint64 { return 24 })
	c := p.udp(t, 41030, netip.MustParseAddrPort("203.0.113.50:4444"))
	defer c.Close()
	_, _ = c.Write([]byte("hold"))
	select {
	case <-h.entered:
	case <-time.After(time.Second):
		t.Fatal("callback not entered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	e := p.plane.Close(ctx)
	if !errors.Is(e, context.DeadlineExceeded) || time.Since(start) > 250*time.Millisecond {
		t.Fatalf("unbounded/fake close %v", e)
	}
	select {
	case <-p.plane.Done():
		t.Fatal("cleanup complete while callback alive")
	default:
	}
	close(h.release)
	end, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if e = p.plane.Close(end); e != nil {
		t.Fatal(e)
	}
	if p.dev.closes.Load() != 1 {
		t.Fatal("deadline path repeated device Close")
	}
}

func TestC50TUNUnknownProcessRuleSkips(t *testing.T) {
	old := lookupTUNApplication
	defer func() { lookupTUNApplication = old }()
	lookupTUNApplication = func(context.Context, procattr.Query) procattr.Identity {
		return procattr.Identity{Status: "unknown", Cause: "process:unknown"}
	}
	s := c50Server(t, nil, func(c *Config) {
		c.Routing = &RoutingOptions{Rules: []RouteRule{{RouteRuleExt: RouteRuleExt{ProcessName: "unavailable.exe"}, Action: "reject"}}, Final: "direct"}
	})
	src := netip.MustParseAddrPort("10.50.0.2:45001")
	dst := netip.MustParseAddrPort("203.0.113.50:443")
	ctx := withInboundMeta(s.ctx, &Inbound{Protocol: "tun"}, net.TCPAddrFromAddrPort(dst), net.TCPAddrFromAddrPort(src))
	ctx = context.WithValue(ctx, tunFlowKey{}, tunstack.Flow{Source: src, Destination: dst, Protocol: tunstack.TCP})
	d, _, e := s.decide(ctx, "tcp", Address{dst.Addr().String(), dst.Port()}, src.Addr())
	if e != nil || decisionHead(d) != "direct" {
		t.Fatalf("unknown attribution hard-rejected: %+v err=%v", d, e)
	}
}

func TestC50TUNDNSPartialTCPFrameFails(t *testing.T) {
	var r c49DNSRecords
	s := c50Server(t, &r, nil)
	p := c50Link(t, c50Ingress(t, s), func() bool { return true }, func() uint64 { return 25 })
	c := p.tcp(t, netip.MustParseAddrPort("198.18.0.2:53"))
	_, _ = c.Write([]byte{0})
	_ = c.CloseWrite()
	_, _ = io.ReadAll(c)
	_ = c.Close()
	waitFor(t, func() bool { _, ok := r.terminal(); return ok })
	end, _ := r.terminal()
	if end.Outcome != "error" || end.Code != "dns_query_failed" || end.Target != "198.18.0.2:53" || end.Down != 0 {
		t.Fatalf("partial DNS TCP frame false success %+v", end)
	}
}
