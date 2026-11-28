package kernel

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/procattr"
	"github.com/shui1iao/Kat/internal/tunplatform"
	"github.com/shui1iao/Kat/internal/tunstack"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A deterministic external association: exactly one reader may wait on it.
// It performs no networking and is used only for identity/fault/join tests.
type m2Packet struct {
	closed                      chan struct{}
	written                     chan struct{}
	once, writeOnce             sync.Once
	failRead                    bool
	closes, readers, maxReaders atomic.Int64
}

func m2PC(fail bool) *m2Packet {
	return &m2Packet{closed: make(chan struct{}), written: make(chan struct{}), failRead: fail}
}
func (p *m2Packet) ReadFrom([]byte) (int, outbound.Addr, error) {
	n := p.readers.Add(1)
	defer p.readers.Add(-1)
	for old := p.maxReaders.Load(); n > old; old = p.maxReaders.Load() {
		if p.maxReaders.CompareAndSwap(old, n) {
			break
		}
	}
	if p.failRead {
		select {
		case <-p.written:
			return 0, outbound.Addr{}, errors.New("injected real receive failure")
		case <-p.closed:
		}
	} else {
		<-p.closed
	}
	return 0, outbound.Addr{}, net.ErrClosed
}
func (p *m2Packet) WriteTo(b []byte, _ outbound.Addr) (int, error) {
	p.writeOnce.Do(func() { close(p.written) })
	return len(b), nil
}
func (p *m2Packet) SetReadDeadline(time.Time) error  { return nil }
func (p *m2Packet) SetWriteDeadline(time.Time) error { return nil }
func (p *m2Packet) Close() error                     { p.once.Do(func() { p.closes.Add(1); close(p.closed) }); return nil }

type m2Outbound struct {
	outbound.Outbound
	pcs         *[]*m2Packet
	fail        bool
	unsupported bool
}

func (o m2Outbound) UDP() bool { return !o.unsupported }
func (o m2Outbound) ListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	if !outbound.EndpointIndependent(ctx) {
		return nil, errors.New("missing EIM request")
	}
	p := m2PC(o.fail)
	*o.pcs = append(*o.pcs, p)
	return p, nil
}
func m2State(t *testing.T, s *Server) *tunUDPState {
	t.Helper()
	ctx, cancel := context.WithCancel(s.trafficContext())
	a, b := net.Pipe()
	u := &tunUDPState{a: &udpAssociation{server: s, ctx: ctx, cancel: cancel, source: netip.MustParseAddr("10.50.0.2")}, c: a, t: tunstack.Flow{Source: netip.MustParseAddrPort("10.50.0.2:41444"), Destination: netip.MustParseAddrPort("203.0.113.60:4444"), Protocol: tunstack.UDP, Epoch: 44}, sessions: map[tunNATKey]*tunNATSession{}}
	maxActivity(u.a)
	t.Cleanup(func() { cancel(); u.closePC(); u.pcWG.Wait(); a.Close(); b.Close() })
	return u
}
func TestM2IdentityLossRetiresKnownMappingAndJoins(t *testing.T) {
	old := lookupTUNApplication
	defer func() { lookupTUNApplication = old }()
	id := procattr.Identity{Status: "known", PID: 11, Stamp: 22}
	lookupTUNApplication = func(context.Context, procattr.Query) procattr.Identity { return id }
	var r c49DNSRecords
	s := c50Server(t, &r, nil)
	var pcs []*m2Packet
	s.rt.nodes["direct"] = m2Outbound{Outbound: s.rt.nodes["direct"], pcs: &pcs}
	u := m2State(t, s)
	send := func() { u.send(u.a.ctx, packet{Address{"203.0.113.60", 4444}, []byte("x")}, time.Second) }
	send()
	id = procattr.Identity{Status: "unknown"}
	send()
	id = procattr.Identity{Status: "ambiguous"}
	send()
	id = procattr.Identity{Status: "known", PID: 33, Stamp: 44}
	send()
	send()
	if len(pcs) != 4 {
		t.Fatalf("identity boundaries reused mappings: %d", len(pcs))
	}
	for _, p := range pcs[:3] {
		if p.closes.Load() != 1 || p.readers.Load() != 0 {
			t.Fatal("old identity not closed/joined")
		}
	}
	u.closePC()
	u.pcWG.Wait()
	for _, p := range pcs {
		if p.closes.Load() != 1 || p.readers.Load() != 0 || p.maxReaders.Load() > 1 {
			t.Fatal("non-exclusive reader/close owner")
		}
	}
	s.udpSlots.mu.Lock()
	used := s.udpSlots.used
	s.udpSlots.mu.Unlock()
	if used != 0 {
		t.Fatalf("session budget leaked: %d", used)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.events {
		if e.Ended && (e.ProcessStatus == "unknown" || e.ProcessStatus == "ambiguous") && (e.ProcessPID != 0 || e.ProcessCreation != 0 || e.ProcessName != "" || e.ProcessPath != "") {
			t.Fatal("positive evidence retained", e)
		}
	}
}
func TestM2ReceiveFailureAndUnsupportedAreNotOK(t *testing.T) {
	for _, unsupported := range []bool{false, true} {
		t.Run(strconv.FormatBool(unsupported), func(t *testing.T) {
			var r c49DNSRecords
			s := c50Server(t, &r, nil)
			var pcs []*m2Packet
			s.rt.nodes["direct"] = m2Outbound{Outbound: s.rt.nodes["direct"], pcs: &pcs, fail: true, unsupported: unsupported}
			u := m2State(t, s)
			u.send(u.a.ctx, packet{Address{"203.0.113.60", 4444}, []byte("x")}, time.Second)
			waitFor(t, func() bool { _, ok := r.terminal(); return ok })
			end, _ := r.terminal()
			code := "udp_receive_failed"
			if unsupported {
				code = "udp_unsupported"
			}
			if end.Outcome != "error" || end.Code != code || end.Target == "" || end.Target == ":0" || end.Rule == "" || len(end.Chain) == 0 {
				t.Fatalf("failure hidden or missing rule/chain %+v", end)
			}
			if !unsupported && end.Up != 1 {
				t.Fatalf("terminal raced send accounting %+v", end)
			}
		})
	}
}
func TestM2PolicyIdleAndCloseJoin(t *testing.T) {
	a, b := stage4Socket(t, "udp4", c50LocalIP(t, false)), stage4Socket(t, "udp4", c50LocalIP(t, false))
	s := c50Server(t, nil, func(c *Config) {
		c.Security = &SecurityOptions{AllowLoopback: true}
		c.Limits.UDPIdle = Duration(120 * time.Millisecond)
		c.Routing = &RoutingOptions{Rules: []RouteRule{{DstPort: strconv.Itoa(b.LocalAddr().(*net.UDPAddr).Port), Action: "direct"}}, Final: "direct"}
	})
	p := c50Link(t, c50Ingress(t, s), func() bool { return true }, func() uint64 { return 44 })
	inner := stage4UDP(t, p, false)
	send := func(sock *net.UDPConn) netip.AddrPort {
		t.Helper()
		if _, e := inner.WriteTo([]byte("x"), sock.LocalAddr()); e != nil {
			t.Fatal(e)
		}
		_ = sock.SetReadDeadline(time.Now().Add(time.Second))
		_, ap, e := sock.ReadFromUDPAddrPort(make([]byte, 8))
		if e != nil {
			t.Fatal(e)
		}
		return ap
	}
	ap, bp := send(a), send(b)
	for i := 0; i < 5; i++ {
		time.Sleep(45 * time.Millisecond)
		if send(a) != ap {
			t.Fatal("active mapping expired")
		}
	}
	if send(b) == bp {
		t.Fatal("idle policy mapping retained by another policy's activity")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := p.plane.Close(ctx); e != nil {
		t.Fatal(e)
	}
	s.udpSlots.mu.Lock()
	used := s.udpSlots.used
	s.udpSlots.mu.Unlock()
	if used != 0 {
		t.Fatalf("source/multi-policy association not joined: %d", used)
	}
}
func TestM2DNSTCPEachQueryOwnsRecordAndRCode(t *testing.T) {
	var r c49DNSRecords
	s := c50Server(t, &r, func(c *Config) {
		c.SetClientEgress(&ClientEgress{SystemQuery: func(_ context.Context, b []byte) ([]byte, error) {
			var m dnsmessage.Message
			_ = m.Unpack(b)
			if m.Questions[0].Type == dnsmessage.TypeAAAA {
				return nil, errors.New("upstream failure")
			}
			return dnsReply(b, []string{"203.0.113.52"}, 0), nil
		}})
	})
	p := c50Link(t, c50Ingress(t, s), func() bool { return true }, func() uint64 { return 44 })
	c := p.tcp(t, netip.MustParseAddrPort("198.18.0.2:53"))
	defer c.Close()
	var totalUp, totalDown uint64
	for i := 0; i < 2; i++ {
		q := c49DNSQuery(t, uint16(200+i))
		if i == 0 {
			var m dnsmessage.Message
			_ = m.Unpack(q)
			m.Questions[0].Type = dnsmessage.TypeAAAA
			q, _ = m.Pack()
		}
		wire := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
		wire = append(wire, q...)
		if _, e := c.Write(wire); e != nil {
			t.Fatal(e)
		}
		var size [2]byte
		if _, e := io.ReadFull(c, size[:]); e != nil {
			t.Fatal(e)
		}
		reply := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if _, e := io.ReadFull(c, reply); e != nil {
			t.Fatal(e)
		}
		totalUp += uint64(len(q))
		totalDown += uint64(len(reply))
	}
	waitFor(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		n := 0
		for _, e := range r.events {
			if e.Ended {
				n++
			}
		}
		return n == 2
	})
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := map[string]bool{}
	var up, down uint64
	for _, e := range r.events {
		if !e.Ended {
			continue
		}
		ids[e.FlowID] = true
		up += e.Up
		down += e.Down
		if e.Target != "198.18.0.2:53" || e.DNSRCode == nil {
			t.Fatalf("missing DNS query metadata %+v", e)
		}
		if e.DNSQueryType == 1 && (*e.DNSRCode != 0 || e.Outcome != "ok") {
			t.Fatal("success misrecorded", e)
		}
		if e.DNSQueryType == 28 && (*e.DNSRCode != 2 || e.Outcome != "error" || e.Code != "dns_query_failed" || e.ErrorText == "") {
			t.Fatal("failure misrecorded", e)
		}
	}
	if len(ids) != 2 || up != totalUp || down != totalDown {
		t.Fatal("not per query/single meter", len(ids), up, down)
	}
	total := s.reg.Snapshot().Total
	if total.Up != up || total.Down != down {
		t.Fatal("duplicated payload", total)
	}
}

func TestM2IdentityRevokesAllPoliciesBeforeFailedRoute(t *testing.T) {
	old := lookupTUNApplication
	defer func() { lookupTUNApplication = old }()
	id := procattr.Identity{Status: "known", PID: 11, Stamp: 22, Name: "old.exe", Path: "C:\\old.exe"}
	lookupTUNApplication = func(context.Context, procattr.Query) procattr.Identity { return id }
	var r c49DNSRecords
	s := c50Server(t, &r, func(c *Config) {
		c.Routing = &RoutingOptions{Rules: []RouteRule{{DstPort: "4446", Action: "reject"}}, Final: "direct"}
	})
	var pcs []*m2Packet
	s.rt.nodes["direct"] = m2Outbound{Outbound: s.rt.nodes["direct"], pcs: &pcs}
	u := m2State(t, s)
	ctx := u.packetContext(u.a.ctx, packet{target: Address{"203.0.113.60", 4444}})
	u.identity(id)
	var flows []*flow
	for _, rule := range []int{-1, 0} {
		v, e := u.session(ctx, tunNATKey{"direct", rule, 44, "standalone"}, Address{"203.0.113.60", 4444})
		if e != nil {
			t.Fatal(e)
		}
		v.f.tunProcess(ctx, Address{"203.0.113.60", 4444})
		flows = append(flows, v.f)
	}
	id = procattr.Identity{Status: "ambiguous"}
	u.send(u.a.ctx, packet{Address{"203.0.113.60", 4446}, []byte("rejected")}, time.Second)
	if len(pcs) != 2 {
		t.Fatal("rejected route created session")
	}
	for _, f := range flows {
		d := f.info(time.Now()).FlowDetails
		if d.ProcessStatus != "ambiguous" || d.ProcessPID != 0 || d.ProcessCreation != 0 || d.ProcessName != "" || d.ProcessPath != "" {
			t.Fatalf("other policy retained positive %+v", d)
		}
	}
	for _, p := range pcs {
		if p.closes.Load() != 1 || p.readers.Load() != 0 {
			t.Fatal("early failed route retained old reader")
		}
	}
}
func TestM2ProxyPhysicalDomainIndependentOfInnerFamily(t *testing.T) {
	s := c50Server(t, nil, func(c *Config) {
		c.SetClientEgress(&ClientEgress{UDPBinding: func(v6 bool) (uint64, string, error) {
			if v6 {
				return 0, "", errors.New("no physical IPv6")
			}
			return 44, "v4-owner", nil
		}, UDPAssociationBinding: func() (uint64, string, error) { return 44, "v4-owner", nil }})
	})
	u := m2State(t, s)
	u.t.Source = netip.MustParseAddrPort("[fd50::2]:41444")
	if _, _, e := u.binding("direct"); e == nil {
		t.Fatal("direct IPv6 bypassed physical family admission")
	}
	if epoch, owner, e := u.binding("proxy"); e != nil || epoch != 44 || owner != "v4-owner" {
		t.Fatal("inner IPv6 incorrectly required a physical IPv6 proxy transport", epoch, owner, e)
	}
}
func TestM2SlowDNSQueryDoesNotIdleSource(t *testing.T) {
	var r c49DNSRecords
	s := c50Server(t, &r, func(c *Config) {
		c.Limits.UDPIdle = Duration(40 * time.Millisecond)
		c.SetClientEgress(&ClientEgress{SystemQuery: func(ctx context.Context, b []byte) ([]byte, error) {
			select {
			case <-time.After(140 * time.Millisecond):
				return dnsReply(b, []string{"203.0.113.52"}, 0), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}})
	})
	p := c50Link(t, c50Ingress(t, s), func() bool { return true }, func() uint64 { return 44 })
	inner := p.udp(t, 41445, netip.MustParseAddrPort("198.18.0.2:53"))
	defer inner.Close()
	for qid := uint16(350); qid <= 351; qid++ {
		if _, e := inner.Write(c49DNSQuery(t, qid)); e != nil {
			t.Fatal(e)
		}
		if _, e := inner.Read(make([]byte, 4096)); e != nil {
			t.Fatal("live query expired at association idle", qid, e)
		}
	}
	waitFor(t, func() bool { _, ok := r.terminal(); return ok })
	end, _ := r.terminal()
	if end.Outcome != "ok" || end.DNSRCode == nil || *end.DNSRCode != 0 {
		t.Fatal("active DNS result", end)
	}
}

type ringFullOnceDevice struct {
	*c50Device
	failNext atomic.Bool
}

func (d *ringFullOnceDevice) WritePacket(b []byte) error {
	if d.failNext.CompareAndSwap(true, false) {
		return &tunplatform.WintunRingFullError{Cause: 111}
	}
	return d.c50Device.WritePacket(b)
}

func TestM2UDPRingFullResponsePreservesRealDownBytesAndFailureRecords(t *testing.T) {
	var r c49DNSRecords
	s := c50Server(t, &r, func(c *Config) {
		c.Security = &SecurityOptions{AllowLoopback: true}
		c.Routing = &RoutingOptions{Final: "direct"}
		c.SetClientEgress(&ClientEgress{SystemQuery: func(_ context.Context, b []byte) ([]byte, error) {
			return dnsReply(b, []string{"203.0.113.52"}, 0), nil
		}})
	})
	p := c50Link(t, c50Ingress(t, s), func() bool { return true }, func() uint64 { return 44 })
	rfDev := &ringFullOnceDevice{c50Device: p.dev}
	// Replace runtime device with ringFullOnceDevice wrapper over the same c50Device.
	_ = p.plane.Close(context.Background())
	// Reset c50Device closes counter and context for the wrapped runtime.
	p.dev.closes.Store(0)
	p.dev.ctx, p.dev.cancel = context.WithCancel(context.Background())
	var err error
	p.plane, err = tunstack.StartReady(context.Background(), tunstack.Config{
		Device:    rfDev,
		Ingress:   c50Ingress(t, s),
		Admitting: func() bool { return true },
		Epoch:     func() uint64 { return 44 },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.plane.Close(context.Background()) }()

	inner := p.udp(t, 41449, netip.MustParseAddrPort("198.18.0.2:53"))
	defer inner.Close()

	// 1st DNS query: outbound reply hits WintunRingFullError -> dropped, 0 Down bytes, runtime stays alive.
	rfDev.failNext.Store(true)
	q1 := c49DNSQuery(t, 501)
	if _, e := inner.Write(q1); e != nil {
		t.Fatal(e)
	}
	waitFor(t, func() bool { return s.counters.Dropped.Load() >= 1 })
	if p.plane.Err() != nil || p.dev.closes.Load() != 0 {
		t.Fatalf("runtime closed/failed on transient ring full: err=%v closes=%d", p.plane.Err(), p.dev.closes.Load())
	}
	if gotDown := s.reg.Snapshot().Total.Down; gotDown != 0 {
		t.Fatalf("dropped UDP/DNS response falsely counted in Total.Down: got %d, want 0", gotDown)
	}

	// 2nd DNS query on the same UDP socket: succeeds and counts only the delivered reply bytes.
	q2 := c49DNSQuery(t, 502)
	if _, e := inner.Write(q2); e != nil {
		t.Fatal(e)
	}
	buf := make([]byte, 4096)
	_ = inner.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, e := inner.Read(buf)
	if e != nil || n == 0 {
		t.Fatalf("second DNS query after ring full failed: n=%d err=%v", n, e)
	}
	waitFor(t, func() bool { return s.reg.Snapshot().Total.Down == uint64(n) })
	if gotDown := s.reg.Snapshot().Total.Down; gotDown != uint64(n) {
		t.Fatalf("Total.Down=%d, want %d (only delivered second reply)", gotDown, n)
	}

	r.mu.Lock()
	sawDNSRespFailed := false
	for _, ev := range r.events {
		if ev.Code == "dns_response_failed" {
			sawDNSRespFailed = true
		}
	}
	r.mu.Unlock()
	if !sawDNSRespFailed {
		t.Fatal("expected dns_response_failed diagnostic record for dropped first reply")
	}

	// 3rd check: regular UDP NAT reply (tun_udp.go): 1st reply hits ring-full -> records udp_response_failed,
	// increments Dropped, does NOT add to Total.Down; 2nd reply succeeds and adds exact bytes to Total.Down.
	echoSock := stage4Socket(t, "udp4", c50LocalIP(t, false))
	udpInner := stage4UDP(t, p, false)
	if _, e := udpInner.WriteTo([]byte("ping"), echoSock.LocalAddr()); e != nil {
		t.Fatal(e)
	}
	_ = echoSock.SetReadDeadline(time.Now().Add(time.Second))
	_, natPeer, e := echoSock.ReadFromUDPAddrPort(make([]byte, 16))
	if e != nil {
		t.Fatal(e)
	}
	beforeDown := s.reg.Snapshot().Total.Down
	beforeDrops := s.counters.Dropped.Load()

	rfDev.failNext.Store(true)
	droppedPayload := []byte("dropped-udp-nat-reply-payload")
	if _, e := echoSock.WriteToUDPAddrPort(droppedPayload, natPeer); e != nil {
		t.Fatal(e)
	}
	waitFor(t, func() bool { return s.counters.Dropped.Load() > beforeDrops })
	if gotDown := s.reg.Snapshot().Total.Down; gotDown != beforeDown {
		t.Fatalf("dropped UDP NAT reply falsely counted in Total.Down: got %d, want %d", gotDown, beforeDown)
	}

	okPayload := []byte("delivered-udp-nat-reply")
	if _, e := echoSock.WriteToUDPAddrPort(okPayload, natPeer); e != nil {
		t.Fatal(e)
	}
	_ = udpInner.SetReadDeadline(time.Now().Add(2 * time.Second))
	rn, _, e := udpInner.ReadFrom(buf)
	if e != nil || rn != len(okPayload) {
		t.Fatalf("recovered UDP NAT reply failed: rn=%d err=%v", rn, e)
	}
	waitFor(t, func() bool { return s.reg.Snapshot().Total.Down == beforeDown+uint64(len(okPayload)) })

	r.mu.Lock()
	sawUDPRespFailed := false
	for _, ev := range r.events {
		if ev.Code == "udp_response_failed" {
			sawUDPRespFailed = true
		}
	}
	r.mu.Unlock()
	if !sawUDPRespFailed {
		t.Fatal("expected udp_response_failed diagnostic record for dropped UDP NAT reply")
	}
}

func TestC46UDPAssociationTerminalOutcomes(t *testing.T) {
	cases := []struct {
		name, result, previous, code, want string
		recorded                           bool
	}{
		{name: "no datagrams is neutral", result: "idle", want: "idle"},
		{name: "normal datagram is successful", result: "ok", want: "ok"},
		{name: "prior error is preserved", result: "idle", previous: "error", code: "udp_send_failed", want: "error", recorded: true},
		{name: "prior reject is preserved", result: "idle", previous: "rejected", code: "rejected", want: "rejected", recorded: true},
		{name: "association error is not idle", result: "udp_association_failed", want: "error"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var events []ConnectionEvent
			s := &Server{core: &core{connectionSink: func(e ConnectionEvent) { events = append(events, e) }}}
			f := &flow{s: s, id: 1, network: "udp", start: time.Now(), lastOutcome: tt.previous, lastCode: tt.code, eventRecorded: tt.recorded}
			f.end(tt.result)
			if len(events) == 0 {
				t.Fatal("missing terminal record")
			}
			got := events[len(events)-1]
			if !got.Ended || got.Outcome != tt.want {
				t.Fatalf("terminal ended=%v outcome=%q, want %q", got.Ended, got.Outcome, tt.want)
			}
			if tt.want == "idle" && (got.Code != "udp_no_datagrams" || len(events) != 1 || got.Up != 0 || got.Down != 0) {
				t.Fatalf("idle was rewritten or duplicated: %+v", events)
			}
			if tt.recorded && got.Code != tt.code {
				t.Fatalf("lost recorded cause %q", got.Code)
			}
			if s.closedSize != 1 {
				t.Fatal("terminal record hidden")
			}
		})
	}
}

func TestC46ZeroPayloadDatagramIsStillAReceivedDatagram(t *testing.T) {
	a := &udpAssociation{server: &Server{cfg: Config{Limits: Limits{UDPQueue: 1, UDPQueueBytes: 1024}}}, ctx: context.Background(), queue: make(chan packet, 1)}
	a.enqueue(packet{target: Address{Host: "127.0.0.1", Port: 53}, payload: []byte{}})
	if !a.receivedDatagram.Load() || len(a.queue) != 1 {
		t.Fatal("valid zero-payload datagram mistaken for no datagrams")
	}
}

const c49DNSName = "c49-private-question.example."

var c49DNSTarget = Address{Host: "198.18.0.2", Port: 53}

type c49DNSRecords struct {
	mu     sync.Mutex
	events []ConnectionEvent
	logs   []ClientLogEvent
}

func (r *c49DNSRecords) event(e ConnectionEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}
func (r *c49DNSRecords) log(e ClientLogEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logs = append(r.logs, e)
}
func (r *c49DNSRecords) terminal() (ConnectionEvent, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.events) - 1; i >= 0; i-- {
		if r.events[i].Ended {
			return r.events[i], true
		}
	}
	return ConnectionEvent{}, false
}
func (r *c49DNSRecords) failed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.events {
		if e.Outcome == "error" {
			return true
		}
	}
	return false
}
func c49DNSQuery(t *testing.T, id uint16) []byte {
	t.Helper()
	name, e := dnsmessage.NewName(c49DNSName)
	if e != nil {
		t.Fatal(e)
	}
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	b, e := m.Pack()
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func c49DNSServer(t *testing.T, records *c49DNSRecords, query func(context.Context, []byte) ([]byte, error), idle time.Duration) *Server {
	t.Helper()
	return startTest(t, Inbound{Protocol: "socks5"}, func(c *Config) {
		c.DNS = &DNSOptions{Server: "system"}
		c.SetClientIPv6(true)
		c.SetClientEgress(&ClientEgress{SystemQuery: query})
		c.SetConnectionSink(records.event)
		c.SetClientLogSink(records.log)
		c.Limits.UDPIdle = Duration(idle)
	})
}

func TestC49ControlledDNSFailureRecords(t *testing.T) {
	for _, tt := range []struct {
		name, code, stage                  string
		invalid, upstreamError, writeError bool
		rcode                              dnsmessage.RCode
	}{
		{name: "malformed request", invalid: true, code: "dns_query_failed", stage: "dns"},
		{name: "upstream error becomes wire SERVFAIL", upstreamError: true, code: "dns_query_failed", stage: "dns"},
		{name: "writeback error", writeError: true, code: "dns_response_failed", stage: "response"},
		{name: "NXDOMAIN is a valid negative answer", rcode: dnsmessage.RCodeNameError},
		{name: "NODATA is a valid answer"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var records c49DNSRecords
			s := c49DNSServer(t, &records, func(_ context.Context, b []byte) ([]byte, error) {
				if tt.upstreamError {
					return nil, errors.New("fixture upstream unavailable")
				}
				m, e := dnsRequest(b)
				if e != nil {
					return nil, e
				}
				r := dnsGatewayReply(m, tt.rcode)
				return r.Pack()
			}, time.Second)
			f, ctx := s.newFlow(withInbound(context.Background(), 0), "udp", Address{})
			nativeSock, clientSock := localUDP(t), localUDP(t)
			if tt.writeError {
				_ = nativeSock.Close()
			}
			a := &udpAssociation{server: s, ctx: ctx, flow: f, native: nativeSock, client: addrPort(clientSock.LocalAddr())}
			q := c49DNSQuery(t, 10)
			if tt.invalid {
				q = []byte{1}
			}
			// Exercise the real controlled branch with concurrent details snapshots.
			done, stopped := make(chan struct{}), make(chan struct{})
			go func() {
				defer close(stopped)
				for {
					select {
					case <-done:
						return
					default:
						f.info(time.Now())
					}
				}
			}()
			a.send(ctx, packet{target: c49DNSTarget, payload: q}, time.Second)
			close(done)
			<-stopped
			var reply []byte
			_ = clientSock.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			rbuf := make([]byte, 2048)
			if rn, _, re := clientSock.ReadFromUDP(rbuf); re == nil && rn > 10 {
				reply = append([]byte(nil), rbuf[10:rn]...)
			}
			f.end("ok") // A graceful control close must preserve the DNS error.
			last, ok := records.terminal()
			wantOutcome := "ok"
			if tt.code != "" {
				wantOutcome = "error"
			}
			if !ok || last.Outcome != wantOutcome || last.Code != tt.code || last.ErrorStage != tt.stage || last.Target != c49DNSTarget.String() || last.Rule != "dns" {
				t.Fatalf("incorrect DNS terminal: %+v", last)
			}
			if last.Up != uint64(len(q)) || last.Down != uint64(len(reply)) {
				t.Fatalf("failed DNS traffic miscount: up/down=%d/%d expected=%d/%d", last.Up, last.Down, len(q), len(reply))
			}
			if tt.code != "" && last.ErrorText == "" {
				t.Fatal("failure missing error detail")
			}
			wantDropped := int64(0)
			if tt.invalid || tt.writeError {
				wantDropped = 1
			}
			if s.Stats().Dropped != wantDropped {
				t.Fatalf("dropped=%d want=%d", s.Stats().Dropped, wantDropped)
			}
			if tt.upstreamError {
				var m dnsmessage.Message
				if m.Unpack(reply) != nil || m.RCode != dnsmessage.RCodeServerFailure {
					t.Fatal("SERVFAIL response was not delivered unchanged")
				}
			}
		})
	}
}

func TestC49ControlledDNSActiveReaders(t *testing.T) {
	var records c49DNSRecords
	const idle = 200 * time.Millisecond
	s := c49DNSServer(t, &records, func(_ context.Context, b []byte) ([]byte, error) {
		return dnsReply(b, []string{"203.0.113.49"}, 60), nil
	}, idle)
	f, ctx := s.newFlow(context.Background(), "udp", Address{})
	defer f.end("ok")
	nativeSock, clientSock := localUDP(t), localUDP(t)
	a := &udpAssociation{server: s, ctx: ctx, flow: f, native: nativeSock, client: addrPort(clientSock.LocalAddr())}
	var readers []<-chan struct{}
	for _, network := range []string{"udp4", "udp6"} {
		ip := net.IPv4(127, 0, 0, 1)
		if network == "udp6" {
			ip = net.IPv6loopback
		}
		u, e := net.ListenUDP(network, &net.UDPAddr{IP: ip})
		if e != nil {
			t.Fatal("reader fixture", e)
		}
		defer u.Close()
		if network == "udp4" {
			a.outbound4 = u
		} else {
			a.outbound6 = u
		}
		done := make(chan struct{})
		readers = append(readers, done)
		a.activity.Store(time.Now().UnixNano())
		go func() { defer close(done); a.returnLoop(u) }()
	}
	for i := 0; i < 7; i++ { // More than three original idle windows, no outbound replies.
		time.Sleep(100 * time.Millisecond)
		for _, done := range readers {
			select {
			case <-done:
				t.Fatal("active DNS was reclaimed by an unused reader")
			default:
			}
		}
		a.send(ctx, packet{target: c49DNSTarget, payload: c49DNSQuery(t, uint16(30+i))}, idle)
		if time.Since(time.Unix(0, a.activity.Load())) > idle/2 {
			t.Fatal("DNS did not refresh activity")
		}
	}
	// Stopping queries must still release genuinely idle readers.
	for _, done := range readers {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("idle DNS reader was not reclaimed")
		}
	}
	if f.up.Load() == 0 || f.down.Load() == 0 {
		t.Fatal("active DNS test did not execute payload accounting")
	}
}

func TestNativeUDPOutputWritebackClosedSocketAndOversizedBoundary(t *testing.T) {
	var records c49DNSRecords
	s := c49DNSServer(t, &records, func(context.Context, []byte) ([]byte, error) {
		return nil, errors.New("unused")
	}, time.Second)
	f, ctx := s.newFlow(context.Background(), "udp", Address{})
	defer f.end("ok")
	nativeSock, clientSock := localUDP(t), localUDP(t)
	clientAddr := addrPort(clientSock.LocalAddr())
	a := &udpAssociation{server: s, ctx: ctx, flow: f, native: nativeSock, client: clientAddr}

	if err := a.output(netip.AddrPortFrom(clientAddr.Addr(), 0), c49DNSTarget, []byte("noop"), time.Second); err != nil {
		t.Fatalf("port 0 output returned error: %v", err)
	}

	if err := a.output(clientAddr, c49DNSTarget, []byte("pong"), time.Second); err != nil {
		t.Fatalf("normal output failed: %v", err)
	}
	_ = clientSock.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 128)
	n, _, err := clientSock.ReadFromUDP(buf)
	if err != nil || n != 14 || string(buf[10:14]) != "pong" {
		t.Fatalf("unexpected SOCKS5 UDP datagram: n=%d err=%v data=%x", n, err, buf[:n])
	}

	beforeDropped := s.counters.Dropped.Load()
	oversized := make([]byte, maxDatagram)
	if err := a.output(clientAddr, c49DNSTarget, oversized, time.Second); err != nil {
		t.Fatalf("oversized output returned error: %v", err)
	}
	if got := s.counters.Dropped.Load(); got != beforeDropped+1 {
		t.Fatalf("oversized datagram did not increment Dropped: got %d want %d", got, beforeDropped+1)
	}

	_ = nativeSock.Close()
	if err := a.output(clientAddr, c49DNSTarget, []byte("after-close"), time.Second); err == nil {
		t.Fatal("expected non-nil error writing to closed native UDP socket, got nil")
	}
}

func TestC50PacketSourceKernelDirect(t *testing.T) {
	ip := netip.MustParseAddr(c50LocalIP(t, false))
	peer, e := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, 0)))
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	selected, controlled, released := 0, 0, 0
	want := errors.New("physical fenced")
	fail := false
	s := c50Server(t, nil, func(c *Config) {
		// socksCfg binds loopback for unrelated tests. Exercise an unconfigured
		// remote source here, letting PacketSource choose the actual local IP.
		c.UDPBindIPv4, c.UDPBindIPv6 = "", ""
		c.SetClientEgress(&ClientEgress{
			PacketSource: func(n string, b netip.Addr) (netip.Addr, error) {
				selected++
				if n != "udp4" || b.IsValid() {
					t.Fatalf("kernel changed source input: %s %s", n, b)
				}
				if fail {
					return netip.Addr{}, want
				}
				return ip, nil
			},
			PacketControl: func(n string, c *net.UDPConn) error {
				controlled++
				if n != "udp4" || c.LocalAddr().(*net.UDPAddr).AddrPort().Addr() != ip {
					t.Fatalf("not selected source %s %v", n, c.LocalAddr())
				}
				return nil
			},
			PacketRelease: func(*net.UDPConn) { released++ },
		})
	})
	// Use the same production direct outbound installed by buildRouting.
	cur := s.current()
	rt, e := cur.buildRouting()
	if e != nil {
		t.Fatal(e)
	}
	defer rt.close()
	pc, e := rt.nodes["direct"].ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	dst := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	addr := outbound.Addr{Host: dst.Addr().String(), Port: dst.Port()}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = pc.WriteTo([]byte("hook"), addr); e != nil {
		t.Fatal(e)
	}
	var b [8]byte
	n, src, e := peer.ReadFromUDPAddrPort(b[:])
	if e != nil || src.Addr() != ip || string(b[:n]) != "hook" {
		t.Fatalf("upstream src=%v err=%v", src, e)
	}
	if _, e = peer.WriteToUDPAddrPort([]byte("reply"), src); e != nil {
		t.Fatal(e)
	}
	_ = pc.SetReadDeadline(time.Now().Add(time.Second))
	n, from, e := pc.ReadFrom(b[:])
	if e != nil || string(b[:n]) != "reply" || from != addr {
		t.Fatalf("downstream %q from=%v err=%v", b[:n], from, e)
	}
	_ = pc.Close()
	if selected != 1 || controlled != 1 || released != 1 {
		t.Fatalf("hook counts %d/%d/%d", selected, controlled, released)
	}
	fail = true
	pc, e = rt.nodes["direct"].ListenPacket(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	n, e = pc.WriteTo([]byte("blocked"), addr)
	if n != 0 || !errors.Is(e, want) || controlled != 1 {
		t.Fatalf("kernel hook error hidden: n=%d err=%v control=%d", n, e, controlled)
	}
}
