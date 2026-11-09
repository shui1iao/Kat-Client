package kernel

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/procattr"
	"github.com/shui1iao/Kat/internal/tunstack"
	"golang.org/x/net/dns/dnsmessage"
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
