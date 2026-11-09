package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/procattr"
	"golang.org/x/net/dns/dnsmessage"
)

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

func TestC49ControlledDNSAccountingAndGeneration(t *testing.T) {
	var records c49DNSRecords
	var calls, processCalls atomic.Int64
	oldLookup := lookupApplication
	lookupApplication = func(context.Context, procattr.Query) procattr.Identity {
		processCalls.Add(1)
		return procattr.Identity{Status: "unsupported"}
	}
	defer func() { lookupApplication = oldLookup }()
	s := c49DNSServer(t, &records, func(_ context.Context, b []byte) ([]byte, error) {
		calls.Add(1)
		return dnsReply(b, []string{"203.0.113.49"}, 60), nil
	}, time.Second)
	control, u, relay := socksAssociate(t, s, 0)
	defer control.Close()
	var up, down uint64
	var id string
	for i := uint16(1); i <= 3; i++ {
		if i == 3 {
			before := s.current()
			next := s.CurrentConfig()
			next.SetClientEgress(&ClientEgress{SystemQuery: func(_ context.Context, b []byte) ([]byte, error) {
				calls.Add(1)
				return dnsReply(b, []string{"203.0.113.50"}, 60), nil
			}})
			if _, e := s.ApplyConfig(next); e != nil {
				t.Fatal(e)
			}
			if s.current() == before {
				t.Fatal("generation did not change")
			}
		}
		q := c49DNSQuery(t, i)
		socksUDPSend(t, u, relay, c49DNSTarget, q, 0)
		reply := socksUDPRead(t, u)
		var m dnsmessage.Message
		if e := m.Unpack(reply); e != nil || m.ID != i || len(m.Answers) != 1 {
			t.Fatal("DNS response changed", e)
		}
		want := [4]byte{203, 0, 113, 49}
		if i == 3 {
			want[3] = 50
		}
		if m.Answers[0].Body.(*dnsmessage.AResource).A != want {
			t.Fatal("retained association did not use current DNS generation")
		}
		up += uint64(len(q))
		down += uint64(len(reply))
		waitFor(t, func() bool { a, _ := s.ClientConnections(1); return len(a) == 1 && a[0].Down == down })
		a, _ := s.ClientConnections(1)
		if id == "" {
			id = a[0].FlowID
		}
		if a[0].FlowID != id || a[0].Target != c49DNSTarget.String() || a[0].Rule != "dns" || joinChain(a[0].Chain) != "dns" || a[0].Network != "udp" || a[0].Up != up {
			t.Fatalf("incorrect DNS flow: %+v", a[0])
		}
		if a[0].Host != "" || a[0].DestHost != "" {
			t.Fatal("DNS question was used as business/sniff target")
		}
	}
	if calls.Load() != 3 || processCalls.Load() != 0 {
		t.Fatalf("system/generation calls=%d, unnecessary process queries=%d", calls.Load(), processCalls.Load())
	}
	control.Close()
	waitFor(t, func() bool { _, ok := records.terminal(); return ok })
	last, _ := records.terminal()
	if last.Outcome != "ok" || last.Code != "" || last.Up != up || last.Down != down {
		t.Fatalf("incorrect terminal DNS record: %+v", last)
	}
	total := s.reg.Total.Load()
	in := s.keys.inbound[0].Load()
	if total.Up != up || total.Down != down || in != total {
		t.Fatalf("DNS payload not counted exactly once: total=%+v inbound=%+v", total, in)
	}
	for _, r := range s.reg.Snapshot().Rules {
		if r.Hits != 0 || r.Up != 0 || r.Down != 0 {
			t.Fatal("internal DNS invented a business rule hit", r)
		}
	}
	if v := s.reg.Outbound("direct").Load(); v.Up != 0 || v.Down != 0 {
		t.Fatal("internal DNS invented direct outbound traffic", v)
	}
	records.mu.Lock()
	logs, _ := json.Marshal(records.logs)
	records.mu.Unlock()
	if strings.Contains(string(logs), "c49-private-question") {
		t.Fatal("DNS question leaked to public safe logs")
	}
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
			var reply []byte
			a := &udpAssociation{server: s, ctx: ctx, flow: f, writeBack: func(source Address, b []byte) error {
				if source != c49DNSTarget {
					t.Fatal("reply source changed")
				}
				if tt.writeError {
					return errors.New("fixture writeback failed")
				}
				reply = append([]byte(nil), b...)
				return nil
			}}
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

func TestC49ControlledDNSFailureSurvivesOtherTraffic(t *testing.T) {
	var records c49DNSRecords
	s := c49DNSServer(t, &records, func(_ context.Context, b []byte) ([]byte, error) {
		return dnsReply(b, []string{"203.0.113.49"}, 60), nil
	}, time.Second)
	control, u, relay := socksAssociate(t, s, 0)
	defer control.Close()
	socksUDPSend(t, u, relay, c49DNSTarget, []byte{1}, 0)
	waitFor(t, records.failed)
	socksUDPSend(t, u, relay, c49DNSTarget, c49DNSQuery(t, 20), 0)
	socksUDPRead(t, u)
	// Ordinary UDP emits a later ok routing event on the SAME association.
	target, _ := echoUDP(t)
	socksUDPSend(t, u, relay, target, []byte("ordinary-udp-still-works"), 0)
	if string(socksUDPRead(t, u)) != "ordinary-udp-still-works" {
		t.Fatal("ordinary UDP behavior changed")
	}
	control.Close()
	waitFor(t, func() bool { _, ok := records.terminal(); return ok })
	last, _ := records.terminal()
	if last.Outcome != "error" || last.Code != "dns_query_failed" || last.Down == 0 {
		t.Fatalf("later successful traffic erased DNS failure: %+v", last)
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
	a := &udpAssociation{server: s, ctx: ctx, flow: f, writeBack: func(Address, []byte) error { return nil }}
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
