package kernel

import (
	"context"

	"errors"
	"net"
	"net/netip"

	"sync"

	"testing"
	"time"

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
