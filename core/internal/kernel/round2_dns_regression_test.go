package kernel

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// [GO-P1-3] Verify that a short-deadline first caller (50ms) does not poison the shared
// singleflight background query for a concurrent 5s caller joining 10ms later on an 80ms RTT upstream,
// while still canceling promptly when the last waiter exits.
func TestDNSSingleflightShortCallerDoesNotPoisonJoiner(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	var aQueries atomic.Int32
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			go func(raw []byte, peer *net.UDPAddr) {
				var qm dnsmessage.Message
				if qm.Unpack(raw) != nil || len(qm.Questions) != 1 {
					return
				}
				q := qm.Questions[0]
				if q.Type == dnsmessage.TypeA {
					aQueries.Add(1)
				}
				time.Sleep(80 * time.Millisecond)
				rep := dnsmessage.Message{
					Header: dnsmessage.Header{
						ID:                 qm.ID,
						Response:           true,
						RecursionDesired:   qm.RecursionDesired,
						RecursionAvailable: true,
					},
					Questions: []dnsmessage.Question{q},
				}
				if q.Type == dnsmessage.TypeA {
					rep.Answers = []dnsmessage.Resource{{
						Header: dnsmessage.ResourceHeader{
							Name:  q.Name,
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   120,
						},
						Body: &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}},
					}}
				}
				if out, err := rep.Pack(); err == nil {
					_, _ = pc.WriteToUDP(out, peer)
				}
			}(pkt, from)
		}
	}()

	r := chainDNS(t, "udp://"+pc.LocalAddr().String())
	r.policyOnly = true
	r.disableIPv6 = true

	// Part 1: Caller A (50ms) starts at t=0; Caller B (5s) joins at t=10ms.
	// Upstream RTT is 80ms -> A times out at ~50ms, B succeeds at ~70ms after joining!
	t0 := time.Now()
	ctxA, cancelA := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelA()

	type lookupRes struct {
		ips     []netip.Addr
		err     error
		elapsed time.Duration
	}
	resACh := make(chan lookupRes, 1)
	go func() {
		ips, err := r.lookup(ctxA, "shared-flight.example.com")
		resACh <- lookupRes{ips: ips, err: err, elapsed: time.Since(t0)}
	}()

	time.Sleep(10 * time.Millisecond)
	tB := time.Now()
	ctxB, cancelB := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelB()
	resBCh := make(chan lookupRes, 1)
	go func() {
		ips, err := r.lookup(ctxB, "shared-flight.example.com")
		resBCh <- lookupRes{ips: ips, err: err, elapsed: time.Since(tB)}
	}()

	resA := <-resACh
	if !errors.Is(resA.err, context.DeadlineExceeded) {
		t.Fatalf("Caller A err = %v, want context.DeadlineExceeded", resA.err)
	}
	if resA.elapsed < 35*time.Millisecond || resA.elapsed > 120*time.Millisecond {
		t.Fatalf("Caller A elapsed = %v, want ~50ms", resA.elapsed)
	}

	resB := <-resBCh
	if resB.err != nil {
		t.Fatalf("Caller B failed (poisoned by short deadline of Caller A): %v", resB.err)
	}
	wantIP := netip.MustParseAddr("93.184.216.34")
	if len(resB.ips) != 1 || resB.ips[0] != wantIP {
		t.Fatalf("Caller B ips = %v, want [%v]", resB.ips, wantIP)
	}
	if resB.elapsed < 40*time.Millisecond || resB.elapsed > 300*time.Millisecond {
		t.Fatalf("Caller B elapsed = %v, want ~70ms", resB.elapsed)
	}
	if gotQ := aQueries.Load(); gotQ != 1 {
		t.Fatalf("expected 1 coalesced upstream TypeA query, got %d", gotQ)
	}

	// Part 2: Single caller with 5s deadline canceled at 40ms -> when waiters hits 0,
	// releaseFlightWaiter immediately calls fl.cancel() and cleans up with zero leak.
	aloneStart := time.Now()
	baseAlone, cancelBaseAlone := context.WithCancel(context.Background())
	ctxAlone, stopAlone := context.WithTimeout(baseAlone, 5*time.Second)
	defer stopAlone()
	go func() {
		time.Sleep(40 * time.Millisecond)
		cancelBaseAlone()
	}()
	_, errAlone := r.lookup(ctxAlone, "alone-short.example.com")
	if !errors.Is(errAlone, context.Canceled) {
		t.Fatalf("alone canceled lookup err = %v, want context.Canceled", errAlone)
	}
	if elapsed := time.Since(aloneStart); elapsed > 120*time.Millisecond {
		t.Fatalf("alone canceled lookup took %v, expected prompt cancellation (~40ms)", elapsed)
	}
	r.mu.Lock()
	inflightLeft := len(r.inflight)
	r.mu.Unlock()
	if inflightLeft != 0 {
		t.Fatalf("expected 0 remaining inflight entries after last waiter exit, got %d", inflightLeft)
	}
}

// [GO-P2-1] Verify parseDNSQueryFast only admits a single standard TypeOPT with rdLen == 0,
// rejecting truncated OPT RDATA (rdLen=1), duplicate OPT records, and unsolicited Additional TypeA,
// while valid queries carrying EDNS0 Options fall back cleanly to the slow path and succeed.
func TestDNSGatewayAdditionalRRValidationAndEDNSOptionFallback(t *testing.T) {
	var upstreamCalls atomic.Int32
	s := startTest(t, Inbound{Protocol: "socks5", Name: "kat-client"}, func(c *Config) {
		c.SetClientDNSConfig(nil, nil, "rule", "direct")
		c.SetClientEgress(&ClientEgress{
			Active: func() bool { return true },
			SystemQuery: func(_ context.Context, w []byte) ([]byte, error) {
				m, e := dnsRequest(w)
				if e != nil {
					return nil, e
				}
				upstreamCalls.Add(1)
				rep := dnsGatewayReply(m, dnsmessage.RCodeSuccess)
				rep.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{
						Name:  m.Questions[0].Name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
						TTL:   60,
					},
					Body: &dnsmessage.AResource{A: [4]byte{1, 1, 1, 1}},
				}}
				return rep.Pack()
			},
		})
	})

	baseQuery := buildDNSQuery(t, 0x9100, "edns-check.example.com", dnsmessage.TypeA)
	var lowerBuf [255]byte

	// Baseline: standard empty OPT (rdLen=0) takes fast path.
	stdEDNS := buildDNSQueryEDNS(t, 0x9101, "edns-check.example.com", dnsmessage.TypeA, 1232)
	if _, _, _, lim, hasOPT, ok := parseDNSQueryFast(stdEDNS, &lowerBuf); !ok || !hasOPT || lim != 1232 {
		t.Fatalf("standard empty OPT should pass fast path: ok=%v hasOPT=%v lim=%d", ok, hasOPT, lim)
	}

	// 1. Truncated 1-byte OPT RDATA (ARCOUNT=1, TypeOPT, RDLENGTH=1, 1 byte body)
	truncOPT := append([]byte(nil), baseQuery...)
	binary.BigEndian.PutUint16(truncOPT[10:12], 1)
	truncOPT = append(truncOPT,
		0x00,       // root "."
		0x00, 0x29, // TypeOPT
		0x10, 0x00, // UDP size 4096
		0x00, 0x00, 0x00, 0x00, // TTL/flags
		0x00, 0x01, // RDLENGTH = 1 (malformed truncated option!)
		0xff, // 1 byte garbage
	)

	// 2. Duplicate OPT records (ARCOUNT=2, two TypeOPT RRs)
	dupOPT := append([]byte(nil), baseQuery...)
	binary.BigEndian.PutUint16(dupOPT[10:12], 2)
	dupOPT = append(dupOPT, ednsOPTRRWire[:]...)
	dupOPT = append(dupOPT, ednsOPTRRWire[:]...)

	// 3a. Unsolicited Additional TypeA with truncated RDATA (RDLENGTH=2)
	truncAddTypeA := append([]byte(nil), baseQuery...)
	binary.BigEndian.PutUint16(truncAddTypeA[10:12], 1)
	truncAddTypeA = append(truncAddTypeA,
		0x00,       // root "."
		0x00, 0x01, // TypeA
		0x00, 0x01, // ClassINET
		0x00, 0x00, 0x00, 0x3c, // TTL 60
		0x00, 0x02, // RDLENGTH = 2 (invalid TypeA)
		1, 2,
	)

	// 3b. Unsolicited Additional TypeA with 4-byte RDATA
	fullAddTypeA := append([]byte(nil), baseQuery...)
	binary.BigEndian.PutUint16(fullAddTypeA[10:12], 1)
	fullAddTypeA = append(fullAddTypeA,
		0x00,       // root "."
		0x00, 0x01, // TypeA
		0x00, 0x01, // ClassINET
		0x00, 0x00, 0x00, 0x3c, // TTL 60
		0x00, 0x04, // RDLENGTH = 4
		1, 2, 3, 4,
	)

	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"truncated_opt_rdlen_1", truncOPT},
		{"duplicate_opt_records", dupOPT},
		{"truncated_additional_type_a", truncAddTypeA},
		{"unsolicited_additional_type_a", fullAddTypeA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, _, _, ok := parseDNSQueryFast(tc.wire, &lowerBuf); ok {
				t.Fatalf("%s unexpectedly accepted by parseDNSQueryFast", tc.name)
			}
			if _, err := s.answerDNS(context.Background(), tc.wire, false); err == nil {
				t.Fatalf("%s unexpectedly accepted by answerDNS", tc.name)
			}
		})
	}
	if got := upstreamCalls.Load(); got != 0 {
		t.Fatalf("malformed queries reached upstream %d times, want 0", got)
	}

	// 4. Valid query carrying an EDNS0 Option (Cookie option code 10, 8-byte client cookie)
	// must bypass parseDNSQueryFast (ok == false) and succeed cleanly via slow-path Unpack!
	validOptMsg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0x9109, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName("edns-option-ok.example.com."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
		Additionals: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.TypeOPT,
				Class: dnsmessage.Class(1400),
			},
			Body: &dnsmessage.OPTResource{
				Options: []dnsmessage.Option{{
					Code: 10, // EDNS0 Cookie
					Data: []byte{1, 2, 3, 4, 5, 6, 7, 8},
				}},
			},
		}},
	}
	validOptWire, err := validOptMsg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, _, ok := parseDNSQueryFast(validOptWire, &lowerBuf); ok {
		t.Fatal("EDNS0 option query should decline fast path and use full Unpack validation")
	}
	replyWire, err := s.answerDNS(context.Background(), validOptWire, false)
	if err != nil {
		t.Fatalf("valid EDNS0 option query failed on slow path: %v", err)
	}
	replyMsg := unpackDNSReply(t, replyWire)
	if replyMsg.RCode != dnsmessage.RCodeSuccess || len(replyMsg.Answers) != 1 || !hasOPTRecord(replyMsg) {
		t.Fatalf("unexpected reply for valid EDNS0 option query: %+v", replyMsg)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("expected 1 upstream call for valid EDNS0 option query, got %d", got)
	}
}
