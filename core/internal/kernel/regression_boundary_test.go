package kernel

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/group"
	oss "github.com/shui1iao/Kat/internal/outbound/ss"
	"github.com/shui1iao/Kat/internal/ss"
	"github.com/shui1iao/Kat/internal/tunplatform"
)

type plainConnNoHalfClose struct {
	r io.Reader
	w io.Writer
	c io.Closer
}

func (p *plainConnNoHalfClose) Read(b []byte) (int, error)       { return p.r.Read(b) }
func (p *plainConnNoHalfClose) Write(b []byte) (int, error)      { return p.w.Write(b) }
func (p *plainConnNoHalfClose) Close() error                     { return p.c.Close() }
func (p *plainConnNoHalfClose) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (p *plainConnNoHalfClose) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (p *plainConnNoHalfClose) SetDeadline(time.Time) error      { return nil }
func (p *plainConnNoHalfClose) SetReadDeadline(time.Time) error  { return nil }
func (p *plainConnNoHalfClose) SetWriteDeadline(time.Time) error { return nil }

type staticDialOutbound struct {
	dialFn func(ctx context.Context, target outbound.Addr) (net.Conn, error)
}

func (o *staticDialOutbound) Name() string     { return "under-anytls" }
func (o *staticDialOutbound) Protocol() string { return "anytls" }
func (o *staticDialOutbound) UDP() bool        { return false }
func (o *staticDialOutbound) DialTCP(ctx context.Context, target outbound.Addr) (net.Conn, error) {
	return o.dialFn(ctx, target)
}
func (o *staticDialOutbound) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return nil, outbound.ErrUDPUnsupported
}

func TestRegressionHalfClose128KiBResponseNoTruncation(t *testing.T) {
	srv := &Server{
		core: &core{},
		pool: newBufferPool(64<<10, 8),
	}
	srv.cfg.Limits.DrainTimeout = Duration(3 * time.Second)

	wantResp := bytes.Repeat([]byte("SERVER-BIG-RESPONSE-PAYLOAD-0123"), 4096) // 131,072 bytes (128 KiB)

	tcpPair := func() (*net.TCPConn, *net.TCPConn) {
		ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		ch := make(chan *net.TCPConn, 1)
		go func() {
			c, _ := ln.AcceptTCP()
			ch <- c
		}()
		d, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
		if err != nil {
			t.Fatal(err)
		}
		return d, <-ch
	}

	runDirectOrWrapped := func(label string, wrapOut func(net.Conn) net.Conn) {
		t.Helper()
		clientEnd, relayClientEnd := tcpPair()
		relayOutRaw, targetServerEnd := tcpPair()
		relayOut := wrapOut(relayOutRaw)

		relayDone := make(chan error, 1)
		go func() {
			defer relayClientEnd.Close()
			defer relayOut.Close()
			relayDone <- srv.relayIdle(context.Background(), relayClientEnd, relayOut, 5*time.Second)
		}()

		go func() {
			reqBuf := make([]byte, 64)
			_, _ = targetServerEnd.Read(reqBuf)
			time.Sleep(25 * time.Millisecond)
			_, _ = targetServerEnd.Write(wantResp)
			_ = targetServerEnd.Close()
		}()

		if _, err := clientEnd.Write([]byte("GET /big HTTP/1.0\r\n\r\n")); err != nil {
			t.Fatalf("%s write request: %v", label, err)
		}
		if err := clientEnd.CloseWrite(); err != nil {
			t.Fatalf("%s CloseWrite: %v", label, err)
		}
		resp, err := io.ReadAll(clientEnd)
		_ = clientEnd.Close()
		relayErr := <-relayDone
		if err != nil {
			t.Fatalf("%s ReadAll err: %v", label, err)
		}
		if len(resp) != len(wantResp) || !bytes.Equal(resp, wantResp) {
			t.Fatalf("%s truncated response: got %d bytes, want %d (relayErr=%v)", label, len(resp), len(wantResp), relayErr)
		}
	}

	// 1. Native CloseWrite-capable outbound
	runDirectOrWrapped("native-tcp", func(c net.Conn) net.Conn { return c })

	// 2. Outbound without CloseWrite() method (e.g. *anytls.stream)
	runDirectOrWrapped("anytls-stream-no-closewrite", func(c net.Conn) net.Conn {
		return &plainConnNoHalfClose{r: c, w: c, c: c}
	})

	// 3. Real Shadowsocks outbound chained over a non-CloseWrite transport (SS-via-AnyTLS)
	const ssMethod = "aes-128-gcm"
	const ssPass = "test-halfclose-pass"
	rawKey, err := ss.PasswordKey2017(ssMethod, ssPass)
	if err != nil {
		t.Fatal(err)
	}
	ssSrv, err := ss.NewServer(ss.Config{Method: ssMethod, Key: rawKey})
	if err != nil {
		t.Fatal(err)
	}
	ssLn, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer ssLn.Close()

	go func() {
		raw, err := ssLn.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		sc, err := ssSrv.Accept(raw)
		if err != nil {
			return
		}
		defer sc.Close()
		buf := make([]byte, 64)
		_, _ = sc.Read(buf)
		time.Sleep(25 * time.Millisecond)
		_, _ = sc.Write(wantResp)
	}()

	ssAddr := ssLn.Addr().(*net.TCPAddr)
	under := &staticDialOutbound{
		dialFn: func(ctx context.Context, _ outbound.Addr) (net.Conn, error) {
			c, e := (&net.Dialer{}).DialContext(ctx, "tcp", ssAddr.String())
			if e != nil {
				return nil, e
			}
			// Strip CloseWrite() to simulate *anytls.stream carrier!
			return &plainConnNoHalfClose{r: c, w: c, c: c}, nil
		},
	}
	ssOut, err := oss.New(outbound.Options{
		Name:     "ss-via-anytls",
		Type:     "shadowsocks",
		Server:   ssAddr.IP.String(),
		Port:     uint16(ssAddr.Port),
		Method:   ssMethod,
		Password: ssPass,
	}, under)
	if err != nil {
		t.Fatal(err)
	}

	clientEnd, relayClientEnd := tcpPair()
	outConn, err := ssOut.DialTCP(context.Background(), outbound.Addr{Host: "example.com", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	// Verify SS-via-AnyTLS CloseWrite wraps errors.ErrUnsupported.
	if cw, ok := outConn.(interface{ CloseWrite() error }); !ok {
		t.Fatal("expected *ss.tcpConn to implement CloseWrite")
	} else if cwErr := cw.CloseWrite(); !errors.Is(cwErr, errors.ErrUnsupported) {
		t.Fatalf("expected errors.ErrUnsupported from SS-via-AnyTLS CloseWrite, got %v", cwErr)
	}

	relayDone := make(chan error, 1)
	go func() {
		defer relayClientEnd.Close()
		defer outConn.Close()
		relayDone <- srv.relayIdle(context.Background(), relayClientEnd, outConn, 5*time.Second)
	}()

	_, _ = clientEnd.Write([]byte("GET /ss-over-anytls HTTP/1.0\r\n\r\n"))
	_ = clientEnd.CloseWrite()
	gotSS, err := io.ReadAll(clientEnd)
	_ = clientEnd.Close()
	<-relayDone
	if err != nil || len(gotSS) != len(wantResp) || !bytes.Equal(gotSS, wantResp) {
		t.Fatalf("SS-via-AnyTLS half-close truncated: got=%d want=%d err=%v", len(gotSS), len(wantResp), err)
	}
}

func TestRegressionWireCacheEvictionAndLookupSingleflight(t *testing.T) {
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	port := tcpLn.Addr().(*net.TCPAddr).Port
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	var udpQueries atomic.Int64
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			udpQueries.Add(1)
			var req dnsmessage.Message
			if req.Unpack(buf[:n]) != nil || len(req.Questions) == 0 {
				continue
			}
			go func(req dnsmessage.Message, from net.Addr) {
				time.Sleep(15 * time.Millisecond)
				rep := dnsmessage.Message{
					Header:    dnsmessage.Header{ID: req.ID, Response: true},
					Questions: req.Questions,
				}
				if req.Questions[0].Type == dnsmessage.TypeA {
					rep.Answers = []dnsmessage.Resource{{
						Header: dnsmessage.ResourceHeader{Name: req.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 180},
						Body:   &dnsmessage.AResource{A: [4]byte{198, 51, 100, 77}},
					}}
				}
				b, _ := rep.Pack()
				_, _ = pc.WriteTo(b, from)
			}(req, from)
		}
	}()

	capEntries := 32
	r, err := newInternalDNS(&DNSOptions{
		Servers:      []string{fmt.Sprintf("udp://127.0.0.1:%d", port)},
		CacheEntries: &capEntries,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()

	// 1. 32 concurrent cold lookups (caller #0 cancels after 2ms): must collapse to <= 2 upstream UDP packets (A + AAAA)!
	var wg sync.WaitGroup
	var okCount atomic.Int32
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			qctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			if i == 0 {
				go func() { time.Sleep(2 * time.Millisecond); cancel() }()
			} else {
				defer cancel()
			}
			ips, e := r.lookup(qctx, "concurrent-burst.example.com")
			if i > 0 {
				if e != nil || len(ips) == 0 {
					t.Errorf("caller #%d failed: %v", i, e)
				} else {
					okCount.Add(1)
				}
			}
		}(i)
	}
	wg.Wait()
	if okCount.Load() != 31 {
		t.Fatalf("expected 31 non-canceled callers to succeed, got %d", okCount.Load())
	}
	if gotQ := udpQueries.Load(); gotQ > 2 {
		t.Fatalf("expected singleflight to coalesce 32 concurrent lookups into <= 2 upstream UDP packets, got %d", gotQ)
	}

	// 2. wireCache full-capacity eviction: 31 expired + 1 hot live entry -> expired entries purged, hot entry preserved!
	hotQ, q, _ := dnsQuestion("hot-live.example.com", dnsmessage.TypeA)
	goodMsg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 0x2222, Response: true},
		Questions: []dnsmessage.Question{q},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
			Body:   &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}},
		}},
	}
	goodWire, _ := goodMsg.Pack()
	slots, _ := scanDNSTTLSlotsInto(goodWire, nil)

	for trial := 0; trial < 20; trial++ {
		baseNow := r.now()
		epoch := r.dnsEpoch()
		r.mu.Lock()
		r.wireCache = make(map[string]dnsWireEntry, capEntries)
		for j := 0; j < capEntries-1; j++ {
			k := fmt.Sprintf("expired-%d-%d", trial, j)
			r.wireCache[k] = dnsWireEntry{
				wire:     goodWire,
				ttlSlots: slots,
				server:   "s",
				added:    baseNow.Add(-10 * time.Minute),
				expires:  baseNow.Add(-5 * time.Minute),
				epoch:    epoch,
			}
		}
		hotKey := string(hotQ[2:])
		r.wireCache[hotKey] = dnsWireEntry{
			wire:     goodWire,
			ttlSlots: slots,
			server:   "UDP 1.1.1.1",
			added:    baseNow.Add(-10 * time.Second),
			expires:  baseNow.Add(290 * time.Second),
			epoch:    epoch,
		}
		r.mu.Unlock()

		qWire, _, _ := dnsQuestion(fmt.Sprintf("fresh-%d.example.com", trial), dnsmessage.TypeA)
		gctx, gcancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, gErr := r.gateway(gctx, qWire, false)
		gcancel()
		if gErr != nil {
			t.Fatalf("gateway query failed: %v", gErr)
		}

		r.mu.Lock()
		_, hotStillThere := r.wireCache[hotKey]
		expiredLeft := 0
		nowAfter := r.now()
		for _, v := range r.wireCache {
			if !v.expires.After(nowAfter) {
				expiredLeft++
			}
		}
		r.mu.Unlock()
		if !hotStillThere {
			t.Fatalf("trial %d: hot unexpired wireCache entry was wrongly evicted!", trial)
		}
		if expiredLeft != 0 {
			t.Fatalf("trial %d: %d expired zombie entries remained in wireCache", trial, expiredLeft)
		}
	}

	// Verify zero-parse TTL rewrite accuracy & TXID rewrite on wireCache hit
	hitQuery := bytes.Clone(hotQ)
	binary.BigEndian.PutUint16(hitQuery[0:2], 0xabcd)
	reply, err := r.gateway(context.Background(), hitQuery, false)
	if err != nil {
		t.Fatal(err)
	}
	var unpacked dnsmessage.Message
	if err := unpacked.Unpack(reply); err != nil {
		t.Fatalf("repacked wireCache hit invalid: %v", err)
	}
	if unpacked.ID != 0xabcd || len(unpacked.Answers) != 1 || unpacked.Answers[0].Header.TTL > 290 || unpacked.Answers[0].Header.TTL < 280 {
		t.Fatalf("unexpected aged wire reply: ID=0x%x answers=%+v", unpacked.ID, unpacked.Answers)
	}
}

func TestRegressionJSONEmptySlicesNeverNull(t *testing.T) {
	// 1. Kernel SelectGroups & Groups from empty dynamic group
	srv, err := Start(Config{
		Inbounds:  []Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0", Name: "in"}},
		Outbounds: []OutboundConfig{{Name: "node1", Type: "socks5", Server: "127.0.0.1", Port: 1080}},
		Groups:    []GroupConfig{{Name: "EmptyDynamic", Type: "select", IncludeAll: true, Filter: "never-matches-xyz"}},
		Routing:   &RoutingOptions{Final: "direct"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close(context.Background())

	b1, err := json.Marshal(srv.SelectGroups())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b1), ":null") {
		t.Fatalf("SelectGroups marshaled :null slice: %s", string(b1))
	}
	b1g, err := json.Marshal(srv.Stats())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b1g), ":null") {
		t.Fatalf("Stats marshaled :null slice: %s", string(b1g))
	}

	// 2. tunplatform.SafeDiagnostic with Removal.Rows == nil
	diag := tunplatform.SafeDiagnostic(tunplatform.Diagnostic{
		Stage:   "cleanup_gone",
		Removal: &tunplatform.RemovalObservation{Rows: nil},
	})
	b2, err := json.Marshal(diag)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b2), `"rows":null`) || strings.Contains(string(b2), `"changes":null`) || !strings.Contains(string(b2), `"rows":[]`) {
		t.Fatalf("SafeDiagnostic marshaled :null slice: %s", string(b2))
	}

	// 3. outbound/group emptyGroup.Snapshot()
	eg, err := group.New(group.Options{Name: "empty", Type: group.TypeSelect, IncludeAll: true}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b3, err := json.Marshal(eg.(group.Snapshotter).Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b3), ":null") {
		t.Fatalf("emptyGroup.Snapshot() marshaled :null slice: %s", string(b3))
	}
}

func BenchmarkDNSGatewayWireCacheHit(b *testing.B) {
	capEntries := 512
	r, err := newInternalDNS(&DNSOptions{Servers: []string{"udp://127.0.0.1:5353"}, CacheEntries: &capEntries})
	if err != nil {
		b.Fatal(err)
	}
	defer r.close()
	qWire, q, _ := dnsQuestion("wirebench.example.com", dnsmessage.TypeA)
	ans := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 1, Response: true},
		Questions: []dnsmessage.Question{q},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
			Body:   &dnsmessage.AResource{A: [4]byte{93, 184, 216, 34}},
		}},
	}
	packed, _ := ans.Pack()
	slots, _ := scanDNSTTLSlotsInto(packed, nil)
	now := time.Now()
	r.wireCache[string(qWire[2:])] = dnsWireEntry{
		wire:     packed,
		ttlSlots: slots,
		server:   "UDP 1.1.1.1",
		added:    now,
		expires:  now.Add(5 * time.Minute),
		epoch:    r.dnsEpoch(),
	}
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := r.gateway(ctx, qWire, false)
		if err != nil || len(out) < 12 {
			b.Fatal(err)
		}
	}
}

func BenchmarkClientLogThrottleStorm(b *testing.B) {
	srv := &Server{core: &core{}}
	var emitted atomic.Int64
	srv.cfg.clientLog = func(ClientLogEvent) { emitted.Add(1) }
	ctx := context.Background()
	errSample := errors.New("i/o timeout")
	start := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			srv.runtimeFailure(ctx, "dial", "timeout", errSample, start)
		}
	})
}
