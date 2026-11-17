package kernel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"golang.org/x/net/dns/dnsmessage"
)

const testDNSTypeHTTPS = dnsmessage.Type(65)

func buildDNSQueryEDNS(t *testing.T, id uint16, name string, qtype dnsmessage.Type, udpSize uint16) []byte {
	t.Helper()
	m := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(strings.TrimSuffix(name, ".") + "."),
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
		Additionals: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.TypeOPT,
				Class: dnsmessage.Class(udpSize),
			},
			Body: &dnsmessage.OPTResource{},
		}},
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func buildRawSNITLSRecord(rawSNI string) []byte {
	nameBytes := []byte(rawSNI)
	var list []byte
	list = append(list, 0x00)
	list = binary.BigEndian.AppendUint16(list, uint16(len(nameBytes)))
	list = append(list, nameBytes...)

	var extData []byte
	extData = binary.BigEndian.AppendUint16(extData, uint16(len(list)))
	extData = append(extData, list...)

	var exts []byte
	exts = binary.BigEndian.AppendUint16(exts, 0x0000)
	exts = binary.BigEndian.AppendUint16(exts, uint16(len(extData)))
	exts = append(exts, extData...)

	var body []byte
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	rec = append(rec, hs...)
	return rec
}

func buildQUICInitialRawSNI(t *testing.T, rawSNI string) []byte {
	t.Helper()
	hs := buildRawSNITLSRecord(rawSNI)[5:]
	var frames []byte
	frames = append(frames, 0x06) // CRYPTO frame
	frames = appendQV(frames, 0)
	frames = appendQV(frames, uint64(len(hs)))
	frames = append(frames, hs...)

	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
	initSec, _ := hkdf.Extract(sha256.New, dcid, salt)
	cSec := quicLabel(initSec, "client in", 32)
	key := quicLabel(cSec, "quic key", 16)
	iv := quicLabel(cSec, "quic iv", 12)
	hp := quicLabel(cSec, "quic hp", 16)

	for len(frames)+16 < 1180 {
		frames = append(frames, 0x00) // PADDING
	}
	pn := uint32(1)
	var hdr []byte
	hdr = append(hdr, 0xc3) // Long Header Initial + 4-byte PN
	hdr = binary.BigEndian.AppendUint32(hdr, 0x00000001)
	hdr = append(hdr, byte(len(dcid)))
	hdr = append(hdr, dcid...)
	hdr = append(hdr, 0x00) // SCID len 0
	hdr = append(hdr, 0x00) // Token len 0
	hdr = appendQV(hdr, uint64(4+len(frames)+16))
	pnOff := len(hdr)
	hdr = binary.BigEndian.AppendUint32(hdr, pn)

	nonce := append([]byte(nil), iv...)
	binary.BigEndian.PutUint32(nonce[8:], binary.BigEndian.Uint32(nonce[8:])^pn)
	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		t.Fatal(err)
	}
	pkt := aead.Seal(hdr, nonce, frames, hdr)

	hpBlk, err := aes.NewCipher(hp)
	if err != nil {
		t.Fatal(err)
	}
	var mask [16]byte
	hpBlk.Encrypt(mask[:], pkt[pnOff+4:pnOff+20])
	pkt[0] ^= mask[0] & 0x0f
	for i := 0; i < 4; i++ {
		pkt[pnOff+i] ^= mask[1+i]
	}
	return pkt
}

func hasOPTRecord(m dnsmessage.Message) bool {
	for _, rr := range m.Additionals {
		if rr.Header.Type == dnsmessage.TypeOPT {
			return true
		}
	}
	return false
}

// 1. Epoch switch / ClearDNSCache / Reload config generation & stale in-flight writeback rejection
func TestDNSHostEpochClearReloadAndStaleInFlight(t *testing.T) {
	proxyPort, _ := startMockSOCKS5Server(t, func(_ string, _ uint16, c net.Conn) {
		_, _ = io.Copy(c, c)
	})

	var curEpoch atomic.Uint64
	curEpoch.Store(1)

	type gate struct {
		entered chan struct{}
		release chan struct{}
	}
	var gateMu sync.Mutex
	gates := map[string]*gate{}
	setGate := func(domain string) *gate {
		g := &gate{entered: make(chan struct{}), release: make(chan struct{})}
		gateMu.Lock()
		gates[domain] = g
		gateMu.Unlock()
		return g
	}
	getGate := func(domain string) *gate {
		gateMu.Lock()
		defer gateMu.Unlock()
		return gates[domain]
	}

	directDNSFix := newDNSFixture(t, func(w []byte) []byte {
		return dnsReply(w, []string{"198.51.100.11"}, 120)
	})

	mkCfg := func(hosts DNSHosts) Config {
		c := socksCfg("127.0.0.1:0")
		c.Inbounds = []Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0", Name: "kat-client"}}
		c.Outbounds = []OutboundConfig{{Name: "proxy-out", Type: "socks5", Server: "127.0.0.1", Port: proxyPort}}
		c.Routing = &RoutingOptions{
			Rules: []RouteRule{{DomainSuffix: "mapped.example", Outbound: "proxy-out"}},
			Final: "reject",
		}
		srcDNS := &DNSOptions{
			Server: "system",
			Hosts:  hosts,
			Rules:  []DNSRule{{Match: "domain_suffix", Domain: "rule.example", Servers: []string{directDNSFix.address()}}},
		}
		c.DNS = srcDNS
		c.SetClientDNSConfig(srcDNS, nil, "rule", "direct")
		c.SetClientEgress(&ClientEgress{
			Active: func() bool { return true },
			DNSContext: func(ctx context.Context) (context.Context, func(), uint64) {
				return ctx, func() {}, curEpoch.Load()
			},
			Bootstrap: func(_ context.Context, _, host string) ([]netip.Addr, error) {
				if g := getGate(strings.ToLower(host)); g != nil {
					select {
					case <-g.entered:
					default:
						close(g.entered)
					}
					<-g.release
				}
				return []netip.Addr{netip.MustParseAddr("198.51.100.21")}, nil
			},
			SystemQuery: func(_ context.Context, wire []byte) ([]byte, error) {
				var qm dnsmessage.Message
				_ = qm.Unpack(wire)
				q := qm.Questions[0]
				name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
				if g := getGate(name); g != nil {
					select {
					case <-g.entered:
					default:
						close(g.entered)
					}
					<-g.release
				}
				r := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
				ip := [4]byte{198, 51, 100, 31}
				switch name {
				case "epoch1-inflight.mapped.example":
					ip = [4]byte{198, 51, 100, 32}
				case "clear-inflight.mapped.example":
					ip = [4]byte{198, 51, 100, 33}
				case "reload-inflight.mapped.example":
					ip = [4]byte{198, 51, 100, 34}
				}
				r.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 180},
					Body:   &dnsmessage.AResource{A: ip},
				}}
				return r.Pack()
			},
		})
		return c
	}

	baseCfg := mkCfg(nil)
	s, err := Start(baseCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	client := socksClient(t, s)
	ctx := context.Background()

	// Seed epoch=1 mapping and verify pure-IP routing succeeds
	if _, err := s.answerDNS(ctx, buildDNSQuery(t, 0x7001, "live1.mapped.example", dnsmessage.TypeA), false); err != nil {
		t.Fatal(err)
	}
	if !sendFirst(t, client, outbound.Addr{Host: "198.51.100.31", Port: 22}, []byte("ping")) {
		t.Fatal("expected epoch=1 mapped IP 198.51.100.31 to route via proxy-out")
	}

	// Subcase A: In-flight query across network epoch change (1 -> 2)
	gEpoch := setGate("epoch1-inflight.mapped.example")
	doneEpoch := make(chan error, 1)
	go func() {
		_, e := s.answerDNS(ctx, buildDNSQuery(t, 0x7002, "epoch1-inflight.mapped.example", dnsmessage.TypeA), false)
		doneEpoch <- e
	}()
	<-gEpoch.entered
	curEpoch.Store(2)
	close(gEpoch.release)
	if err := <-doneEpoch; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if got := s.lookupDNSHost(netip.MustParseAddr("198.51.100.31")); got != "" {
		t.Fatalf("epoch-1 mapping survived epoch switch: %q", got)
	}
	if got := s.lookupDNSHost(netip.MustParseAddr("198.51.100.32")); got != "" {
		t.Fatalf("stale epoch-1 in-flight query wrote back into epoch-2 dnsHosts: %q", got)
	}
	if sendFirst(t, client, outbound.Addr{Host: "198.51.100.32", Port: 22}, []byte("ping")) {
		t.Fatal("stale epoch-1 in-flight IP should hit Final=reject on epoch 2")
	}

	// Subcase B: ClearDNSCache invalidates multi-resolvers + dnsHosts + blocks in-flight pre-clear writeback
	if _, err := s.answerDNS(ctx, buildDNSQuery(t, 0x7003, "sub.rule.example", dnsmessage.TypeA), false); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.current().directDNS.lookupAnswer(ctx, "direct-cache.example"); err != nil {
		t.Fatal(err)
	}
	gClear := setGate("clear-inflight.mapped.example")
	doneClear := make(chan error, 1)
	go func() {
		_, e := s.answerDNS(ctx, buildDNSQuery(t, 0x7004, "clear-inflight.mapped.example", dnsmessage.TypeA), false)
		doneClear <- e
	}()
	<-gClear.entered
	if _, err := s.ClearDNSCache(); err != nil {
		t.Fatal(err)
	}
	close(gClear.release)
	if err := <-doneClear; err != nil {
		t.Fatal(err)
	}
	if got := s.lookupDNSHost(netip.MustParseAddr("198.51.100.33")); got != "" {
		t.Fatalf("pre-ClearDNSCache in-flight query wrote back after ClearDNSCache: %q", got)
	}
	items, _, err := s.ListDNSCache()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 0 {
		t.Fatalf("expected all resolvers + wireCache empty after ClearDNSCache and stale in-flight completion, got %+v", items)
	}

	// Subcase C: Hot reload with DNS/hosts config change bumps generation & blocks pre-reload in-flight writeback
	if _, err := s.answerDNS(ctx, buildDNSQuery(t, 0x7005, "live2.mapped.example", dnsmessage.TypeA), false); err != nil {
		t.Fatal(err)
	}
	if got := s.lookupDNSHost(netip.MustParseAddr("198.51.100.31")); got != "live2.mapped.example" {
		t.Fatalf("expected live2.mapped.example before reload, got %q", got)
	}
	gReload := setGate("reload-inflight.mapped.example")
	doneReload := make(chan error, 1)
	go func() {
		_, e := s.answerDNS(ctx, buildDNSQuery(t, 0x7006, "reload-inflight.mapped.example", dnsmessage.TypeA), false)
		doneReload <- e
	}()
	<-gReload.entered
	nextCfg := mkCfg(DNSHosts{"local.override.example": {"198.51.100.99"}})
	if _, err := s.ApplyConfig(nextCfg); err != nil {
		t.Fatal(err)
	}
	close(gReload.release)
	if err := <-doneReload; err != nil {
		t.Fatal(err)
	}
	if got := s.lookupDNSHost(netip.MustParseAddr("198.51.100.31")); got != "" {
		t.Fatalf("pre-reload mapping survived DNS config reload: %q", got)
	}
	if got := s.lookupDNSHost(netip.MustParseAddr("198.51.100.34")); got != "" {
		t.Fatalf("pre-reload in-flight query wrote back into post-reload dnsHosts: %q", got)
	}
}

// 2. Ambiguity conflict, remaining-TTL cache hit, CNAME chain min TTL, cloudflare-ech rejection & bootstrap mapping
func TestDNSHostAmbiguityTTLCNAMEWireCacheAndBootstrap(t *testing.T) {
	proxyPort, _ := startMockSOCKS5Server(t, func(_ string, _ uint16, c net.Conn) {
		_, _ = io.Copy(c, c)
	})

	var nowMu sync.Mutex
	curNow := time.Now()
	nowFn := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return curNow
	}
	advance := func(d time.Duration) {
		nowMu.Lock()
		curNow = curNow.Add(d)
		nowMu.Unlock()
	}

	// Closed local UDP port to force upstream failure -> bootstrap fallback
	deadConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := deadConn.LocalAddr().String()
	_ = deadConn.Close()

	var eventsMu sync.Mutex
	var events []ConnectionEvent

	s := startTest(t, Inbound{Protocol: "socks5", Name: "kat-client"}, func(c *Config) {
		c.SetConnectionSink(func(ev ConnectionEvent) {
			eventsMu.Lock()
			events = append(events, ev)
			eventsMu.Unlock()
		})
		c.Outbounds = []OutboundConfig{{Name: "proxy-out", Type: "socks5", Server: "127.0.0.1", Port: proxyPort}}
		c.Routing = &RoutingOptions{
			Rules: []RouteRule{
				{DomainSuffix: "proxy.example", Outbound: "proxy-out"},
				{DomainSuffix: "direct.example", Action: "direct"},
			},
			Final: "reject",
		}
		c.SetClientDNSConfig(&DNSOptions{Servers: []string{"udp://" + deadAddr}}, nil, "rule", "direct")
		c.SetClientEgress(&ClientEgress{
			Active: func() bool { return true },
			Bootstrap: func(_ context.Context, _, host string) ([]netip.Addr, error) {
				if strings.EqualFold(host, "boot-fallback.proxy.example") {
					return []netip.Addr{netip.MustParseAddr("198.51.100.95")}, nil
				}
				return []netip.Addr{netip.MustParseAddr("198.51.100.96")}, nil
			},
			SystemQuery: func(_ context.Context, wire []byte) ([]byte, error) {
				var qm dnsmessage.Message
				_ = qm.Unpack(wire)
				q := qm.Questions[0]
				name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
				r := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
				switch name {
				case "cloudflare-ech.com", "sub.cloudflare-ech.com":
					r.Answers = []dnsmessage.Resource{{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300},
						Body:   &dnsmessage.AResource{A: [4]byte{104, 18, 10, 10}},
					}}
				case "cname-head.proxy.example":
					target := dnsmessage.MustNewName("edge.cdn.example.")
					r.Answers = []dnsmessage.Resource{
						{
							Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 70},
							Body:   &dnsmessage.CNAMEResource{CNAME: target},
						},
						{
							Header: dnsmessage.ResourceHeader{Name: target, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 600},
							Body:   &dnsmessage.AResource{A: [4]byte{198, 51, 100, 88}},
						},
					}
				case "cache-rem.proxy.example":
					r.Answers = []dnsmessage.Resource{{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
						Body:   &dnsmessage.AResource{A: [4]byte{198, 51, 100, 89}},
					}}
				case "alpha.proxy.example", "beta.direct.example", "gamma.proxy.example":
					r.Answers = []dnsmessage.Resource{{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 90},
						Body:   &dnsmessage.AResource{A: [4]byte{198, 51, 100, 200}},
					}}
				}
				return r.Pack()
			},
		})
	})

	s.core.dnsHosts.now = nowFn
	g := s.current()
	g.dns.now = nowFn
	if g.directDNS != nil {
		g.directDNS.now = nowFn
	}
	ctx := context.Background()

	// 2a) cloudflare-ech.com & subdomains never enter dnsHosts
	for _, echName := range []string{"cloudflare-ech.com", "sub.cloudflare-ech.com"} {
		if _, err := s.answerDNS(ctx, buildDNSQuery(t, 0x7101, echName, dnsmessage.TypeA), false); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.lookupDNSHost(netip.MustParseAddr("104.18.10.10")); got != "" {
		t.Fatalf("cloudflare-ech.com polluted dnsHosts: %q", got)
	}

	// 2b) CNAME chain uses min TTL along chain (70s CNAME, not 600s A)
	if _, err := s.answerDNS(ctx, buildDNSQuery(t, 0x7102, "cname-head.proxy.example", dnsmessage.TypeA), false); err != nil {
		t.Fatal(err)
	}
	advance(50 * time.Second)
	if got := s.lookupDNSHost(netip.MustParseAddr("198.51.100.88")); got != "cname-head.proxy.example" {
		t.Fatalf("expected CNAME mapping active at +50s, got %q", got)
	}
	advance(25 * time.Second) // +75s > 70s CNAME TTL
	if got := s.lookupDNSHost(netip.MustParseAddr("198.51.100.88")); got != "" {
		t.Fatalf("expected CNAME mapping expired at +75s (min TTL 70s), got %q", got)
	}

	// 2c) wireCache hit maintains dnsHosts with remaining TTL (does not clamp up to +60s)
	if _, err := s.answerDNS(ctx, buildDNSQuery(t, 0x7103, "cache-rem.proxy.example", dnsmessage.TypeA), false); err != nil {
		t.Fatal(err)
	}
	advance(100 * time.Second) // 20s remaining in wireCache
	if _, err := s.answerDNS(ctx, buildDNSQuery(t, 0x7104, "cache-rem.proxy.example", dnsmessage.TypeA), false); err != nil {
		t.Fatal(err)
	}
	advance(25 * time.Second) // +125s > original 120s TTL; if clamped to +60s on cache hit it would still be alive at +160s!
	if got := s.lookupDNSHost(netip.MustParseAddr("198.51.100.89")); got != "" {
		t.Fatalf("wireCache hit illegally extended dnsHosts past remaining TTL: %q", got)
	}

	// 2d) internalDNS upstream failure -> bootstrap fallback populates dnsHosts
	ips, _, _, err := g.directDNS.lookupAnswer(ctx, "boot-fallback.proxy.example")
	if err != nil {
		// In this test g.directDNS has an explicit dead UDP upstream; verify via a non-policyOnly internalDNS with owner=s that bootstrap fallback populates dnsHosts!
		bootFallbackDNS, bErr := newInternalDNS(&DNSOptions{Servers: []string{"udp://" + deadAddr}})
		if bErr != nil {
			t.Fatal(bErr)
		}
		defer bootFallbackDNS.close()
		bootFallbackDNS.setOwner(s)
		bootFallbackDNS.now = nowFn
		bootFallbackDNS.configureIO(false, func(_ context.Context, _, host string) ([]netip.Addr, error) {
			if strings.EqualFold(host, "boot-fallback.proxy.example") {
				return []netip.Addr{netip.MustParseAddr("198.51.100.95")}, nil
			}
			return nil, errDNS
		}, (&net.Dialer{}).DialContext, nil)
		tctxBoot, cancelBoot := context.WithTimeout(ctx, 250*time.Millisecond)
		ips, _, _, err = bootFallbackDNS.lookupAnswer(tctxBoot, "boot-fallback.proxy.example")
		cancelBoot()
	}
	if err != nil || len(ips) != 1 || ips[0].String() != "198.51.100.95" {
		t.Fatalf("bootstrap fallback failed: ips=%v err=%v", ips, err)
	}
	if got := s.lookupDNSHost(netip.MustParseAddr("198.51.100.95")); got != "boot-fallback.proxy.example" {
		t.Fatalf("bootstrap fallback did not populate dnsHosts: got %q", got)
	}

	// 2e) Same IP active multi-domain -> ambiguous (neither routing nor panel may impersonate single domain)
	if _, err := s.answerDNS(ctx, buildDNSQuery(t, 0x7105, "alpha.proxy.example", dnsmessage.TypeA), false); err != nil {
		t.Fatal(err)
	}
	if got := s.lookupDNSHost(netip.MustParseAddr("198.51.100.200")); got != "alpha.proxy.example" {
		t.Fatalf("expected single domain alpha.proxy.example, got %q", got)
	}
	if _, err := s.answerDNS(ctx, buildDNSQuery(t, 0x7106, "beta.direct.example", dnsmessage.TypeA), false); err != nil {
		t.Fatal(err)
	}
	if got := s.lookupDNSHost(netip.MustParseAddr("198.51.100.200")); got != "" {
		t.Fatalf("colliding active domains must mark IP ambiguous (empty lookup), got %q", got)
	}
	client := socksClient(t, s)
	if sendFirst(t, client, outbound.Addr{Host: "198.51.100.200", Port: 22}, []byte("ping")) {
		t.Fatal("ambiguous IP must not match alpha.proxy.example rule; expected Final=reject")
	}
	eventsMu.Lock()
	for _, ev := range events {
		if strings.HasPrefix(ev.Target, "198.51.100.200:") && (ev.DestHost != "" || ev.Host != "") {
			eventsMu.Unlock()
			t.Fatalf("ambiguous IP leaked single-domain DestHost/Host into panel event: %+v", ev)
		}
	}
	eventsMu.Unlock()

	// After conflict window expires (+95s), fresh single domain cleanly claims the IP again
	advance(95 * time.Second)
	if _, err := s.answerDNS(ctx, buildDNSQuery(t, 0x7107, "gamma.proxy.example", dnsmessage.TypeA), false); err != nil {
		t.Fatal(err)
	}
	if got := s.lookupDNSHost(netip.MustParseAddr("198.51.100.200")); got != "gamma.proxy.example" {
		t.Fatalf("expected expired ambiguous slot to accept fresh gamma.proxy.example, got %q", got)
	}
}

// 3. Fallback TCP DNS protectedDNS direct-leaf fail-closed & static-proxy-only anti-poisoning (preserving AdGuard/Pi-hole/Refused/FakeIP)
func TestFallbackProtectedDirectLeafAndStaticProxyOnlyAntiPoison(t *testing.T) {
	var proxyDNSCalls atomic.Int32
	proxyPort, _ := startMockSOCKS5Server(t, func(host string, port uint16, c net.Conn) {
		if host != "1.1.1.1" || port != 53 {
			return
		}
		proxyDNSCalls.Add(1)
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		wire := make([]byte, int(binary.BigEndian.Uint16(lb[:])))
		if _, err := io.ReadFull(c, wire); err != nil {
			return
		}
		var qm dnsmessage.Message
		_ = qm.Unpack(wire)
		q := qm.Questions[0]
		r := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
		r.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 180},
			Body:   &dnsmessage.AResource{A: [4]byte{104, 18, 99, 1}},
		}}
		rb, _ := r.Pack()
		var out [2]byte
		binary.BigEndian.PutUint16(out[:], uint16(len(rb)))
		_, _ = c.Write(out[:])
		_, _ = c.Write(rb)
	})

	var directDialAttempts atomic.Int32
	var localMode atomic.Int32

	s := startTest(t, Inbound{Protocol: "socks5", Name: "kat-client"}, func(c *Config) {
		c.Outbounds = []OutboundConfig{{Name: "proxy-out", Type: "socks5", Server: "127.0.0.1", Port: proxyPort}}
		c.Groups = []GroupConfig{{Name: "auto-group", Type: "select", Members: []string{"direct", "proxy-out"}}}
		c.Routing = &RoutingOptions{
			Rules: []RouteRule{
				{DomainSuffix: "static-proxy.example", Outbound: "auto-group"},
				{IPCIDR: "10.99.0.0/16", Action: "direct"},
				{DomainSuffix: "after-unknown-ip.example", Outbound: "proxy-out"},
				{DomainSuffix: "explicit-direct.example", Action: "direct"},
			},
			Final: "proxy-out",
		}
		c.SetClientDNSConfig(nil, nil, "rule", "auto-group")
		c.SetClientEgress(&ClientEgress{
			Active:    func() bool { return true },
			Bootstrap: net.DefaultResolver.LookupNetIP,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if strings.HasSuffix(address, ":53") {
					directDialAttempts.Add(1)
				}
				return (&net.Dialer{}).DialContext(ctx, network, address)
			},
			SystemQuery: func(_ context.Context, wire []byte) ([]byte, error) {
				var qm dnsmessage.Message
				_ = qm.Unpack(wire)
				q := qm.Questions[0]
				switch localMode.Load() {
				case 0: // 127.0.0.1 blackhole
					r := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
					r.Answers = []dnsmessage.Resource{{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
						Body:   &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
					}}
					return r.Pack()
				case 1: // 0.0.0.0 AdGuard block
					r := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
					r.Answers = []dnsmessage.Resource{{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
						Body:   &dnsmessage.AResource{A: [4]byte{0, 0, 0, 0}},
					}}
					return r.Pack()
				case 2: // ClientFakeIP 198.18.0.42
					r := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
					r.Answers = []dnsmessage.Resource{{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
						Body:   &dnsmessage.AResource{A: [4]byte{198, 18, 0, 42}},
					}}
					return r.Pack()
				case 3: // RCodeRefused
					r := dnsGatewayReply(qm, dnsmessage.RCodeRefused)
					return r.Pack()
				case 4: // NXDOMAIN
					r := dnsGatewayReply(qm, dnsmessage.RCodeNameError)
					return r.Pack()
				default:
					return nil, errors.New("servfail")
				}
			},
		})
	})

	ctx := context.Background()

	// 3a) Group "auto-group" initially selects "direct": fallback TCP DNS MUST fail-closed without dialing direct 1.1.1.1:53!
	localMode.Store(0)
	repDirectLeaf, err := s.answerDNS(ctx, buildDNSQuery(t, 0x7201, "leaf-direct.static-proxy.example", dnsmessage.TypeA), false)
	if err != nil {
		t.Fatal(err)
	}
	if directDialAttempts.Load() != 0 || proxyDNSCalls.Load() != 0 {
		t.Fatalf("direct leaf in group must fail-closed on protectedDNS: directDials=%d proxyCalls=%d", directDialAttempts.Load(), proxyDNSCalls.Load())
	}
	mDirectLeaf := unpackDNSReply(t, repDirectLeaf)
	if len(mDirectLeaf.Answers) != 1 || netip.AddrFrom4(mDirectLeaf.Answers[0].Body.(*dnsmessage.AResource).A).String() != "127.0.0.1" {
		t.Fatalf("when fallback fails closed, local reply should be returned cleanly: %+v", mDirectLeaf.Answers)
	}

	// Switch "auto-group" to "proxy-out": now static-proxy domain recovers via proxy TCP DNS!
	if err := s.Select("auto-group", "proxy-out"); err != nil {
		t.Fatal(err)
	}
	repProxyLeaf, err := s.answerDNS(ctx, buildDNSQuery(t, 0x7202, "leaf-proxy.static-proxy.example", dnsmessage.TypeA), false)
	if err != nil {
		t.Fatal(err)
	}
	mProxyLeaf := unpackDNSReply(t, repProxyLeaf)
	if len(mProxyLeaf.Answers) != 1 || netip.AddrFrom4(mProxyLeaf.Answers[0].Body.(*dnsmessage.AResource).A).String() != "104.18.99.1" {
		t.Fatalf("expected clean proxy answer 104.18.99.1 after selecting proxy-out, got %+v", mProxyLeaf.Answers)
	}

	// 3b) Preceding unknown direct rule (IPCIDR -> direct) blocks anti-poison fallback!
	prevProxy := proxyDNSCalls.Load()
	localMode.Store(1) // 0.0.0.0
	repUnknown, err := s.answerDNS(ctx, buildDNSQuery(t, 0x7203, "test.after-unknown-ip.example", dnsmessage.TypeA), false)
	if err != nil {
		t.Fatal(err)
	}
	mUnknown := unpackDNSReply(t, repUnknown)
	if proxyDNSCalls.Load() != prevProxy || len(mUnknown.Answers) != 1 || netip.AddrFrom4(mUnknown.Answers[0].Body.(*dnsmessage.AResource).A).String() != "0.0.0.0" {
		t.Fatalf("domain after unknown IPCIDR direct rule must NOT trigger proxy fallback: proxyCalls=%d->%d ans=%+v", prevProxy, proxyDNSCalls.Load(), mUnknown.Answers)
	}

	// 3c) Explicit direct / ordinary / internal (.local, home.arpa) preserve FakeIP (198.18.0.42), Refused, NXDOMAIN, 0.0.0.0 without errFakeIP rejection!
	localMode.Store(2) // 198.18.0.42 FakeIP
	for _, dom := range []string{"app.explicit-direct.example", "nas.home.arpa", "printer.local", "unmatched-ordinary.example"} {
		repFake, err := s.answerDNS(ctx, buildDNSQuery(t, 0x7210, dom, dnsmessage.TypeA), false)
		if err != nil {
			t.Fatal(err)
		}
		mf := unpackDNSReply(t, repFake)
		if mf.RCode != dnsmessage.RCodeSuccess || len(mf.Answers) != 1 || netip.AddrFrom4(mf.Answers[0].Body.(*dnsmessage.AResource).A).String() != "198.18.0.42" {
			t.Fatalf("approved local FakeIP for %s was rejected or altered: rcode=%v ans=%+v", dom, mf.RCode, mf.Answers)
		}
	}

	localMode.Store(3) // RCodeRefused preserved verbatim!
	repRefused, err := s.answerDNS(ctx, buildDNSQuery(t, 0x7220, "refused-adguard.example", dnsmessage.TypeA), false)
	if err != nil {
		t.Fatal(err)
	}
	mRefused := unpackDNSReply(t, repRefused)
	if mRefused.RCode != dnsmessage.RCodeRefused || proxyDNSCalls.Load() != prevProxy {
		t.Fatalf("expected RCodeRefused preserved verbatim without fallback, got rcode=%v proxyCalls=%d->%d", mRefused.RCode, prevProxy, proxyDNSCalls.Load())
	}

	localMode.Store(4) // NXDOMAIN on ordinary domain preserved verbatim!
	repNX, err := s.answerDNS(ctx, buildDNSQuery(t, 0x7221, "missing.home.arpa", dnsmessage.TypeA), false)
	if err != nil {
		t.Fatal(err)
	}
	if unpackDNSReply(t, repNX).RCode != dnsmessage.RCodeNameError || proxyDNSCalls.Load() != prevProxy {
		t.Fatalf("expected NXDOMAIN preserved verbatim on internal domain")
	}
}

// 4. ECH strip before EDNS truncation, valid OPT on synthetic NODATA/NXDOMAIN/TC=1, unified budget & accurate single DNSEvent
func TestECHLargePayloadTruncationOPTAndUnifiedBudgetEvent(t *testing.T) {
	proxyPort, _ := startMockSOCKS5Server(t, func(host string, port uint16, c net.Conn) {
		if host != "1.1.1.1" || port != 53 {
			return
		}
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		wire := make([]byte, int(binary.BigEndian.Uint16(lb[:])))
		if _, err := io.ReadFull(c, wire); err != nil {
			return
		}
		var qm dnsmessage.Message
		_ = qm.Unpack(wire)
		q := qm.Questions[0]
		r := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
		r.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 200},
			Body:   &dnsmessage.AResource{A: [4]byte{104, 18, 88, 88}},
		}}
		rb, _ := r.Pack()
		var out [2]byte
		binary.BigEndian.PutUint16(out[:], uint16(len(rb)))
		_, _ = c.Write(out[:])
		_, _ = c.Write(rb)
	})

	var dnsEventsMu sync.Mutex
	var dnsEvents []DNSEvent

	s := startTest(t, Inbound{Protocol: "socks5", Name: "kat-client"}, func(c *Config) {
		c.SetDNSSink(func(ev DNSEvent) {
			dnsEventsMu.Lock()
			dnsEvents = append(dnsEvents, ev)
			dnsEventsMu.Unlock()
		})
		c.Outbounds = []OutboundConfig{{Name: "proxy-out", Type: "socks5", Server: "127.0.0.1", Port: proxyPort}}
		c.Routing = &RoutingOptions{
			Rules: []RouteRule{{DomainSuffix: "openai.com", Outbound: "proxy-out"}},
			Final: "direct",
		}
		c.SetClientDNSConfig(nil, nil, "rule", "proxy-out")
		c.SetClientEgress(&ClientEgress{
			Active:    func() bool { return true },
			Bootstrap: net.DefaultResolver.LookupNetIP,
			SystemQuery: func(qctx context.Context, wire []byte) ([]byte, error) {
				var qm dnsmessage.Message
				_ = qm.Unpack(wire)
				q := qm.Questions[0]
				name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
				switch name {
				case "ech-big.example.com":
					// 900-byte HTTPS RR + normal A RR: >512 before ECH strip, <120 after ECH strip!
					r := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
					r.Answers = []dnsmessage.Resource{{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 150},
						Body:   &dnsmessage.AResource{A: [4]byte{104, 18, 32, 7}},
					}}
					r.Additionals = []dnsmessage.Resource{{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET, TTL: 150},
						Body: &dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{
							Priority: 1,
							Target:   dnsmessage.MustNewName("."),
							Params:   []dnsmessage.SVCParam{{Key: 5, Value: bytes.Repeat([]byte{0xab}, 900)}},
						}},
					}}
					return r.Pack()
				case "huge-a.example.com":
					// 45 A records (>750 bytes) -> genuinely exceeds 512-byte EDNS UDP size
					r := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
					for i := 0; i < 45; i++ {
						r.Answers = append(r.Answers, dnsmessage.Resource{
							Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
							Body:   &dnsmessage.AResource{A: [4]byte{198, 51, 100, byte(i + 1)}},
						})
					}
					return r.Pack()
				case "slow-local.openai.com":
					// Hang until local sub-budget expires!
					<-qctx.Done()
					return nil, qctx.Err()
				default:
					r := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
					return r.Pack()
				}
			},
		})
	})

	ctx := context.Background()

	// 4a) Synthetic HTTPS NODATA & PTR NXDOMAIN carry OPT when request has EDNS0 OPT
	repHTTPS, err := s.answerDNS(ctx, buildDNSQueryEDNS(t, 0x7301, "app.example.com", testDNSTypeHTTPS, 1232), false)
	if err != nil {
		t.Fatal(err)
	}
	mHTTPS := unpackDNSReply(t, repHTTPS)
	if mHTTPS.RCode != dnsmessage.RCodeSuccess || len(mHTTPS.Answers) != 0 || !hasOPTRecord(mHTTPS) {
		t.Fatalf("synthetic HTTPS NODATA missing OPT or wrong RCode: %+v", mHTTPS)
	}

	repPTR, err := s.answerDNS(ctx, buildDNSQueryEDNS(t, 0x7302, "42.0.19.198.in-addr.arpa", dnsmessage.TypePTR, 1232), false)
	if err != nil {
		t.Fatal(err)
	}
	mPTR := unpackDNSReply(t, repPTR)
	if mPTR.RCode != dnsmessage.RCodeNameError || !hasOPTRecord(mPTR) {
		t.Fatalf("synthetic PTR NXDOMAIN missing OPT or wrong RCode: %+v", mPTR)
	}

	// 4b) ECH stripped BEFORE 512-byte EDNS truncation -> NOT truncated, A record preserved!
	repECHBig, err := s.answerDNS(ctx, buildDNSQueryEDNS(t, 0x7303, "ech-big.example.com", dnsmessage.TypeA, 512), false)
	if err != nil {
		t.Fatal(err)
	}
	mECHBig := unpackDNSReply(t, repECHBig)
	if mECHBig.Truncated || len(mECHBig.Answers) != 1 || netip.AddrFrom4(mECHBig.Answers[0].Body.(*dnsmessage.AResource).A).String() != "104.18.32.7" {
		t.Fatalf("ECH strip should prevent false TC=1 truncation: truncated=%v answers=%+v", mECHBig.Truncated, mECHBig.Answers)
	}

	// 4c) Genuine >512B reply with EDNS0 UDPSize=512 sets TC=1 AND includes valid OPT RR within 512B!
	repHuge, err := s.answerDNS(ctx, buildDNSQueryEDNS(t, 0x7304, "huge-a.example.com", dnsmessage.TypeA, 512), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(repHuge) > 512 {
		t.Fatalf("TC=1 truncated reply exceeded 512B EDNS limit: %d", len(repHuge))
	}
	mHuge := unpackDNSReply(t, repHuge)
	if !mHuge.Truncated || !hasOPTRecord(mHuge) {
		t.Fatalf("expected TC=1 with valid OPT RR, got truncated=%v opt=%v", mHuge.Truncated, hasOPTRecord(mHuge))
	}

	// 4d) Unified budget & single accurate DNSEvent when local DNS hangs past local sub-budget
	tctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	repBudget, err := s.answerDNS(tctx, buildDNSQuery(t, 0x7305, "slow-local.openai.com", dnsmessage.TypeA), false)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("expected fallback recovery within unified 500ms budget, got err=%v after %v", err, elapsed)
	}
	mBudget := unpackDNSReply(t, repBudget)
	if len(mBudget.Answers) != 1 || netip.AddrFrom4(mBudget.Answers[0].Body.(*dnsmessage.AResource).A).String() != "104.18.88.88" {
		t.Fatalf("expected fallback answer 104.18.88.88, got %+v", mBudget.Answers)
	}

	dnsEventsMu.Lock()
	var slowEvents []DNSEvent
	for _, ev := range dnsEvents {
		if ev.Name == "slow-local.openai.com" {
			slowEvents = append(slowEvents, ev)
		}
	}
	dnsEventsMu.Unlock()
	if len(slowEvents) != 1 || slowEvents[0].Outcome != "ok" || len(slowEvents[0].Addresses) != 1 || slowEvents[0].Addresses[0] != "104.18.88.88" || !strings.HasPrefix(slowEvents[0].Server, "TCP 1.1.1.1") {
		t.Fatalf("expected exactly 1 accurate final DNSEvent for slow-local.openai.com, got %+v", slowEvents)
	}
}

// 5. Sniff enabled=false config retention & raw "Mijia Cloud" SNI skip_domain blocking both override and DNS map fallback
func TestSniffDisabledRetainsConfigAndRawMijiaSkipFallback(t *testing.T) {
	// 5a) ValidateSkipDomains strict checks
	for _, invalid := range [][]string{
		{"+..."},
		{"*..."},
		{"..."},
		{"+. ."},
		{"+.a..b"},
		{"bad\x00ctrl"},
		{strings.Repeat("x", 254)},
	} {
		if err := ValidateSkipDomains(invalid); err == nil {
			t.Fatalf("ValidateSkipDomains unexpectedly accepted %q", invalid)
		}
	}
	if err := ValidateSkipDomains([]string{"Mijia Cloud", "+.push.apple.com"}); err != nil {
		t.Fatalf("ValidateSkipDomains rejected valid entries: %v", err)
	}

	// 5b) enabled=false retains SniffOptions on inbound metadata while keeping sniffing off
	echo := rcEchoTCP(t)
	sDisabled := startTest(t, Inbound{
		Protocol: "socks5",
		Name:     "kat-client",
		Sniff: &SniffOptions{
			Enabled:             false,
			OverrideDestination: true,
			TCPPorts:            strconv.Itoa(int(echo)),
			SkipDomain:          []string{"+.keep.example"},
		},
	}, func(c *Config) {
		c.Routing = &RoutingOptions{
			Rules: []RouteRule{{DomainSuffix: "blocked.example", Action: "reject"}},
			Final: "direct",
		}
	})
	im := inboundMetaOf(withInboundMeta(context.Background(), &sDisabled.current().cfg.Inbounds[0], sDisabled.Addresses()[0], &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 54321}))
	if im == nil || im.sniff == nil || im.sniff.Enabled || !im.sniff.OverrideDestination || len(im.sniff.SkipDomain) != 1 {
		t.Fatalf("enabled=false SniffOptions not retained on inboundMeta: %+v", im)
	}
	if !sendFirst(t, socksClient(t, sDisabled), outbound.Addr{Host: "127.0.0.1", Port: echo}, tlsHello(t, "sub.blocked.example")) {
		t.Fatal("enabled=false sniff still inspected TLS ClientHello and rejected connection")
	}

	// 5c) Raw "Mijia Cloud" TLS SNI & QUIC SNI hit DefaultSkipDomains -> forbid override AND forbid DNS reverse-map fallback!
	proxyAI, aiTargets := startMockSOCKS5Server(t, func(_ string, _ uint16, c net.Conn) { _, _ = io.Copy(c, c) })
	proxyRawIP, rawIPTargets := startMockSOCKS5Server(t, func(_ string, _ uint16, c net.Conn) { _, _ = io.Copy(c, c) })

	var connMu sync.Mutex
	var events []ConnectionEvent

	sMijia := startTest(t, Inbound{
		Protocol: "socks5",
		Name:     "kat-client",
		Sniff:    &SniffOptions{Enabled: true, TCPPorts: "443", UDPPorts: "443", OverrideDestination: true},
	}, func(c *Config) {
		c.SetConnectionSink(func(ev ConnectionEvent) {
			connMu.Lock()
			events = append(events, ev)
			connMu.Unlock()
		})
		c.Outbounds = []OutboundConfig{
			{Name: "ai-proxy", Type: "socks5", Server: "127.0.0.1", Port: proxyAI},
			{Name: "raw-ip-proxy", Type: "socks5", Server: "127.0.0.1", Port: proxyRawIP},
		}
		c.Routing = &RoutingOptions{
			Rules: []RouteRule{{DomainSuffix: "mapped-ai.example", Outbound: "ai-proxy"}},
			Final: "raw-ip-proxy",
		}
		c.SetClientDNSConfig(nil, nil, "rule", "direct")
		c.SetClientEgress(&ClientEgress{
			Active:    func() bool { return true },
			Bootstrap: net.DefaultResolver.LookupNetIP,
			SystemQuery: func(_ context.Context, wire []byte) ([]byte, error) {
				var qm dnsmessage.Message
				_ = qm.Unpack(wire)
				q := qm.Questions[0]
				r := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
				r.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 180},
					Body:   &dnsmessage.AResource{A: [4]byte{198, 51, 100, 120}},
				}}
				return r.Pack()
			},
		})
	})

	// Populate dnsHosts: 198.51.100.120 -> mapped-ai.example
	if _, err := sMijia.answerDNS(context.Background(), buildDNSQuery(t, 0x7401, "sub.mapped-ai.example", dnsmessage.TypeA), false); err != nil {
		t.Fatal(err)
	}
	// Send TLS ClientHello with raw SNI "Mijia Cloud" to 198.51.100.120:443
	if !sendFirst(t, socksClient(t, sMijia), outbound.Addr{Host: "198.51.100.120", Port: 443}, buildRawSNITLSRecord("Mijia Cloud")) {
		t.Fatal("Mijia Cloud connection failed")
	}
	if len(aiTargets()) != 0 {
		t.Fatalf("Mijia Cloud illegally fell back to mapped-ai.example route: %v", aiTargets())
	}
	if gots := rawIPTargets(); len(gots) != 1 || gots[0] != "198.51.100.120:443" {
		t.Fatalf("expected Mijia Cloud to route via Final raw-ip-proxy with raw IP 198.51.100.120:443, got %v", gots)
	}
	connMu.Lock()
	for _, ev := range events {
		if strings.HasPrefix(ev.Target, "198.51.100.120:") && (ev.DestHost != "" || ev.Host != "") {
			connMu.Unlock()
			t.Fatalf("Mijia Cloud flow leaked mapped DestHost/Host: %+v", ev)
		}
	}
	connMu.Unlock()
}

type recordUDPPacketConn struct {
	mu      sync.Mutex
	targets []string
	closed  chan struct{}
	once    sync.Once
}

func newRecordUDPPacketConn() *recordUDPPacketConn {
	return &recordUDPPacketConn{closed: make(chan struct{})}
}
func (r *recordUDPPacketConn) ReadFrom([]byte) (int, outbound.Addr, error) {
	<-r.closed
	return 0, outbound.Addr{}, net.ErrClosed
}
func (r *recordUDPPacketConn) WriteTo(b []byte, addr outbound.Addr) (int, error) {
	r.mu.Lock()
	r.targets = append(r.targets, net.JoinHostPort(addr.Host, strconv.Itoa(int(addr.Port))))
	r.mu.Unlock()
	return len(b), nil
}
func (r *recordUDPPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (r *recordUDPPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (r *recordUDPPacketConn) Close() error {
	r.once.Do(func() { close(r.closed) })
	return nil
}
func (r *recordUDPPacketConn) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.targets...)
}

type recordUDPOutbound struct {
	outbound.Outbound
	pc *recordUDPPacketConn
}

func (o recordUDPOutbound) UDP() bool { return true }
func (o recordUDPOutbound) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return o.pc, nil
}

// 6. TUN direct UDP original IP preservation, UDP per-packet sniffHost & shared-NAT clearing, and accurate RemoteDNS
func TestUDPOriginalIPPanelTargetClearingAndRemoteDNS(t *testing.T) {
	proxyPort, tcpTargets := startMockSOCKS5Server(t, func(_ string, _ uint16, c net.Conn) {
		_, _ = io.Copy(c, c)
	})

	var records c49DNSRecords
	wrongDNS := newDNSFixture(t, func(w []byte) []byte {
		// If TUN direct UDP mistakenly resolves sniffed SNI "quic.override.example", it would send to 203.0.113.250 instead of original 203.0.113.77!
		return dnsReply(w, []string{"203.0.113.250"}, 120)
	})

	s := c50Server(t, &records, func(c *Config) {
		c.Inbounds[0].Sniff = &SniffOptions{Enabled: true, TCPPorts: "443", UDPPorts: "443", OverrideDestination: true}
		c.DNS = &DNSOptions{Server: wrongDNS.address()}
		c.Outbounds = []OutboundConfig{{Name: "proxy-out", Type: "socks5", Server: "127.0.0.1", Port: proxyPort}}
		c.Routing = &RoutingOptions{
			Rules: []RouteRule{
				{DomainSuffix: "mapped-only.example", Outbound: "proxy-out"},
				{DomainSuffix: "sniff-proxy.example", Outbound: "proxy-out"},
				{DomainSuffix: "quic.override.example", Action: "direct"},
			},
			Final: "direct",
		}
	})

	// Seed dnsHosts mapping: 198.51.100.70 -> mapped-only.example
	s.recordDNSResolved("mapped-only.example", []netip.Addr{netip.MustParseAddr("198.51.100.70")}, 120*time.Second, false, s.beginDNSHostScope())

	client := socksClient(t, s)
	// 6a) TCP via DNS map (raw IP 198.51.100.70:22 -> proxy-out): dial target stays IP -> RemoteDNS MUST be false!
	if !sendFirst(t, client, outbound.Addr{Host: "198.51.100.70", Port: 22}, []byte("ssh-banner")) {
		t.Fatal("mapped IP TCP dial failed")
	}
	// 6b) TCP via sniff override (raw IP 198.51.100.71:443 + TLS SNI sub.sniff-proxy.example -> proxy-out): dial target becomes domain -> RemoteDNS MUST be true!
	if !sendFirst(t, client, outbound.Addr{Host: "198.51.100.71", Port: 443}, tlsHello(t, "sub.sniff-proxy.example")) {
		t.Fatal("sniff-overridden TCP dial failed")
	}
	gotsTCP := tcpTargets()
	if len(gotsTCP) != 2 || gotsTCP[0] != "198.51.100.70:22" || gotsTCP[1] != "sub.sniff-proxy.example:443" {
		t.Fatalf("unexpected TCP proxy targets: %v", gotsTCP)
	}

	waitFor(t, func() bool {
		records.mu.Lock()
		defer records.mu.Unlock()
		n := 0
		for _, ev := range records.events {
			if ev.Ended && ev.Network == "tcp" {
				n++
			}
		}
		return n >= 2
	})
	records.mu.Lock()
	var sawMappedRemoteFalse, sawSniffRemoteTrue bool
	for _, ev := range records.events {
		if !ev.Ended || ev.Network != "tcp" {
			continue
		}
		if ev.DestHost == "mapped-only.example" {
			if ev.RemoteDNS || ev.Sniffed {
				records.mu.Unlock()
				t.Fatalf("mapped IP dial must have RemoteDNS=false & Sniffed=false, got %+v", ev)
			}
			sawMappedRemoteFalse = true
		}
		if ev.DestHost == "sub.sniff-proxy.example" {
			if !ev.RemoteDNS || !ev.Sniffed {
				records.mu.Unlock()
				t.Fatalf("sniff-overridden domain dial must have RemoteDNS=true & Sniffed=true, got %+v", ev)
			}
			sawSniffRemoteTrue = true
		}
	}
	records.mu.Unlock()
	if !sawMappedRemoteFalse || !sawSniffRemoteTrue {
		t.Fatalf("missing expected TCP RemoteDNS events: mappedFalse=%v sniffTrue=%v", sawMappedRemoteFalse, sawSniffRemoteTrue)
	}

	// 6c) TUN direct UDP with QUIC Initial SNI "quic.override.example" & override_destination=true:
	// MUST preserve original public IP 203.0.113.77:443 (NOT resolve quic.override.example -> 203.0.113.250)!
	// And when a second peer 203.0.113.78:443 shares the TUN NAT session, single-target DestHost/DestIP/Sniffed MUST be cleared!
	recDirectPC := newRecordUDPPacketConn()
	s.rt.nodes["direct"] = recordUDPOutbound{Outbound: s.rt.nodes["direct"], pc: recDirectPC}

	u := m2State(t, s)
	u.a.ctx = withInboundMeta(u.a.ctx, &s.current().cfg.Inbounds[0], nil, &net.UDPAddr{IP: net.IPv4(10, 50, 0, 2), Port: 41444})
	quicPkt := buildQUICInitialRawSNI(t, "quic.override.example")
	ctxQUIC := withSniff(u.a.ctx, s.cfg.Inbounds[0].Sniff.applyResult("quic", "quic.override.example"))

	u.send(ctxQUIC, packet{target: Address{Host: "203.0.113.77", Port: 443}, payload: quicPkt}, time.Second)
	udpTargets := recDirectPC.snapshot()
	if len(udpTargets) != 1 || udpTargets[0] != "203.0.113.77:443" {
		t.Fatalf("TUN direct UDP rewrote public destination IP on sniff override: got %v, want [203.0.113.77:443]", udpTargets)
	}

	var ses *tunNATSession
	for _, v := range u.sessions {
		ses = v
	}
	if ses == nil {
		t.Fatal("missing TUN NAT session")
	}
	ciSingle := ses.f.info(time.Now())
	if ciSingle.DestHost != "quic.override.example" || !ciSingle.Sniffed || ciSingle.RemoteDNS {
		t.Fatalf("unexpected single-peer TUN UDP flow details: %+v", ciSingle)
	}

	// Send second packet on same NAT session (both hit Final=direct -> rule=0) to different peer 203.0.113.78:443 -> shared session clears stale single-target fields!
	u.send(u.a.ctx, packet{target: Address{Host: "203.0.113.78", Port: 443}, payload: []byte("plain-udp-1")}, time.Second)
	u.send(u.a.ctx, packet{target: Address{Host: "203.0.113.79", Port: 443}, payload: []byte("plain-udp-2")}, time.Second)
	var sharedSes *tunNATSession
	for k, v := range u.sessions {
		if k.rule == 0 {
			sharedSes = v
		}
	}
	if sharedSes == nil {
		t.Fatal("missing Final=direct shared TUN NAT session")
	}
	ciShared := sharedSes.f.info(time.Now())
	if ciShared.Target != "udp-association" || ciShared.Host != "" || ciShared.DestHost != "" || ciShared.DestIP != "" || ciShared.Sniffed {
		t.Fatalf("shared TUN UDP session retained stale single-target metadata: %+v", ciShared)
	}

	// 6d) Real SOCKS5 UDP association: packet 1 to mapped IP 198.51.100.70 sets DestHost="mapped-only.example", packet 2 to unmapped IP 198.51.100.79 clears stale DestHost!
	recProxyPC := newRecordUDPPacketConn()
	s.rt.nodes["proxy-out"] = recordUDPOutbound{Outbound: s.rt.nodes["proxy-out"], pc: recProxyPC}
	udpCli, err := client.ListenPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer udpCli.Close()

	if _, err := udpCli.WriteTo([]byte("pkt1"), outbound.Addr{Host: "198.51.100.70", Port: 9000}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(recProxyPC.snapshot()) >= 1 })
	if pTargets := recProxyPC.snapshot(); pTargets[0] != "198.51.100.70:9000" {
		t.Fatalf("UDP proxy target rewrote mapped IP: %v", pTargets)
	}
	active1, _ := s.ClientConnections(20)
	var sawMappedUDP bool
	for _, ci := range active1 {
		if ci.Network == "udp" && ci.DestHost == "mapped-only.example" && !ci.RemoteDNS {
			sawMappedUDP = true
		}
	}
	if !sawMappedUDP {
		t.Fatalf("expected active SOCKS5 UDP flow with mapped DestHost=mapped-only.example and RemoteDNS=false, got %+v", active1)
	}

	if _, err := udpCli.WriteTo([]byte("pkt2"), outbound.Addr{Host: "198.51.100.79", Port: 9000}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		active2, _ := s.ClientConnections(20)
		for _, ci := range active2 {
			if ci.Network == "udp" && ci.DestIP == "198.51.100.79" && ci.DestHost == "" {
				return true
			}
		}
		return false
	})
}
