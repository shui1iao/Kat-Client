package kernel

import (
	"context"
	"encoding/binary"
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

func buildDNSQuery(t *testing.T, id uint16, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	m := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(strings.TrimSuffix(name, ".") + "."),
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
	}
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unpackDNSReply(t *testing.T, b []byte) dnsmessage.Message {
	t.Helper()
	var m dnsmessage.Message
	if err := m.Unpack(b); err != nil {
		t.Fatalf("unpack DNS reply: %v", err)
	}
	return m
}

// startMockSOCKS5Server starts a minimal SOCKS5 server recording requested target
// host:port strings and dispatching connections via handler(targetHost, targetPort, conn).
func startMockSOCKS5Server(t *testing.T, handler func(host string, port uint16, c net.Conn)) (uint16, func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var mu sync.Mutex
	var targets []string

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var hdr [2]byte
				if _, err := io.ReadFull(conn, hdr[:]); err != nil || hdr[0] != 0x05 {
					return
				}
				methods := make([]byte, int(hdr[1]))
				if _, err := io.ReadFull(conn, methods); err != nil {
					return
				}
				_, _ = conn.Write([]byte{0x05, 0x00})

				var req [4]byte
				if _, err := io.ReadFull(conn, req[:]); err != nil || req[0] != 0x05 || req[1] != 0x01 {
					return
				}
				var host string
				switch req[3] {
				case 0x01:
					var ip4 [4]byte
					if _, err := io.ReadFull(conn, ip4[:]); err != nil {
						return
					}
					host = netip.AddrFrom4(ip4).String()
				case 0x03:
					var l [1]byte
					if _, err := io.ReadFull(conn, l[:]); err != nil {
						return
					}
					d := make([]byte, int(l[0]))
					if _, err := io.ReadFull(conn, d); err != nil {
						return
					}
					host = string(d)
				case 0x04:
					var ip6 [16]byte
					if _, err := io.ReadFull(conn, ip6[:]); err != nil {
						return
					}
					host = netip.AddrFrom16(ip6).String()
				default:
					return
				}
				var pb [2]byte
				if _, err := io.ReadFull(conn, pb[:]); err != nil {
					return
				}
				port := binary.BigEndian.Uint16(pb[:])
				mu.Lock()
				targets = append(targets, net.JoinHostPort(host, strconv.Itoa(int(port))))
				mu.Unlock()

				_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})
				handler(host, port, conn)
			}(c)
		}
	}()

	return uint16(ln.Addr().(*net.TCPAddr).Port), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), targets...)
	}
}

// 1. TUN DNS HTTPS (TYPE 65) / SVCB NODATA + DNSEvent & Additionals/Answers ECH stripping
func TestTUNDNSECHBlockingAndStripping(t *testing.T) {
	var upstreamCalls atomic.Int32
	var mu sync.Mutex
	var events []DNSEvent

	s := startTest(t, Inbound{Protocol: "socks5", Name: "kat-client"}, func(c *Config) {
		c.SetDNSSink(func(ev DNSEvent) {
			mu.Lock()
			events = append(events, ev)
			mu.Unlock()
		})
		c.SetClientDNSConfig(nil, nil, "rule", "direct")
		c.SetClientEgress(&ClientEgress{
			Active:    func() bool { return true },
			Bootstrap: net.DefaultResolver.LookupNetIP,
			SystemQuery: func(_ context.Context, wire []byte) ([]byte, error) {
				upstreamCalls.Add(1)
				var qm dnsmessage.Message
				_ = qm.Unpack(wire)
				q := qm.Questions[0]
				reply := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
				reply.Answers = []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
						Body:   &dnsmessage.AResource{A: [4]byte{104, 18, 32, 47}},
					},
					{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET, TTL: 120},
						Body:   &dnsmessage.UnknownResource{Type: dnsmessage.TypeHTTPS, Data: []byte{0, 1, 0}},
					},
				}
				reply.Additionals = []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeSVCB, Class: dnsmessage.ClassINET, TTL: 120},
						Body:   &dnsmessage.UnknownResource{Type: dnsmessage.TypeSVCB, Data: []byte{0, 1, 0}},
					},
				}
				return reply.Pack()
			},
		})
	})

	ctx := context.Background()
	for _, qt := range []dnsmessage.Type{dnsmessage.TypeHTTPS, dnsmessage.TypeSVCB} {
		q := buildDNSQuery(t, 0x1234, "chatgpt.com", qt)
		replyBytes, err := s.answerDNS(ctx, q, false)
		if err != nil {
			t.Fatalf("type %v failed: %v", qt, err)
		}
		m := unpackDNSReply(t, replyBytes)
		if m.RCode != dnsmessage.RCodeSuccess || len(m.Answers) != 0 {
			t.Fatalf("expected empty NODATA RCodeSuccess, got rcode=%v answers=%d", m.RCode, len(m.Answers))
		}
	}
	if upstreamCalls.Load() != 0 {
		t.Fatalf("HTTPS/SVCB must not hit upstream, got %d calls", upstreamCalls.Load())
	}

	mu.Lock()
	if len(events) != 2 || events[0].Server != "ECH 已屏蔽" || events[0].Outcome != "nodata" || events[0].QType != "HTTPS" || events[1].QType != "SVCB" {
		t.Fatalf("unexpected ECH block DNSEvents: %+v", events)
	}
	mu.Unlock()

	// TypeA query with HTTPS/SVCB in Answers/Additionals must strip ECH records.
	aQuery := buildDNSQuery(t, 0x2234, "chatgpt.com", dnsmessage.TypeA)
	aReplyBytes, err := s.answerDNS(ctx, aQuery, false)
	if err != nil {
		t.Fatal(err)
	}
	aMsg := unpackDNSReply(t, aReplyBytes)
	if len(aMsg.Answers) != 1 || aMsg.Answers[0].Header.Type != dnsmessage.TypeA || len(aMsg.Additionals) != 0 {
		t.Fatalf("expected stripped HTTPS/SVCB records, got answers=%+v additionals=%+v", aMsg.Answers, aMsg.Additionals)
	}
}

// 2. TUN System DNS blackhole poisoning (127.0.0.1 / 0.0.0.0 / NXDOMAIN) auto-fallback via proxy TCP DNS
func TestTUNSystemDNSBlackholeAutoFallbackOverProxyTCP(t *testing.T) {
	var proxyDNSCalls atomic.Int32
	proxyPort, recordedTargets := startMockSOCKS5Server(t, func(host string, port uint16, c net.Conn) {
		if port != 53 {
			return
		}
		proxyDNSCalls.Add(1)
		var lb [2]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(lb[:]))
		wire := make([]byte, n)
		if _, err := io.ReadFull(c, wire); err != nil {
			return
		}
		var qm dnsmessage.Message
		if qm.Unpack(wire) != nil {
			return
		}
		q := qm.Questions[0]
		reply := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
		reply.Answers = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 180},
			Body:   &dnsmessage.AResource{A: [4]byte{104, 18, 37, 228}},
		}}
		out, _ := reply.Pack()
		frame := make([]byte, 2+len(out))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(out)))
		copy(frame[2:], out)
		_, _ = c.Write(frame)
	})

	var sysCalls atomic.Int32
	var mode atomic.Int32 // 0 -> 127.0.0.1, 1 -> 0.0.0.0, 2 -> NXDOMAIN
	s := startTest(t, Inbound{Protocol: "socks5", Name: "kat-client"}, func(c *Config) {
		c.Outbounds = []OutboundConfig{{
			Name: "proxy-out", Type: "socks5", Server: "127.0.0.1", Port: proxyPort,
		}}
		c.Routing = &RoutingOptions{
			Rules: []RouteRule{
				{DomainSuffix: "openai.com", Outbound: "proxy-out"},
				{DomainSuffix: "proxy-only.example", Outbound: "proxy-out"},
			},
			Final: "proxy-out",
		}
		c.SetClientDNSConfig(nil, nil, "rule", "proxy-out")
		c.SetClientEgress(&ClientEgress{
			Active:    func() bool { return true },
			Bootstrap: net.DefaultResolver.LookupNetIP,
			SystemQuery: func(_ context.Context, wire []byte) ([]byte, error) {
				sysCalls.Add(1)
				var qm dnsmessage.Message
				_ = qm.Unpack(wire)
				q := qm.Questions[0]
				switch mode.Load() {
				case 0:
					r := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
					r.Answers = []dnsmessage.Resource{{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
						Body:   &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
					}}
					return r.Pack()
				case 1:
					r := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
					r.Answers = []dnsmessage.Resource{{
						Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
						Body:   &dnsmessage.AResource{A: [4]byte{0, 0, 0, 0}},
					}}
					return r.Pack()
				default:
					r := dnsGatewayReply(qm, dnsmessage.RCodeNameError)
					return r.Pack()
				}
			},
		})
	})

	ctx := context.Background()
	// Case A: 127.0.0.1 blackhole on static proxy domain -> clean 104.18.37.228 + cached in wireCache!
	mode.Store(0)
	q1 := buildDNSQuery(t, 0x3101, "poisoned1.proxy-only.example", dnsmessage.TypeA)
	rep1, err := s.answerDNS(ctx, q1, false)
	if err != nil {
		t.Fatal(err)
	}
	m1 := unpackDNSReply(t, rep1)
	if len(m1.Answers) != 1 || netip.AddrFrom4(m1.Answers[0].Body.(*dnsmessage.AResource).A).String() != "104.18.37.228" {
		t.Fatalf("expected clean IP 104.18.37.228, got %+v", m1.Answers)
	}
	// Second query for same domain hits wireCache without calling SystemQuery or proxy again!
	prevSys, prevProxy := sysCalls.Load(), proxyDNSCalls.Load()
	q1Cached := buildDNSQuery(t, 0x3102, "poisoned1.proxy-only.example", dnsmessage.TypeA)
	rep1Cached, err := s.answerDNS(ctx, q1Cached, false)
	if err != nil {
		t.Fatal(err)
	}
	m1Cached := unpackDNSReply(t, rep1Cached)
	if m1Cached.ID != 0x3102 || netip.AddrFrom4(m1Cached.Answers[0].Body.(*dnsmessage.AResource).A).String() != "104.18.37.228" {
		t.Fatalf("unexpected cached reply: %+v", m1Cached)
	}
	if sysCalls.Load() != prevSys || proxyDNSCalls.Load() != prevProxy {
		t.Fatalf("expected wireCache hit, sys=%d->%d proxy=%d->%d", prevSys, sysCalls.Load(), prevProxy, proxyDNSCalls.Load())
	}

	// Case B: 0.0.0.0 blackhole on static proxy domain -> clean IP; ordinary domain keeps 0.0.0.0 (AdGuard/Pi-hole preserved)
	mode.Store(1)
	q2 := buildDNSQuery(t, 0x3201, "poisoned2.proxy-only.example", dnsmessage.TypeA)
	rep2, err := s.answerDNS(ctx, q2, false)
	if err != nil {
		t.Fatal(err)
	}
	m2 := unpackDNSReply(t, rep2)
	if len(m2.Answers) != 1 || netip.AddrFrom4(m2.Answers[0].Body.(*dnsmessage.AResource).A).String() != "104.18.37.228" {
		t.Fatalf("expected clean IP on 0.0.0.0 blackhole, got %+v", m2.Answers)
	}
	prevProxyBeforeAd := proxyDNSCalls.Load()
	qAd := buildDNSQuery(t, 0x3202, "adguard-blocked.example", dnsmessage.TypeA)
	repAd, err := s.answerDNS(ctx, qAd, false)
	if err != nil {
		t.Fatal(err)
	}
	mAd := unpackDNSReply(t, repAd)
	if len(mAd.Answers) != 1 || netip.AddrFrom4(mAd.Answers[0].Body.(*dnsmessage.AResource).A).String() != "0.0.0.0" || proxyDNSCalls.Load() != prevProxyBeforeAd {
		t.Fatalf("ordinary domain 0.0.0.0 must be returned unchanged without proxy fallback: answers=%+v proxyCalls=%d->%d", mAd.Answers, prevProxyBeforeAd, proxyDNSCalls.Load())
	}

	// Case C: NXDOMAIN on static route.Proxy domain api.openai.com -> clean IP via proxy
	mode.Store(2)
	q3 := buildDNSQuery(t, 0x3301, "api.openai.com", dnsmessage.TypeA)
	rep3, err := s.answerDNS(ctx, q3, false)
	if err != nil {
		t.Fatal(err)
	}
	m3 := unpackDNSReply(t, rep3)
	if len(m3.Answers) != 1 || netip.AddrFrom4(m3.Answers[0].Body.(*dnsmessage.AResource).A).String() != "104.18.37.228" {
		t.Fatalf("expected clean IP on NXDOMAIN for static proxy domain, got %+v", m3.Answers)
	}

	// Verify proxy dialed 1.1.1.1:53
	gots := recordedTargets()
	if len(gots) == 0 || gots[0] != "1.1.1.1:53" {
		t.Fatalf("expected proxy target 1.1.1.1:53, got %v", gots)
	}
}

// 3 & 4. DNS IP->domain reverse mapping (port 22 / sniff off / ECH outer SNI fallback) + Sniffed=false + ClearDNSCache
func TestDNSHostReverseMapAndECHOuterSNIFallback(t *testing.T) {
	proxyPort, recordedTargets := startMockSOCKS5Server(t, func(_ string, _ uint16, c net.Conn) {
		_, _ = io.Copy(c, c)
	})

	var connMu sync.Mutex
	var events []ConnectionEvent

	s := startTest(t, Inbound{
		Protocol: "socks5",
		Name:     "kat-client",
		Sniff:    &SniffOptions{Enabled: true, TCPPorts: "443", OverrideDestination: true},
	}, func(c *Config) {
		c.SetConnectionSink(func(ev ConnectionEvent) {
			connMu.Lock()
			events = append(events, ev)
			connMu.Unlock()
		})
		c.Outbounds = []OutboundConfig{{
			Name: "ai-proxy", Type: "socks5", Server: "127.0.0.1", Port: proxyPort,
		}}
		c.Routing = &RoutingOptions{
			Rules: []RouteRule{
				{DomainSuffix: "chatgpt.com", Outbound: "ai-proxy"},
				{DomainSuffix: "github.com", Outbound: "ai-proxy"},
			},
			Final: "reject",
		}
		c.SetClientDNSConfig(nil, nil, "rule", "direct")
		c.SetClientEgress(&ClientEgress{
			Active:    func() bool { return true },
			Bootstrap: net.DefaultResolver.LookupNetIP,
			SystemQuery: func(_ context.Context, wire []byte) ([]byte, error) {
				var qm dnsmessage.Message
				_ = qm.Unpack(wire)
				q := qm.Questions[0]
				name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
				r := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
				ip := [4]byte{140, 82, 114, 4}
				if strings.HasSuffix(name, "chatgpt.com") {
					ip = [4]byte{104, 18, 32, 47}
				}
				r.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
					Body:   &dnsmessage.AResource{A: ip},
				}}
				return r.Pack()
			},
		})
	})

	ctx := context.Background()
	// Step 1: Resolve github.com via TUN DNS -> records 140.82.114.4 -> github.com
	if _, err := s.answerDNS(ctx, buildDNSQuery(t, 0x4001, "github.com", dnsmessage.TypeA), false); err != nil {
		t.Fatal(err)
	}
	client := socksClient(t, s)
	// Connect to raw IP 140.82.114.4 on port 22 (non-sniffed SSH port) with SSH banner:
	// must match github.com rule -> ai-proxy while preserving raw dial IP 140.82.114.4:22!
	if !sendFirst(t, client, outbound.Addr{Host: "140.82.114.4", Port: 22}, []byte("SSH-2.0-OpenSSH_9.0\r\n")) {
		t.Fatal("expected pure IP connection on port 22 to route via DNS IP->domain map")
	}

	// Step 2: Resolve chatgpt.com -> records 104.18.32.47 -> chatgpt.com
	if _, err := s.answerDNS(ctx, buildDNSQuery(t, 0x4002, "chatgpt.com", dnsmessage.TypeA), false); err != nil {
		t.Fatal(err)
	}
	// Connect to 104.18.32.47:443 with outer SNI "cloudflare-ech.com":
	// sniff must ignore cloudflare-ech.com, route via DNS map "chatgpt.com", and keep raw dial IP 104.18.32.47:443!
	echoHello := tlsHello(t, "cloudflare-ech.com")
	if !sendFirst(t, client, outbound.Addr{Host: "104.18.32.47", Port: 443}, echoHello) {
		t.Fatal("expected cloudflare-ech.com SNI to be ignored and fall back to chatgpt.com DNS map")
	}

	gots := recordedTargets()
	if len(gots) != 2 || gots[0] != "140.82.114.4:22" || gots[1] != "104.18.32.47:443" {
		t.Fatalf("DNS mapping must not rewrite dial target IPs: expected [140.82.114.4:22 104.18.32.47:443], got %v", gots)
	}

	connMu.Lock()
	var sawGithub, sawChatgpt bool
	for _, ev := range events {
		if ev.DestHost == "cloudflare-ech.com" || ev.Host == "cloudflare-ech.com" {
			connMu.Unlock()
			t.Fatalf("cloudflare-ech.com leaked into ConnectionEvent: %+v", ev)
		}
		if ev.DestHost == "github.com" {
			sawGithub = true
			if ev.Sniffed {
				connMu.Unlock()
				t.Fatalf("DNS-mapped flow must have Sniffed=false, got %+v", ev)
			}
		}
		if ev.DestHost == "chatgpt.com" {
			sawChatgpt = true
			if ev.Sniffed {
				connMu.Unlock()
				t.Fatalf("ECH-ignored DNS-mapped flow must have Sniffed=false, got %+v", ev)
			}
		}
	}
	connMu.Unlock()
	if !sawGithub || !sawChatgpt {
		t.Fatalf("missing mapped hosts in events: github=%v chatgpt=%v", sawGithub, sawChatgpt)
	}

	// ClearDNSCache must also clear dnsHosts reverse map!
	if _, err := s.ClearDNSCache(); err != nil {
		t.Fatal(err)
	}
	if sendFirst(t, client, outbound.Addr{Host: "140.82.114.4", Port: 22}, []byte("SSH-2.0-OpenSSH_9.0\r\n")) {
		t.Fatal("expected connection to hit Final=reject after ClearDNSCache cleared dnsHosts")
	}
}

// 5. LAN IP protection & skip_domain exclusions (courier.push.apple.com, Mijia Cloud, explicit [])
func TestSniffLANIPProtectionAndSkipDomain(t *testing.T) {
	// Unit check on target() for LAN/CGNAT/link-local vs loopback 127.0.0.2 vs public IP
	r := &sniffResult{proto: "tls", host: "nas.example.com", override: true}
	for _, lanIP := range []string{"192.168.1.10", "10.0.0.8", "172.16.5.4", "100.64.1.2", "fe80::1", "fd00::1"} {
		got := r.target(Address{Host: lanIP, Port: 443})
		if got.Host != lanIP {
			t.Fatalf("LAN IP %s should not be overridden, got %s", lanIP, got.Host)
		}
	}
	// Loopback 127.0.0.2 MUST still override for TestSniffOverrideDestination compatibility!
	if got := r.target(Address{Host: "127.0.0.2", Port: 443}); got.Host != "nas.example.com" {
		t.Fatalf("loopback 127.0.0.2 must still allow override, got %s", got.Host)
	}
	if got := r.target(Address{Host: "203.0.113.9", Port: 443}); got.Host != "nas.example.com" {
		t.Fatalf("public IP should override to nas.example.com, got %s", got.Host)
	}

	// Built-in DefaultSkipDomains behavior when SkipDomain == nil
	opt := &SniffOptions{Enabled: true, OverrideDestination: true}
	if err := opt.normalize(); err != nil {
		t.Fatal(err)
	}
	if opt.SkipDomain != nil {
		t.Fatalf("normalize must keep SkipDomain == nil when omitted, got %#v", opt.SkipDomain)
	}
	appleRes := opt.applyResult("tls", "courier.push.apple.com")
	if appleRes.override || appleRes.host != "courier.push.apple.com" {
		t.Fatalf("courier.push.apple.com should keep host for routing but disable override: %+v", appleRes)
	}
	if got := appleRes.target(Address{Host: "17.57.144.83", Port: 443}); got.Host != "17.57.144.83" {
		t.Fatalf("skip_domain must preserve IP 17.57.144.83, got %s", got.Host)
	}
	mijiaRes := opt.applyResult("tls", "Mijia Cloud")
	if mijiaRes.override || mijiaRes.host != "" {
		t.Fatalf("Mijia Cloud invalid DNS name should clear host and disable override: %+v", mijiaRes)
	}
	echRes := opt.applyResult("tls", "Sub.Cloudflare-ECH.com")
	if echRes.override || echRes.host != "" {
		t.Fatalf("cloudflare-ech.com must be completely ignored: %+v", echRes)
	}

	// Explicit SkipDomain: [] clears built-in skip list (apple overrides, ECH & LAN still protected)
	emptyOpt := &SniffOptions{Enabled: true, OverrideDestination: true, SkipDomain: []string{}}
	if err := emptyOpt.normalize(); err != nil {
		t.Fatal(err)
	}
	appleCleared := emptyOpt.applyResult("tls", "courier.push.apple.com")
	if !appleCleared.override || appleCleared.host != "courier.push.apple.com" {
		t.Fatalf("explicit empty skip_domain should allow override on apple: %+v", appleCleared)
	}
	if echCleared := emptyOpt.applyResult("tls", "cloudflare-ech.com"); echCleared.host != "" {
		t.Fatalf("cloudflare-ech.com must still be ignored even when skip_domain=[]: %+v", echCleared)
	}

	// End-to-end SOCKS5 -> Proxy test verifying courier.push.apple.com and LAN IP 192.168.1.10 keep raw IP target
	proxyPort, recordedTargets := startMockSOCKS5Server(t, func(_ string, _ uint16, c net.Conn) {
		_, _ = io.Copy(c, c)
	})
	s := startTest(t, Inbound{
		Protocol: "socks5",
		Name:     "kat-client",
		Sniff:    &SniffOptions{Enabled: true, TCPPorts: "443", OverrideDestination: true},
	}, func(c *Config) {
		c.Outbounds = []OutboundConfig{{
			Name: "proxy", Type: "socks5", Server: "127.0.0.1", Port: proxyPort,
		}}
		c.Routing = &RoutingOptions{
			Rules: []RouteRule{{DomainSuffix: "push.apple.com", Outbound: "proxy"}, {DomainSuffix: "example.com", Outbound: "proxy"}},
			Final: "reject",
		}
	})
	client := socksClient(t, s)
	if !sendFirst(t, client, outbound.Addr{Host: "17.57.144.83", Port: 443}, tlsHello(t, "courier.push.apple.com")) {
		t.Fatal("apple push connection failed")
	}
	if !sendFirst(t, client, outbound.Addr{Host: "192.168.1.10", Port: 443}, tlsHello(t, "nas.example.com")) {
		t.Fatal("LAN IP connection failed")
	}
	gots := recordedTargets()
	if len(gots) != 2 || gots[0] != "17.57.144.83:443" || gots[1] != "192.168.1.10:443" {
		t.Fatalf("expected raw IPs [17.57.144.83:443 192.168.1.10:443], got %v", gots)
	}
}

// 6. System DNS mode lookupAnswer (45s TTL) & gateway (wire TTL) caching + ListDNSCache
func TestSystemDNSCacheLookupAndGateway(t *testing.T) {
	var bootCalls, sysWireCalls atomic.Int32
	s := startTest(t, Inbound{Protocol: "socks5", Name: "kat-client"}, func(c *Config) {
		c.SetClientDNSConfig(nil, nil, "rule", "direct")
		c.SetClientEgress(&ClientEgress{
			Active: func() bool { return true },
			Bootstrap: func(_ context.Context, _ string, host string) ([]netip.Addr, error) {
				bootCalls.Add(1)
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			},
			SystemQuery: func(_ context.Context, wire []byte) ([]byte, error) {
				sysWireCalls.Add(1)
				var qm dnsmessage.Message
				_ = qm.Unpack(wire)
				q := qm.Questions[0]
				r := dnsGatewayReply(qm, dnsmessage.RCodeSuccess)
				r.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 240},
					Body:   &dnsmessage.AResource{A: [4]byte{198, 51, 100, 77}},
				}}
				return r.Pack()
			},
		})
	})

	ctx := context.Background()
	g := s.current()
	// 1) lookupAnswer in system DNS mode caches for ~45s
	ips1, srv1, cached1, err := g.dns.lookupAnswer(ctx, "lookup-sys.example.com")
	if err != nil || cached1 || srv1 != "system" || len(ips1) != 1 {
		t.Fatalf("first lookupAnswer unexpected: ips=%v srv=%s cached=%v err=%v", ips1, srv1, cached1, err)
	}
	ips2, srv2, cached2, err := g.dns.lookupAnswer(ctx, "lookup-sys.example.com")
	if err != nil || !cached2 || srv2 != "system" || len(ips2) != 1 || bootCalls.Load() != 1 {
		t.Fatalf("second lookupAnswer expected cache hit: cached=%v bootCalls=%d err=%v", cached2, bootCalls.Load(), err)
	}
	// Also recorded into core.dnsHosts (clamped to >=60s)
	if gotHost := s.core.lookupDNSHost(netip.MustParseAddr("93.184.216.34")); gotHost != "lookup-sys.example.com" {
		t.Fatalf("expected lookupAnswer to populate dnsHosts, got %q", gotHost)
	}

	// 2) gateway in system DNS mode caches by real upstream wire TTL (240s)
	qw1 := buildDNSQuery(t, 0x6001, "wire-sys.example.com", dnsmessage.TypeA)
	if _, err := s.answerDNS(ctx, qw1, false); err != nil {
		t.Fatal(err)
	}
	qw2 := buildDNSQuery(t, 0x6002, "wire-sys.example.com", dnsmessage.TypeA)
	if _, err := s.answerDNS(ctx, qw2, false); err != nil {
		t.Fatal(err)
	}
	if sysWireCalls.Load() != 1 {
		t.Fatalf("expected gateway wireCache hit on second query, sysWireCalls=%d", sysWireCalls.Load())
	}

	// 3) ListDNSCache returns capacity 256 and both cached entries with expected TTL bounds
	items, capVal, err := s.ListDNSCache()
	if err != nil {
		t.Fatal(err)
	}
	if capVal != 256 {
		t.Fatalf("expected default system DNS cache capacity 256, got %d", capVal)
	}
	byName := map[string]DNSCacheItem{}
	for _, it := range items {
		byName[it.Name] = it
	}
	lu, ok1 := byName["lookup-sys.example.com"]
	wr, ok2 := byName["wire-sys.example.com"]
	if !ok1 || !ok2 {
		t.Fatalf("expected both lookup and wire items in ListDNSCache, got %+v", items)
	}
	if lu.TTLSec <= 0 || lu.TTLSec > 45 {
		t.Fatalf("expected lookupAnswer TTL in (0,45], got %d", lu.TTLSec)
	}
	if wr.TTLSec < 200 || wr.TTLSec > 240 {
		t.Fatalf("expected gateway wire TTL near 240s, got %d", wr.TTLSec)
	}
}
