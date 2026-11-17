package kernel

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/shui1iao/Kat/internal/route"
	"golang.org/x/net/dns/dnsmessage"
)

var errFakeIP = errors.New("legacy synthetic address refused")
var fake4 = netip.MustParsePrefix("198.19.0.0/16")
var fake6 = netip.MustParsePrefix("fd4b:6174:6661::/112")
var proxyFallbackDNSServers = []string{"1.1.1.1:53", "8.8.8.8:53"}

// ClientFakeIP only identifies retired desktop pools for safety rejection.
// No identities are allocated, loaded, persisted or restored.
func ClientFakeIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	return fake4.Contains(ip) || fake6.Contains(ip)
}

type originalTargetKey struct{}

func withOriginalTarget(ctx context.Context, a Address) context.Context {
	return context.WithValue(ctx, originalTargetKey{}, a)
}
func originalTarget(ctx context.Context, a Address) Address {
	if v, ok := ctx.Value(originalTargetKey{}).(Address); ok {
		return v
	}
	return a
}
func sniffTarget(ctx context.Context, a Address) Address { return sniffOf(ctx).target(a) }

func localDNSName(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if !strings.Contains(name, ".") {
		return true
	}
	for _, suffix := range []string{"localhost", "local", "lan", "localdomain", "home.arpa", "internal", "in-addr.arpa", "ip6.arpa"} {
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return true
		}
	}
	return false
}

func reverseDNSIP(name string) (netip.Addr, bool) {
	if strings.HasSuffix(name, ".in-addr.arpa") {
		parts := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa"), ".")
		if len(parts) != 4 {
			return netip.Addr{}, false
		}
		for i, j := 0, 3; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		ip, e := netip.ParseAddr(strings.Join(parts, "."))
		return ip, e == nil
	}
	if strings.HasSuffix(name, ".ip6.arpa") {
		parts := strings.Split(strings.TrimSuffix(name, ".ip6.arpa"), ".")
		if len(parts) != 32 {
			return netip.Addr{}, false
		}
		for _, p := range parts {
			if len(p) != 1 {
				return netip.Addr{}, false
			}
		}
		for i, j := 0, 31; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		b, e := hex.DecodeString(strings.Join(parts, ""))
		if e != nil || len(b) != 16 {
			return netip.Addr{}, false
		}
		var a [16]byte
		copy(a[:], b)
		return netip.AddrFrom16(a), true
	}
	return netip.Addr{}, false
}

func isBlackholeDNSIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	return ip.IsUnspecified() || ip.IsLoopback() || ClientFakeIP(ip)
}

func replySectionsHaveFakeIP(m dnsmessage.Message) bool {
	for _, section := range [][]dnsmessage.Resource{m.Answers, m.Additionals} {
		for _, rr := range section {
			var ip netip.Addr
			switch v := rr.Body.(type) {
			case *dnsmessage.AResource:
				ip = netip.AddrFrom4(v.A)
			case *dnsmessage.AAAAResource:
				ip = netip.AddrFrom16(v.AAAA)
			}
			if ip.IsValid() && ClientFakeIP(ip) {
				return true
			}
		}
	}
	return false
}

func replyHasBlackholeIP(m dnsmessage.Message) bool {
	if replySectionsHaveFakeIP(m) {
		return true
	}
	for _, rr := range m.Answers {
		switch v := rr.Body.(type) {
		case *dnsmessage.AResource:
			if isBlackholeDNSIP(netip.AddrFrom4(v.A)) {
				return true
			}
		case *dnsmessage.AAAAResource:
			if isBlackholeDNSIP(netip.AddrFrom16(v.AAAA)) {
				return true
			}
		}
	}
	return false
}

func stripECHRecords(m *dnsmessage.Message) bool {
	stripped := false
	if len(m.Answers) > 0 {
		out := m.Answers[:0]
		for _, rr := range m.Answers {
			if rr.Header.Type == dnsmessage.TypeHTTPS || rr.Header.Type == dnsmessage.TypeSVCB {
				stripped = true
				continue
			}
			out = append(out, rr)
		}
		m.Answers = out
	}
	if len(m.Additionals) > 0 {
		out := m.Additionals[:0]
		for _, rr := range m.Additionals {
			if rr.Header.Type == dnsmessage.TypeHTTPS || rr.Header.Type == dnsmessage.TypeSVCB {
				stripped = true
				continue
			}
			out = append(out, rr)
		}
		m.Additionals = out
	}
	return stripped
}

func minWireTTL(m dnsmessage.Message) uint32 {
	ttl := uint32(300)
	for _, section := range [][]dnsmessage.Resource{m.Answers, m.Authorities} {
		for _, rr := range section {
			if rr.Header.TTL < ttl {
				ttl = rr.Header.TTL
			}
		}
	}
	return ttl
}

// staticDomainProxy returns a proxy outbound only when name is statically
// guaranteed to route through a proxy without any preceding unknown non-proxy
// rule that could steer the actual connection to direct/reject.
func (s *Server) staticDomainProxy(name string) string {
	if s == nil || s.rt == nil || s.rt.engine == nil {
		return ""
	}
	if s.cfg.clientDNS != nil && s.cfg.clientDNS.Mode == "direct" {
		return ""
	}
	if d, ok := s.rt.engine.MatchStaticDomain(name); ok && d.Kind == route.Proxy && d.Outbound != "" && d.Outbound != "direct" && d.Outbound != "reject" {
		return d.Outbound
	}
	return ""
}

func queryProxyTCPDNSOnce(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), server string, query dnsmessage.Message, q dnsmessage.Question, wire []byte) ([]byte, dnsmessage.Message, bool) {
	c, err := dial(ctx, "tcp", server)
	if err != nil {
		return nil, dnsmessage.Message{}, false
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	} else {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	}
	frame := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(wire)))
	copy(frame[2:], wire)
	if _, err := c.Write(frame); err != nil {
		return nil, dnsmessage.Message{}, false
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return nil, dnsmessage.Message{}, false
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n < 12 || n > 65535 {
		return nil, dnsmessage.Message{}, false
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, dnsmessage.Message{}, false
	}
	if _, err := validWireReply(resp, query.ID, q); err != nil {
		return nil, dnsmessage.Message{}, false
	}
	var parsed dnsmessage.Message
	if parsed.Unpack(resp) != nil || replyHasBlackholeIP(parsed) {
		return nil, dnsmessage.Message{}, false
	}
	if parsed.RCode != dnsmessage.RCodeSuccess || len(parsed.Answers) == 0 {
		return nil, dnsmessage.Message{}, false
	}
	return resp, parsed, true
}

func (s *Server) fallbackProxyTCPDNS(ctx context.Context, proxyOutbound string, query dnsmessage.Message, q dnsmessage.Question, wire []byte) ([]byte, dnsmessage.Message, string, bool) {
	if s == nil || s.rt == nil || len(wire) < 12 || proxyOutbound == "" || proxyOutbound == "direct" || proxyOutbound == "reject" {
		return nil, dnsmessage.Message{}, "", false
	}
	dial, err := s.rt.dialVia(proxyOutbound)
	if err != nil {
		return nil, dnsmessage.Message{}, "", false
	}
	qctx := ctx
	if _, has := ctx.Deadline(); !has {
		var cancel context.CancelFunc
		qctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	// Mark fallback dials as protected DNS so any group resolving to a direct
	// leaf fails closed inside clientDirect.selectRole instead of leaking plaintext DNS.
	qctx = context.WithValue(qctx, protectedDNSKey{}, true)
	deadline, _ := qctx.Deadline()
	for i, srv := range proxyFallbackDNSServers {
		rem := time.Until(deadline)
		if rem <= 0 || qctx.Err() != nil {
			break
		}
		actx, stop := context.WithTimeout(qctx, rem/time.Duration(len(proxyFallbackDNSServers)-i))
		resp, parsed, ok := queryProxyTCPDNSOnce(actx, dial, srv, query, q, wire)
		stop()
		if ok {
			return resp, parsed, srv, true
		}
	}
	return nil, dnsmessage.Message{}, "", false
}

func (s *Server) answerClientDNS(ctx context.Context, wire []byte, tcp bool) ([]byte, error) {
	if !s.tunDNSActive() {
		return s.dns.gateway(ctx, wire, tcp)
	}
	return s.dns.gatewayWithPolicy(ctx, wire, tcp, &clientGatewayPolicy{server: s})
}
