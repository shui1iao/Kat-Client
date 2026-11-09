package kernel

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

var errFakeIP = errors.New("legacy synthetic address refused")
var fake4 = netip.MustParsePrefix("198.19.0.0/16")
var fake6 = netip.MustParsePrefix("fd4b:6174:6661::/112")

// ClientFakeIP only identifies retired desktop pools for safety rejection.
// No identities are allocated, loaded, persisted or restored.
func ClientFakeIP(ip netip.Addr) bool {
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
	for _, suffix := range []string{"localhost", "local", "lan", "localdomain", "home.arpa"} {
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
func (s *Server) answerClientDNS(ctx context.Context, wire []byte, tcp bool) ([]byte, error) {
	if !s.tunDNSActive() {
		return s.dns.gateway(ctx, wire, tcp)
	}
	m, e := dnsRequest(wire)
	if e != nil {
		return nil, e
	}
	q := m.Questions[0]
	if q.Type == dnsmessage.TypePTR {
		name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
		if ip, ok := reverseDNSIP(name); ok && ClientFakeIP(ip) {
			// Old synthetic identities are no longer loaded or recoverable. Never
			// forward their reverse queries or invent a name from stale state.
			reply := dnsGatewayReply(m, dnsmessage.RCodeNameError)
			return reply.Pack()
		}
	}
	// All record types use the real gateway, including HTTPS/SVCB/ANY. Its
	// existing IPv6 gate still returns AAAA NODATA when IPv6 is disabled.
	b, e := s.dns.gateway(ctx, wire, tcp)
	if e != nil {
		return nil, e
	}
	// Retain the old pool guard, but never allocate or restore an identity.
	var real dnsmessage.Message
	if real.Unpack(b) == nil {
		for _, section := range [][]dnsmessage.Resource{real.Answers, real.Additionals} {
			for _, rr := range section {
				var ip netip.Addr
				switch v := rr.Body.(type) {
				case *dnsmessage.AResource:
					ip = netip.AddrFrom4(v.A)
				case *dnsmessage.AAAAResource:
					ip = netip.AddrFrom16(v.AAAA)
				}
				if ip.IsValid() && ClientFakeIP(ip) {
					return nil, errFakeIP
				}
			}
		}
	}
	return b, nil
}
