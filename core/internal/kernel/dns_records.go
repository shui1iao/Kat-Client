package kernel

import (
	"context"
	"golang.org/x/net/dns/dnsmessage"
	"net/netip"
	"sort"
	"strings"
	"time"
)

type DNSEvent struct {
	Time       time.Time `json:"time"`
	Name       string    `json:"name"`
	QType      string    `json:"qtype"`
	Addresses  []string  `json:"addresses"`
	Server     string    `json:"server,omitempty"`
	Cached     bool      `json:"cached"`
	DurationMS int64     `json:"duration_ms"`
	Outcome    string    `json:"outcome"` // "ok" | "nxdomain" | "nodata" | "error"
	Source     string    `json:"source"`  // "kernel" | "tun" | "test"
}

type DNSCacheItem struct {
	Name      string   `json:"name"`
	QType     string   `json:"qtype"`
	Addresses []string `json:"addresses"`
	Server    string   `json:"server,omitempty"`
	TTLSec    int64    `json:"ttl_sec"`
}

func (c *Config) SetDNSSink(sink func(DNSEvent)) { c.clientDNSSink = sink }

type dnsQuerySourceKey struct{}

func withDNSSource(ctx context.Context, src string) context.Context {
	return context.WithValue(ctx, dnsQuerySourceKey{}, src)
}

func dnsSourceOf(ctx context.Context, fallback string) string {
	if v, ok := ctx.Value(dnsQuerySourceKey{}).(string); ok && v != "" {
		return v
	}
	return fallback
}

func (r *internalDNS) setEventSink(fn func(DNSEvent)) {
	if r == nil {
		return
	}
	r.eventSink = fn
	for _, p := range r.rules {
		p.resolver.setEventSink(fn)
	}
	if r.local != nil {
		r.local.setEventSink(fn)
	}
}

func dnsTypeString(t dnsmessage.Type) string {
	switch t {
	case dnsmessage.TypeA:
		return "A"
	case dnsmessage.TypeAAAA:
		return "AAAA"
	case dnsmessage.TypeCNAME:
		return "CNAME"
	case dnsmessage.TypeHTTPS:
		return "HTTPS"
	case dnsmessage.TypeSVCB:
		return "SVCB"
	case dnsmessage.TypePTR:
		return "PTR"
	case dnsmessage.TypeTXT:
		return "TXT"
	case dnsmessage.TypeMX:
		return "MX"
	case dnsmessage.TypeNS:
		return "NS"
	case dnsmessage.TypeSOA:
		return "SOA"
	default:
		s := t.String()
		return strings.TrimPrefix(s, "Type")
	}
}

func extractWireAddresses(b []byte) ([]string, uint32, dnsmessage.RCode, bool) {
	var m dnsmessage.Message
	if len(b) < 12 || m.Unpack(b) != nil {
		return nil, 0, dnsmessage.RCodeServerFailure, false
	}
	var addrs []string
	seen := map[string]bool{}
	minTTL := uint32(0)
	hasTTL := false
	for _, rr := range m.Answers {
		if !hasTTL || rr.Header.TTL < minTTL {
			minTTL = rr.Header.TTL
			hasTTL = true
		}
		switch v := rr.Body.(type) {
		case *dnsmessage.AResource:
			s := netip.AddrFrom4(v.A).String()
			if !seen[s] {
				seen[s] = true
				addrs = append(addrs, s)
			}
		case *dnsmessage.AAAAResource:
			s := netip.AddrFrom16(v.AAAA).String()
			if !seen[s] {
				seen[s] = true
				addrs = append(addrs, s)
			}
		case *dnsmessage.CNAMEResource:
			// keep scanning for terminal A/AAAA; if none, CNAME target is informative
			_ = v
		}
	}
	return addrs, minTTL, m.RCode, true
}

func (r *internalDNS) collectCache(out *[]DNSCacheItem, seen map[string]bool) {
	if r == nil {
		return
	}
	now := r.now()
	epoch := r.dnsEpoch()
	r.mu.Lock()
	for name, e := range r.cache {
		if e.epoch != epoch || !e.expires.After(now) {
			continue
		}
		ttl := int64(e.expires.Sub(now).Seconds())
		if ttl <= 0 {
			continue
		}
		key := "lookup:" + name
		if seen[key] {
			continue
		}
		seen[key] = true
		addrs := make([]string, 0, len(e.ips))
		has4, has6 := false, false
		for _, ip := range e.ips {
			addrs = append(addrs, ip.String())
			if ip.Is4() {
				has4 = true
			} else {
				has6 = true
			}
		}
		qt := "A"
		if has4 && has6 {
			qt = "A+AAAA"
		} else if has6 {
			qt = "AAAA"
		}
		*out = append(*out, DNSCacheItem{
			Name:      name,
			QType:     qt,
			Addresses: addrs,
			Server:    e.server,
			TTLSec:    ttl,
		})
	}
	for _, e := range r.wireCache {
		if e.epoch != epoch || !e.expires.After(now) {
			continue
		}
		ttl := int64(e.expires.Sub(now).Seconds())
		if ttl <= 0 {
			continue
		}
		var m dnsmessage.Message
		if m.Unpack(e.wire) != nil || len(m.Questions) == 0 {
			continue
		}
		q := m.Questions[0]
		name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
		qt := dnsTypeString(q.Type)
		key := "wire:" + name + ":" + qt
		if seen[key] {
			continue
		}
		seen[key] = true
		addrs, _, _, ok := extractWireAddresses(e.wire)
		if !ok {
			continue
		}
		*out = append(*out, DNSCacheItem{
			Name:      name,
			QType:     qt,
			Addresses: addrs,
			Server:    e.server,
			TTLSec:    ttl,
		})
	}
	r.mu.Unlock()
	for _, p := range r.rules {
		p.resolver.collectCache(out, seen)
	}
}

func (s *Server) ListDNSCache() ([]DNSCacheItem, int, error) {
	if s.core.ctx.Err() != nil {
		return nil, 0, ErrCoreNotRunning
	}
	g := s.current()
	if !g.tryRef() {
		return nil, 0, ErrCoreNotRunning
	}
	defer g.unref()
	items := []DNSCacheItem{}
	seen := map[string]bool{}
	g.dns.collectCache(&items, seen)
	if g.directDNS != nil && g.directDNS != g.dns {
		g.directDNS.collectCache(&items, seen)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].TTLSec != items[j].TTLSec {
			return items[i].TTLSec > items[j].TTLSec
		}
		return items[i].Name < items[j].Name
	})
	capVal := 0
	if g.dns != nil {
		capVal = g.dns.capacity
	}
	return items, capVal, nil
}

func (s *Server) LookupIPASN(ip netip.Addr) uint32 {
	if s == nil || s.core == nil || s.core.ctx.Err() != nil {
		return 0
	}
	g := s.current()
	if !g.tryRef() {
		return 0
	}
	defer g.unref()
	if g.rt == nil || g.rt.engine == nil {
		return 0
	}
	return g.rt.engine.LookupASN(ip)
}
