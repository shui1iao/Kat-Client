package kernel

// Ordinary DNS is answered inside the existing SOCKS data plane. The SYSTEM
// service, adapter DNS addresses, routes, lease and rollback journal are NOT
// changed. While controlled egress is installed, TCP/UDP destination port 53
// is handled before originalResolver's legacy physical passthrough. Resolver
// upstream sockets use the physical egress hook and cannot re-enter this gate.
import (
	"bytes"
	"context"
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"
)

type dnsWireEntry struct {
	wire           []byte
	added, expires time.Time
}

func (s *Server) controlledDNS(a Address) bool {
	return a.Port == 53 && s.cfg.clientIPv6 != nil && s.cfg.clientEgress != nil
}
func dnsRequest(w []byte) (dnsmessage.Message, error) {
	var m dnsmessage.Message
	if len(w) < 12 || len(w) > maxDNSMessage || m.Unpack(w) != nil || m.Response || m.OpCode != 0 || len(m.Questions) != 1 || m.Questions[0].Class != dnsmessage.ClassINET || len(m.Answers) != 0 || len(m.Authorities) != 0 {
		return m, errDNS
	}
	if _, e := dnsName(strings.TrimSuffix(m.Questions[0].Name.String(), ".")); e != nil {
		return m, errDNS
	}
	return m, nil
}
func dnsGatewayReply(m dnsmessage.Message, code dnsmessage.RCode) dnsmessage.Message {
	return dnsmessage.Message{Header: dnsmessage.Header{ID: m.ID, Response: true, RecursionDesired: m.RecursionDesired, RecursionAvailable: true, RCode: code}, Questions: m.Questions}
}
func (r *internalDNS) gateway(ctx context.Context, wire []byte, tcp bool) ([]byte, error) {
	m, e := dnsRequest(wire)
	if e != nil {
		return nil, e
	}
	q := m.Questions[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	reply := dnsGatewayReply(m, dnsmessage.RCodeSuccess)
	if q.Type == dnsmessage.TypeAAAA && r.disableIPv6 {
		return reply.Pack()
	}
	if ips, ok := r.host(name); ok && (q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA) {
		for _, ip := range ips {
			rr := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60, Type: q.Type}}
			if ip.Is4() && q.Type == dnsmessage.TypeA {
				rr.Body = &dnsmessage.AResource{A: ip.As4()}
			} else if ip.Is6() && q.Type == dnsmessage.TypeAAAA {
				rr.Body = &dnsmessage.AAAAResource{AAAA: ip.As16()}
			} else {
				continue
			}
			reply.Answers = append(reply.Answers, rr)
		}
		b, e := reply.Pack()
		return dnsDownstream(m, b, tcp), e
	}
	p := r.policy(name)
	// One bounded worker per admitted connection/association; never per packet.
	select {
	case p.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-p.slots }()
	key := string(wire[2:])
	p.mu.Lock()
	entry, hit := p.wireCache[key]
	p.mu.Unlock()
	if hit && entry.expires.After(p.now()) {
		var cached dnsmessage.Message
		if cached.Unpack(entry.wire) == nil {
			cached.ID = m.ID
			age := uint32(p.now().Sub(entry.added) / time.Second)
			for _, section := range [][]dnsmessage.Resource{cached.Answers, cached.Authorities, cached.Additionals} {
				for i := range section {
					if section[i].Header.Type != dnsmessage.TypeOPT {
						if section[i].Header.TTL > age {
							section[i].Header.TTL -= age
						} else {
							section[i].Header.TTL = 0
						}
					}
				}
			}
			b, e := cached.Pack()
			return dnsDownstream(m, b, tcp), e
		}
	}
	upstreams := append([]*dnsUpstream(nil), p.upstreams...)
	// Preserve the existing custom -> physical/system fallback chain. No public
	// resolver is invented for system-only clients, and selected rule chains do
	// not silently leak to the system resolver when they fail.
	if p == r || len(upstreams) == 0 {
		for _, ip := range r.physical {
			if r.disableIPv6 && ip.Unmap().Is6() {
				continue
			}
			ep, e := parseDNS(net.JoinHostPort(ip.String(), "53"))
			if e == nil {
				upstreams = append(upstreams, &dnsUpstream{ep: ep, resolver: p})
			}
		}
	}
	deadline, has := ctx.Deadline()
	if !has {
		deadline = time.Now().Add(5 * time.Second)
	}
	for i, u := range upstreams {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		attempt, cancel := context.WithTimeout(ctx, remaining/time.Duration(len(upstreams)-i))
		b, e := u.rawQuery(attempt, wire, q, m.ID)
		cancel()
		if e != nil {
			continue
		}
		var answer dnsmessage.Message
		if answer.Unpack(b) != nil || answer.RCode != dnsmessage.RCodeSuccess && answer.RCode != dnsmessage.RCodeNameError {
			continue
		}
		ttl := uint32(300)
		for _, section := range [][]dnsmessage.Resource{answer.Answers, answer.Authorities} {
			for _, rr := range section {
				if rr.Header.TTL < ttl {
					ttl = rr.Header.TTL
				}
			}
		}
		if p.capacity > 0 && ttl > 0 && !answer.Truncated && answer.RCode == dnsmessage.RCodeSuccess && len(answer.Answers) > 0 {
			p.mu.Lock()
			if len(p.wireCache) >= p.capacity {
				for k, v := range p.wireCache {
					delete(p.wireCache, k)
					if !v.expires.After(p.now()) {
						continue
					}
					break
				}
			}
			p.wireCache[key] = dnsWireEntry{append([]byte(nil), b...), p.now(), p.now().Add(time.Duration(ttl) * time.Second)}
			p.mu.Unlock()
		}
		return dnsDownstream(m, b, tcp), nil
	}
	reply.RCode = dnsmessage.RCodeServerFailure
	return reply.Pack()
}
func dnsDownstream(query dnsmessage.Message, b []byte, tcp bool) []byte {
	if tcp {
		return b
	}
	limit := 512
	for _, rr := range query.Additionals {
		if rr.Header.Type == dnsmessage.TypeOPT {
			n := int(rr.Header.Class)
			if n > limit {
				limit = n
			}
		}
	}
	if limit > 4096 {
		limit = 4096
	}
	if len(b) <= limit {
		return b
	}
	var response dnsmessage.Message
	if response.Unpack(b) != nil {
		return nil
	}
	response.Truncated = true
	response.Answers = nil
	response.Authorities = nil
	response.Additionals = nil
	out, _ := response.Pack()
	return out
}
func validWireReply(b []byte, id uint16, q dnsmessage.Question) (bool, error) {
	var parser dnsmessage.Parser
	header, e := parser.Start(b)
	if e != nil || !header.Response || header.ID != id || header.OpCode != 0 {
		return false, errDNS
	}
	qs, e := parser.AllQuestions()
	if e != nil || len(qs) != 1 {
		return false, errDNS
	}
	p := qs[0]
	if !strings.EqualFold(p.Name.String(), q.Name.String()) || p.Type != q.Type || p.Class != q.Class {
		return false, errDNS
	}
	// A truncated UDP body need not be unpackable: retry the SAME upstream by
	// TCP after authenticating its header/question, before parsing RR sections.
	if header.Truncated {
		return true, nil
	}
	var m dnsmessage.Message
	if m.Unpack(b) != nil {
		return false, errDNS
	}
	return false, nil
}

func (u *dnsUpstream) rawQuery(ctx context.Context, wire []byte, q dnsmessage.Question, id uint16) ([]byte, error) {
	var b []byte
	var e error
	switch u.ep.scheme {
	case "udp", "tcp":
		b, e = u.exchange(ctx, u.ep.scheme, wire)
	case "https":
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.ep.url, bytes.NewReader(wire))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		resp, err := u.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil || media != "application/dns-message" || resp.StatusCode != 200 {
			return nil, errDNS
		}
		b, e = io.ReadAll(io.LimitReader(resp.Body, maxDNSMessage+1))
	default:
		return nil, errDNS
	}
	if e != nil || len(b) > maxDNSMessage {
		return nil, errDNS
	}
	tc, e := validWireReply(b, id, q)
	if e != nil {
		return nil, e
	}
	if tc {
		if u.ep.scheme != "udp" {
			return nil, errDNS
		}
		b, e = u.exchange(ctx, "tcp", wire)
		if e != nil {
			return nil, e
		}
		tc, e = validWireReply(b, id, q)
		if e != nil || tc {
			return nil, errDNS
		}
	}
	return b, nil
}
func (s *Server) dnsTCP(parent context.Context) net.Conn {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		stop := context.AfterFunc(parent, func() { server.Close() })
		defer stop()
		for {
			_ = server.SetDeadline(time.Now().Add(s.cfg.Limits.UDPIdle.value()))
			var size [2]byte
			if _, e := io.ReadFull(server, size[:]); e != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(size[:]))
			if n < 12 {
				return
			}
			b := make([]byte, n)
			if _, e := io.ReadFull(server, b); e != nil {
				return
			}
			ctx, cancel := context.WithTimeout(parent, s.cfg.Limits.DialTimeout.value())
			reply, e := s.answerDNS(ctx, b, true)
			cancel()
			if e != nil {
				return
			}
			out := binary.BigEndian.AppendUint16(nil, uint16(len(reply)))
			out = append(out, reply...)
			if writeAll(server, out) != nil {
				return
			}
		}
	}()
	return client
}
func (s *Server) ClearDNSCache() (int, error) {
	if s.core.ctx.Err() != nil {
		return 0, ErrCoreNotRunning
	}
	// Retained UDP/business generations may still resolve new destinations.
	// Clearing only the current generation would leave those answers alive.
	s.gensMu.Lock()
	live := make([]*Server, 0, len(s.gens))
	for _, g := range s.gens {
		if g.tryRef() {
			live = append(live, g)
		}
	}
	s.gensMu.Unlock()
	if len(live) == 0 {
		return 0, ErrCoreNotRunning
	}
	count := 0
	for _, g := range live {
		count += g.dns.clearCache()
		g.unref()
	}
	return count, nil
}

// Resolve each query against the current generation: Windows may retain a DNS
// TCP connection/UDP association across ordinary document changes.
func (s *Server) answerDNS(ctx context.Context, wire []byte, tcp bool) ([]byte, error) {
	g := s.current()
	if !g.tryRef() {
		return nil, ErrCoreNotRunning
	}
	defer g.unref()
	return g.dns.gateway(ctx, wire, tcp)
}
