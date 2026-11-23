package kernel

// Ordinary DNS is answered inside the existing SOCKS data plane. The SYSTEM
// service configures only its owned TUN DNS peer; upstream queries use a
// separate owner/scope-bound transport. While controlled egress is installed, TCP/UDP destination port 53
// is handled before originalResolver's legacy physical passthrough. Resolver
// upstream sockets use the physical egress hook and cannot re-enter this gate.
import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/shui1iao/Kat/internal/outbound"
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
	server         string
	added, expires time.Time
	epoch          uint64
}

type clientGatewayPolicy struct {
	server *Server
}

func (s *Server) controlledDNS(a Address) bool {
	return a.Port == 53 && s.cfg.clientIPv6 != nil && s.cfg.clientEgress.active()
}

func dnsRequest(w []byte) (dnsmessage.Message, error) {
	var m dnsmessage.Message
	if len(w) < 12 || len(w) > maxDNSMessage || m.Unpack(w) != nil || m.Response || m.OpCode != 0 || len(m.Questions) != 1 || m.Questions[0].Class != dnsmessage.ClassINET || len(m.Answers) != 0 || len(m.Authorities) != 0 {
		return m, errDNS
	}
	// Unpack has already validated the DNS label encoding. Owner names are
	// not dial hostnames (e.g. the root, _service._tcp or a wildcard).
	// Never feed terminal/control bytes from a label to diagnostics/policy.
	name := m.Questions[0].Name.String()
	if len(name) > 254 || strings.IndexFunc(name, func(c rune) bool { return c < 0x21 || c > 0x7e }) >= 0 {
		return m, errDNS
	}
	return m, nil
}

func dnsGatewayReply(m dnsmessage.Message, code dnsmessage.RCode) dnsmessage.Message {
	return dnsmessage.Message{Header: dnsmessage.Header{ID: m.ID, Response: true, RecursionDesired: m.RecursionDesired, RecursionAvailable: true, RCode: code}, Questions: m.Questions}
}

func queryEDNS(query dnsmessage.Message) (int, bool) {
	limit := 512
	hasOPT := false
	for _, rr := range query.Additionals {
		if rr.Header.Type == dnsmessage.TypeOPT {
			hasOPT = true
			if n := int(rr.Header.Class); n > limit {
				limit = n
			}
		}
	}
	if limit > 4096 {
		limit = 4096
	}
	return limit, hasOPT
}

func responseOPTRR() dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("."),
			Type:  dnsmessage.TypeOPT,
			Class: dnsmessage.Class(4096),
			TTL:   0,
		},
		Body: &dnsmessage.OPTResource{},
	}
}

func stripOPTRecords(m *dnsmessage.Message) {
	if len(m.Additionals) == 0 {
		return
	}
	out := m.Additionals[:0]
	for _, rr := range m.Additionals {
		if rr.Header.Type != dnsmessage.TypeOPT {
			out = append(out, rr)
		}
	}
	m.Additionals = out
}

func applyResponseEDNS(m *dnsmessage.Message, wantOPT bool) {
	stripOPTRecords(m)
	if wantOPT {
		m.Additionals = append(m.Additionals, responseOPTRR())
	}
}

func (r *internalDNS) gateway(ctx context.Context, wire []byte, tcp bool) ([]byte, error) {
	return r.gatewayWithPolicy(ctx, wire, tcp, nil)
}

func (r *internalDNS) gatewayWithPolicy(ctx context.Context, wire []byte, tcp bool, pol *clientGatewayPolicy) (response []byte, result error) {
	started := time.Now()
	cacheHit := false
	delegated := false
	usedServer := ""
	qName := ""
	qType := ""
	var eventWire []byte
	mode := "custom"
	if len(r.upstreams) == 0 {
		mode = "system"
	}
	defer func() {
		category, native := outbound.Category(result)
		elapsed := time.Since(started).Milliseconds()
		var addrs []string
		outcome := "error"
		inspect := eventWire
		if len(inspect) == 0 {
			inspect = response
		}
		if result == nil && len(inspect) >= 12 {
			var m dnsmessage.Message
			if m.Unpack(inspect) == nil {
				addrs, _, _, _ = extractWireAddresses(inspect)
				if m.RCode == dnsmessage.RCodeNameError {
					category = "nxdomain"
					outcome = "nxdomain"
				} else if m.RCode != dnsmessage.RCodeSuccess {
					category = "dns"
					outcome = "error"
				} else if len(m.Answers) == 0 {
					category = "nodata"
					outcome = "nodata"
				} else {
					outcome = "ok"
				}
			}
		}
		r.observe(ctx, outbound.Diagnostic{Stage: "dns_exchange", Category: category, Protocol: mode, Native: native, ElapsedMS: outbound.Known(uint64(elapsed)), CacheHit: &cacheHit})
		if !delegated && r.eventSink != nil && qName != "" && result != context.Canceled {
			if addrs == nil {
				addrs = []string{}
			}
			r.eventSink(DNSEvent{
				Time:       time.Now(),
				Name:       qName,
				QType:      qType,
				Addresses:  addrs,
				Server:     usedServer,
				Cached:     cacheHit,
				DurationMS: elapsed,
				Outcome:    outcome,
				Source:     dnsSourceOf(ctx, "tun"),
			})
		}
	}()

	ctx, cancelScope, epoch := r.dnsScope(ctx)
	defer cancelScope()
	hostScope := r.beginHostScope(epoch)

	m, e := dnsRequest(wire)
	if e != nil {
		return nil, e
	}
	_, hasOPT := queryEDNS(m)
	q := m.Questions[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	qName = name
	if qName == "" {
		qName = "." // Preserve the root in the diagnostic record.
	}
	qType = dnsTypeString(q.Type)

	if pol != nil && pol.server != nil {
		if q.Type == dnsmessage.TypePTR {
			if ip, ok := reverseDNSIP(name); ok && ClientFakeIP(ip) {
				// Old synthetic identities are no longer loaded or recoverable. Never
				// forward their reverse queries or invent a name from stale state.
				delegated = true
				reply := dnsGatewayReply(m, dnsmessage.RCodeNameError)
				applyResponseEDNS(&reply, hasOPT)
				b, packErr := reply.Pack()
				if packErr != nil {
					return nil, packErr
				}
				return dnsDownstream(m, b, tcp), nil
			}
		}
		if !localDNSName(name) && (q.Type == dnsmessage.TypeHTTPS || q.Type == dnsmessage.TypeSVCB) {
			usedServer = "ECH 已屏蔽"
			reply := dnsGatewayReply(m, dnsmessage.RCodeSuccess)
			clean, packErr := reply.Pack()
			if packErr != nil {
				return nil, packErr
			}
			eventWire = clean
			applyResponseEDNS(&reply, hasOPT)
			packed, packErr := reply.Pack()
			if packErr != nil {
				return nil, packErr
			}
			return dnsDownstream(m, packed, tcp), nil
		}
	}

	reply := dnsGatewayReply(m, dnsmessage.RCodeSuccess)
	if q.Type == dnsmessage.TypeAAAA && r.disableIPv6 {
		usedServer = "IPv6 已关闭"
		clean, _ := reply.Pack()
		eventWire = clean
		applyResponseEDNS(&reply, hasOPT)
		b, e := reply.Pack()
		return dnsDownstream(m, b, tcp), e
	}
	if ips, ok := r.host(name); ok && (q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA) {
		usedServer = "hosts"
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
		clean, e := reply.Pack()
		if e != nil {
			return nil, e
		}
		eventWire = clean
		r.recordHostWire(clean, 0, false, hostScope)
		applyResponseEDNS(&reply, hasOPT)
		b, e := reply.Pack()
		return dnsDownstream(m, b, tcp), e
	}

	p := r.policy(name)
	if p == r && r.local != nil && localDNSName(name) {
		delegated = true
		return r.local.gatewayWithPolicy(ctx, wire, tcp, pol)
	}

	// Unified total deadline covering both local upstream and optional proxy TCP fallback.
	totalCtx := ctx
	if _, has := totalCtx.Deadline(); !has {
		var cancelTotal context.CancelFunc
		totalCtx, cancelTotal = context.WithTimeout(ctx, 5*time.Second)
		defer cancelTotal()
	}

	// One bounded worker per admitted connection/association; never per packet.
	select {
	case p.slots <- struct{}{}:
	case <-totalCtx.Done():
		return nil, totalCtx.Err()
	}
	defer func() { <-p.slots }()

	key := string(wire[2:])
	now := p.now()
	p.mu.Lock()
	startClearSeq := p.clearSeq
	entry, hit := p.wireCache[key]
	p.mu.Unlock()
	if hit && entry.epoch == epoch && epoch == p.dnsEpoch() && entry.expires.After(now) {
		var cached dnsmessage.Message
		if cached.Unpack(entry.wire) == nil {
			cached.ID = m.ID
			rem := entry.expires.Sub(now)
			age := uint32(now.Sub(entry.added) / time.Second)
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
			cleanAged, cleanErr := cached.Pack()
			if cleanErr == nil {
				if epoch != p.dnsEpoch() {
					return nil, context.Canceled
				}
				cacheHit = true
				usedServer = entry.server
				eventWire = cleanAged
				r.recordHostWire(cleanAged, rem, true, hostScope)
				applyResponseEDNS(&cached, hasOPT)
				b, e := cached.Pack()
				return dnsDownstream(m, b, tcp), e
			}
		}
	}

	staticProxy := ""
	if pol != nil && pol.server != nil {
		s := pol.server
		if s.cfg.clientDNS != nil && !explicitDNSRoot(s.cfg.clientDNS.Source) && !r.protected && !localDNSName(name) && p == r && (q.Type == dnsmessage.TypeA || q.Type == dnsmessage.TypeAAAA) {
			staticProxy = s.staticDomainProxy(name)
		}
	}

	upstreams := append([]*dnsUpstream(nil), p.upstreams...)
	// Preserve the existing custom -> physical/system fallback chain. No public
	// resolver is invented for system-only clients, and selected rule chains do
	// not silently leak to the system resolver when they fail.
	useSystem := !p.protected && (p == r || len(upstreams) == 0) && p.systemQuery != nil
	if !p.protected && (p == r || len(upstreams) == 0) && p.systemQuery == nil {
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

	totalDeadline, _ := totalCtx.Deadline()
	localDeadline := totalDeadline
	if staticProxy != "" {
		rem := time.Until(totalDeadline)
		if rem > 0 {
			// Reserve 60% of the total budget for protected proxy TCP fallback when local hangs;
			// fast local negative/blackhole answers immediately release the unused share.
			localSub := (rem * 2) / 5
			if localSub <= 0 {
				localSub = rem / 2
			}
			localDeadline = time.Now().Add(localSub)
		}
	}

	attempts := len(upstreams)
	if useSystem {
		attempts++
	}
	var rawMsg dnsmessage.Message
	var rawSrv string
	gotPrimary := false
	var lastOtherMsg dnsmessage.Message
	var lastOtherSrv string
	hasLastOther := false

	for i := 0; i < attempts; i++ {
		remaining := time.Until(localDeadline)
		if remaining <= 0 || ctx.Err() == context.Canceled {
			break
		}
		attempt, cancel := context.WithTimeout(totalCtx, remaining/time.Duration(attempts-i))
		var b []byte
		var e error
		curSrv := "system"
		if i < len(upstreams) {
			curSrv = upstreams[i].ep.label()
			b, e = upstreams[i].rawQuery(attempt, wire, q, m.ID)
		} else {
			b, e = p.systemQuery(attempt, wire)
			p.observeError(ctx, "dns_exchange", "system", e, started)
		}
		cancel()
		if e != nil {
			continue
		}
		var answer dnsmessage.Message
		if answer.Unpack(b) != nil {
			continue
		}
		if answer.RCode == dnsmessage.RCodeSuccess || answer.RCode == dnsmessage.RCodeNameError {
			rawMsg = answer
			rawSrv = curSrv
			gotPrimary = true
			break
		}
		lastOtherMsg = answer
		lastOtherSrv = curSrv
		hasLastOther = true
	}

	gotAnswer := gotPrimary
	if !gotAnswer && hasLastOther {
		rawMsg = lastOtherMsg
		rawSrv = lastOtherSrv
		gotAnswer = true
	}

	fallbackSucceeded := false
	if pol != nil && pol.server != nil {
		s := pol.server
		if staticProxy != "" && ctx.Err() != context.Canceled {
			needFallback := !gotAnswer ||
				replyHasBlackholeIP(rawMsg) ||
				rawMsg.RCode == dnsmessage.RCodeNameError ||
				rawMsg.RCode == dnsmessage.RCodeRefused ||
				rawMsg.RCode == dnsmessage.RCodeServerFailure
			if needFallback && totalCtx.Err() == nil {
				if _, cleanMsg, srv, ok := s.fallbackProxyTCPDNS(totalCtx, staticProxy, m, q, wire); ok {
					rawMsg = cleanMsg
					rawSrv = "TCP " + srv
					gotAnswer = true
					fallbackSucceeded = true
				}
			}
			if !fallbackSucceeded && gotAnswer && replySectionsHaveFakeIP(rawMsg) {
				return nil, errFakeIP
			}
		} else if gotAnswer && replySectionsHaveFakeIP(rawMsg) {
			// Enforce legacy synthetic pool rejection on protected/explicit custom DNS,
			// while preserving approved local system answers for ordinary/direct/LAN names.
			if r.protected || (s.cfg.clientDNS != nil && explicitDNSRoot(s.cfg.clientDNS.Source)) || p != r {
				return nil, errFakeIP
			}
		}
	}

	if !gotAnswer {
		if epoch != p.dnsEpoch() || ctx.Err() == context.Canceled {
			return nil, context.Canceled
		}
		reply.RCode = dnsmessage.RCodeServerFailure
		cleanFail, _ := reply.Pack()
		eventWire = cleanFail
		applyResponseEDNS(&reply, hasOPT)
		b, e := reply.Pack()
		return dnsDownstream(m, b, tcp), e
	}

	usedServer = rawSrv
	// The local-name exception applies to the reply as well as the query.
	// In particular, retain service bindings and ALPN from a LAN resolver.
	if pol != nil && pol.server != nil && !localDNSName(name) && stripECHRecords(&rawMsg) {
		rawMsg.AuthenticData = false // the upstream did not authenticate our edited RRsets
	}
	stripOPTRecords(&rawMsg)

	cleanBytes, packErr := rawMsg.Pack()
	if packErr != nil {
		return nil, packErr
	}
	eventWire = cleanBytes

	ttl := minWireTTL(rawMsg)
	cacheable := epoch == p.dnsEpoch() &&
		ctx.Err() == nil &&
		p.capacity > 0 &&
		ttl > 0 &&
		!rawMsg.Truncated &&
		rawMsg.RCode == dnsmessage.RCodeSuccess &&
		len(rawMsg.Answers) > 0 &&
		(pol == nil || !replyHasBlackholeIP(rawMsg))
	if cacheable {
		nowStore := p.now()
		p.mu.Lock()
		if p.clearSeq == startClearSeq {
			if _, exists := p.wireCache[key]; !exists && len(p.wireCache) >= p.capacity {
				for k, v := range p.wireCache {
					delete(p.wireCache, k)
					if v.epoch != epoch || !v.expires.After(nowStore) {
						continue
					}
					break
				}
			}
			p.wireCache[key] = dnsWireEntry{append([]byte(nil), cleanBytes...), usedServer, nowStore, nowStore.Add(time.Duration(ttl) * time.Second), epoch}
		}
		p.mu.Unlock()
	}

	if epoch != p.dnsEpoch() || ctx.Err() == context.Canceled {
		return nil, context.Canceled
	}
	r.recordHostWire(cleanBytes, 0, false, hostScope)

	applyResponseEDNS(&rawMsg, hasOPT)
	wireOut, packErr := rawMsg.Pack()
	if packErr != nil {
		return nil, packErr
	}
	return dnsDownstream(m, wireOut, tcp), nil
}

func dnsDownstream(query dnsmessage.Message, b []byte, tcp bool) []byte {
	if tcp {
		return b
	}
	limit, hasOPT := queryEDNS(query)
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
	if hasOPT {
		response.Additionals = []dnsmessage.Resource{responseOPTRR()}
	}
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

func (u *dnsUpstream) rawQuery(ctx context.Context, wire []byte, q dnsmessage.Question, id uint16) (response []byte, result error) {
	started := time.Now()
	defer func() { u.resolver.observeError(ctx, "dns_exchange", u.ep.scheme, result, started) }()
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
		u.resolver.observe(ctx, outbound.Diagnostic{Stage: "dns_fallback", Category: "truncated_tcp", Protocol: u.ep.scheme})
		if u.ep.scheme != "udp" {
			return nil, errDNS
		}
		b, e = u.exchange(ctx, "tcp", wire)
		if e != nil {
			return nil, errDNS
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

func (s *Server) ClearDNSCache(closeIdle ...bool) (int, error) {
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
		if len(closeIdle) > 0 && closeIdle[0] {
			visitedClose := map[*internalDNS]bool{}
			g.dns.closeVisited(visitedClose)
			g.directDNS.closeVisited(visitedClose)
			g.bootstrapDNS.closeVisited(visitedClose)
		}
		visitedClear := map[*internalDNS]bool{}
		count += g.dns.clearCacheVisited(visitedClear)
		count += g.directDNS.clearCacheVisited(visitedClear)
		count += g.bootstrapDNS.clearCacheVisited(visitedClear)
		g.unref()
	}
	if s.core != nil && s.core.dnsHosts != nil {
		s.core.dnsHosts.bump()
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
	reply, err := g.answerClientDNS(ctx, wire, tcp)
	if err == nil {
		if g.rt != nil && g.rt.icmp != nil {
			g.rt.icmp.noteDNSWire(reply)
		}
	}
	return reply, err
}
