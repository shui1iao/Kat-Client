package kernel

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/route"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Ordinary DNS is answered inside the existing SOCKS data plane. The SYSTEM
// service configures only its owned TUN DNS peer; upstream queries use a
// separate owner/scope-bound transport. While controlled egress is installed, TCP/UDP destination port 53
// is handled before originalResolver's legacy physical passthrough. Resolver
// upstream sockets use the physical egress hook and cannot re-enter this gate.
type dnsTTLSlot struct {
	off uint16
	ttl uint32
}

type dnsWireEntry struct {
	wire           []byte
	ttlSlots       []dnsTTLSlot
	server         string
	added, expires time.Time
	epoch          uint64
}

var ednsOPTRRWire = [...]byte{
	0x00,       // root name "."
	0x00, 0x29, // TypeOPT (41)
	0x10, 0x00, // UDP payload size 4096
	0x00, 0x00, 0x00, 0x00, // extended RCODE & flags
	0x00, 0x00, // RDLENGTH 0
}

func skipDNSWireName(w []byte, off int) (int, bool) {
	for hops := 0; hops < 128; hops++ {
		if off >= len(w) {
			return 0, false
		}
		l := int(w[off])
		if l == 0 {
			return off + 1, true
		}
		if l&0xc0 == 0xc0 {
			if off+2 > len(w) {
				return 0, false
			}
			return off + 2, true
		}
		if l&0xc0 != 0 {
			return 0, false
		}
		off += 1 + l
	}
	return 0, false
}

func scanDNSTTLSlotsInto(w []byte, dst []dnsTTLSlot) ([]dnsTTLSlot, bool) {
	if len(w) < 12 || len(w) > 65535 {
		return nil, false
	}
	qd := int(binary.BigEndian.Uint16(w[4:6]))
	an := int(binary.BigEndian.Uint16(w[6:8]))
	ns := int(binary.BigEndian.Uint16(w[8:10]))
	ar := int(binary.BigEndian.Uint16(w[10:12]))
	off := 12
	for i := 0; i < qd; i++ {
		var ok bool
		off, ok = skipDNSWireName(w, off)
		if !ok || off+4 > len(w) {
			return nil, false
		}
		off += 4
	}
	totalRR := an + ns + ar
	for i := 0; i < totalRR; i++ {
		var ok bool
		off, ok = skipDNSWireName(w, off)
		if !ok || off+10 > len(w) {
			return nil, false
		}
		rrType := binary.BigEndian.Uint16(w[off : off+2])
		ttl := binary.BigEndian.Uint32(w[off+4 : off+8])
		rdLen := int(binary.BigEndian.Uint16(w[off+8 : off+10]))
		if rrType != uint16(dnsmessage.TypeOPT) {
			dst = append(dst, dnsTTLSlot{off: uint16(off + 4), ttl: ttl})
		}
		off += 10 + rdLen
		if off > len(w) {
			return nil, false
		}
	}
	if off != len(w) {
		return nil, false
	}
	return dst, true
}

func parseDNSQueryFast(w []byte, lowerOut *[255]byte) (id uint16, q dnsmessage.Question, lowerLen int, ednsLimit int, hasOPT bool, ok bool) {
	if len(w) < 12 || len(w) > maxDNSMessage {
		return 0, q, 0, 0, false, false
	}
	flags := binary.BigEndian.Uint16(w[2:4])
	if flags&0x8000 != 0 || (flags>>11)&0x0f != 0 {
		return 0, q, 0, 0, false, false
	}
	qd := binary.BigEndian.Uint16(w[4:6])
	an := binary.BigEndian.Uint16(w[6:8])
	ns := binary.BigEndian.Uint16(w[8:10])
	ar := binary.BigEndian.Uint16(w[10:12])
	if qd != 1 || an != 0 || ns != 0 {
		return 0, q, 0, 0, false, false
	}
	id = binary.BigEndian.Uint16(w[0:2])
	nLen := 0
	off := 12
	for {
		if off >= len(w) {
			return 0, q, 0, 0, false, false
		}
		l := int(w[off])
		off++
		if l == 0 {
			break
		}
		if l > 63 || off+l > len(w) || nLen+l+1 > 254 {
			return 0, q, 0, 0, false, false
		}
		for i := 0; i < l; i++ {
			c := w[off+i]
			if c < 0x21 || c > 0x7e || c == '.' || c == '\\' {
				return 0, q, 0, 0, false, false
			}
			q.Name.Data[nLen+i] = c
			if c >= 'A' && c <= 'Z' {
				lowerOut[nLen+i] = c + ('a' - 'A')
			} else {
				lowerOut[nLen+i] = c
			}
		}
		nLen += l
		q.Name.Data[nLen] = '.'
		lowerOut[nLen] = '.'
		nLen++
		off += l
	}
	if off+4 > len(w) {
		return 0, q, 0, 0, false, false
	}
	qType := dnsmessage.Type(binary.BigEndian.Uint16(w[off : off+2]))
	qClass := dnsmessage.Class(binary.BigEndian.Uint16(w[off+2 : off+4]))
	if qClass != dnsmessage.ClassINET {
		return 0, q, 0, 0, false, false
	}
	off += 4
	ednsLimit = 512
	for i := uint16(0); i < ar; i++ {
		if off >= len(w) || w[off] != 0 || off+11 > len(w) {
			return 0, q, 0, 0, false, false
		}
		rrType := dnsmessage.Type(binary.BigEndian.Uint16(w[off+1 : off+3]))
		rrClass := int(binary.BigEndian.Uint16(w[off+3 : off+5]))
		rdLen := int(binary.BigEndian.Uint16(w[off+9 : off+11]))
		if rrType != dnsmessage.TypeOPT || rdLen != 0 || hasOPT {
			return 0, q, 0, 0, false, false
		}
		off += 11
		hasOPT = true
		if rrClass > ednsLimit {
			ednsLimit = rrClass
		}
	}
	if off != len(w) {
		return 0, q, 0, 0, false, false
	}
	if ednsLimit > 4096 {
		ednsLimit = 4096
	}
	q.Type = qType
	q.Class = qClass
	if nLen == 0 {
		q.Name.Data[0] = '.'
		q.Name.Length = 1
		return id, q, 0, ednsLimit, hasOPT, true
	}
	q.Name.Length = uint8(nLen)
	return id, q, nLen - 1, ednsLimit, hasOPT, true
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
	hasOPT := false
	for _, rr := range m.Additionals {
		if rr.Header.Type != dnsmessage.TypeOPT || rr.Header.Name.String() != "." || hasOPT {
			return m, errDNS
		}
		hasOPT = true
	}
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
			rcode := dnsmessage.RCode(inspect[3] & 0x0f)
			ancount := binary.BigEndian.Uint16(inspect[6:8])
			if rcode == dnsmessage.RCodeNameError {
				category = "nxdomain"
				outcome = "nxdomain"
			} else if rcode != dnsmessage.RCodeSuccess {
				category = "dns"
				outcome = "error"
			} else if ancount == 0 {
				category = "nodata"
				outcome = "nodata"
			} else {
				outcome = "ok"
			}
			if !delegated && r.eventSink != nil {
				addrs, _, _, _ = extractWireAddresses(inspect)
			}
		}
		if r.diagnostic != nil {
			r.observe(ctx, outbound.Diagnostic{Stage: "dns_exchange", Category: category, Protocol: mode, Native: native, ElapsedMS: outbound.Known(uint64(elapsed)), CacheHit: &cacheHit})
		}
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

	var (
		m         dnsmessage.Message
		q         dnsmessage.Question
		lowerBuf  [255]byte
		lowerLen  int
		fastOK    bool
		name      string
		ednsLimit int
		hasOPT    bool
	)
	if id, fq, flen, flimit, fopt, ok := parseDNSQueryFast(wire, &lowerBuf); ok {
		fastOK = true
		lowerLen = flen
		m.ID = id
		m.RecursionDesired = (wire[2] & 0x01) != 0
		q = fq
		ednsLimit = flimit
		hasOPT = fopt
	} else {
		var e error
		m, e = dnsRequest(wire)
		if e != nil {
			return nil, e
		}
		ednsLimit, hasOPT = queryEDNS(m)
		q = m.Questions[0]
		name = strings.ToLower(strings.TrimSuffix(q.Name.String(), "."))
	}
	qType = dnsTypeString(q.Type)

	if fastOK && pol == nil && !(q.Type == dnsmessage.TypeAAAA && r.disableIPv6) && len(r.hosts) == 0 && len(r.rules) == 0 && r.local == nil && r.eventSink == nil {
		now := r.now()
		r.mu.Lock()
		entry, hit := r.wireCache[string(wire[2:])]
		r.mu.Unlock()
		if hit && entry.epoch == epoch && epoch == r.dnsEpoch() && entry.expires.After(now) {
			if out, ok := buildAgedWireReply(r, entry, m, now, epoch, ednsLimit, hasOPT, tcp, hostScope, &eventWire); ok {
				if out == nil {
					return nil, context.Canceled
				}
				cacheHit = true
				usedServer = entry.server
				return out, nil
			}
		}
	}

	if fastOK {
		name = string(lowerBuf[:lowerLen])
		m.Questions = []dnsmessage.Question{q}
	}
	qName = name
	if qName == "" {
		qName = "." // Preserve the root in the diagnostic record.
	}

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
				return dnsDownstreamWithEDNS(m, b, tcp, ednsLimit, hasOPT), nil
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
			return dnsDownstreamWithEDNS(m, packed, tcp, ednsLimit, hasOPT), nil
		}
	}

	reply := dnsGatewayReply(m, dnsmessage.RCodeSuccess)
	if q.Type == dnsmessage.TypeAAAA && r.disableIPv6 {
		usedServer = "IPv6 已关闭"
		clean, _ := reply.Pack()
		eventWire = clean
		applyResponseEDNS(&reply, hasOPT)
		b, e := reply.Pack()
		return dnsDownstreamWithEDNS(m, b, tcp, ednsLimit, hasOPT), e
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
		return dnsDownstreamWithEDNS(m, b, tcp, ednsLimit, hasOPT), e
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

	now := p.now()
	p.mu.Lock()
	startClearSeq := p.clearSeq
	entry, hit := p.wireCache[string(wire[2:])]
	p.mu.Unlock()
	if hit && entry.epoch == epoch && epoch == r.dnsEpoch() && entry.expires.After(now) {
		if out, ok := buildAgedWireReply(r, entry, m, now, epoch, ednsLimit, hasOPT, tcp, hostScope, &eventWire); ok {
			if out == nil {
				return nil, context.Canceled
			}
			cacheHit = true
			usedServer = entry.server
			return out, nil
		}
	}
	key := string(wire[2:])

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
		return dnsDownstreamWithEDNS(m, b, tcp, ednsLimit, hasOPT), e
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
				var oldestKey string
				var oldestAdded time.Time
				for k, v := range p.wireCache {
					if v.epoch != epoch || !v.expires.After(nowStore) {
						delete(p.wireCache, k)
						continue
					}
					if oldestKey == "" || v.added.Before(oldestAdded) {
						oldestKey = k
						oldestAdded = v.added
					}
				}
				if len(p.wireCache) >= p.capacity && oldestKey != "" {
					delete(p.wireCache, oldestKey)
				}
			}
			storedWire := bytes.Clone(cleanBytes)
			slots, _ := scanDNSTTLSlotsInto(storedWire, nil)
			if slots == nil {
				slots = []dnsTTLSlot{}
			}
			p.wireCache[key] = dnsWireEntry{
				wire:     storedWire,
				ttlSlots: slots,
				server:   usedServer,
				added:    nowStore,
				expires:  nowStore.Add(time.Duration(ttl) * time.Second),
				epoch:    epoch,
			}
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
	return dnsDownstreamWithEDNS(m, wireOut, tcp, ednsLimit, hasOPT), nil
}

func buildAgedWireReply(r *internalDNS, entry dnsWireEntry, m dnsmessage.Message, now time.Time, epoch uint64, ednsLimit int, hasOPT, tcp bool, hostScope dnsHostScope, eventWire *[]byte) ([]byte, bool) {
	var stackSlots [16]dnsTTLSlot
	slots := entry.ttlSlots
	validWire := slots != nil
	if !validWire {
		slots, validWire = scanDNSTTLSlotsInto(entry.wire, stackSlots[:0])
	}
	if !validWire {
		return nil, false
	}
	rem := entry.expires.Sub(now)
	age := uint32(now.Sub(entry.added) / time.Second)
	extra := 0
	if hasOPT {
		extra = len(ednsOPTRRWire)
	}
	out := make([]byte, len(entry.wire), len(entry.wire)+extra)
	copy(out, entry.wire)
	binary.BigEndian.PutUint16(out[0:2], m.ID)
	for _, sl := range slots {
		newTTL := uint32(0)
		if sl.ttl > age {
			newTTL = sl.ttl - age
		}
		binary.BigEndian.PutUint32(out[sl.off:sl.off+4], newTTL)
	}
	if epoch != r.dnsEpoch() {
		return nil, true
	}
	r.recordHostWire(out, rem, true, hostScope)
	if hasOPT {
		if r.eventSink != nil {
			*eventWire = bytes.Clone(out)
		}
		ar := binary.BigEndian.Uint16(out[10:12])
		binary.BigEndian.PutUint16(out[10:12], ar+1)
		out = append(out, ednsOPTRRWire[:]...)
		if *eventWire == nil {
			*eventWire = out
		}
	} else {
		*eventWire = out
	}
	if !tcp && len(out) > ednsLimit {
		if len(m.Questions) == 0 {
			var qm dnsmessage.Message
			if qm.Unpack(out) == nil {
				m.Questions = qm.Questions
			}
		}
		return dnsDownstreamLimit(m, out, ednsLimit, hasOPT), true
	}
	return out, true
}

func dnsDownstream(query dnsmessage.Message, b []byte, tcp bool) []byte {
	if tcp {
		return b
	}
	limit, hasOPT := queryEDNS(query)
	return dnsDownstreamLimit(query, b, limit, hasOPT)
}

func dnsDownstreamWithEDNS(query dnsmessage.Message, b []byte, tcp bool, limit int, hasOPT bool) []byte {
	if tcp {
		return b
	}
	return dnsDownstreamLimit(query, b, limit, hasOPT)
}

func dnsDownstreamLimit(query dnsmessage.Message, b []byte, limit int, hasOPT bool) []byte {
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

// tunDNSQuery uses the real gateway unchanged. Only client payload is metered;
// retries, cache work and TCP length prefixes are not business/direct traffic.
func (s *Server) tunDNSQuery(ctx context.Context, f *flow, target Address, p []byte, tcp bool, output func([]byte) error) error {
	f.udpUp(nil, len(p))
	tunDNSMeta(f, target)
	var query dnsmessage.Parser
	if _, err := query.Start(p); err == nil {
		if q, err := query.Question(); err == nil {
			f.mu.Lock()
			f.details.DNSQueryType = uint16(q.Type)
			f.mu.Unlock()
		}
	}
	qctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.DialTimeout.value())
	reply, e := s.answerDNS(qctx, p, tcp)
	cancel()
	if e != nil {
		f.udpDNS(target, "dns_query_failed", e)
		s.counters.Dropped.Add(1)
		return e
	}
	var parser dnsmessage.Parser
	h, e := parser.Start(reply)
	if e == nil {
		code := uint16(h.RCode)
		f.mu.Lock()
		f.details.DNSRCode = &code
		f.mu.Unlock()
	}
	var outcomeErr error
	if e != nil || !h.Response || (h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError) {
		outcomeErr = errors.New("DNS upstream returned a failure response")
		f.udpDNS(target, "dns_query_failed", errors.New("DNS upstream returned a failure response"))
	}
	if e = output(reply); e != nil {
		f.udpDNS(target, "dns_response_failed", e)
		s.counters.Dropped.Add(1)
		return e
	}
	f.udpDown(nil, len(reply))
	if outcomeErr == nil {
		f.emitConnection(target.String(), "dns", []string{"dns"}, "ok", "")
	}
	return outcomeErr
}
func tunDNSMeta(f *flow, target Address) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.target = target.String()
	f.ruleKey = "dns"
	f.chain = []string{"dns"}
	f.mu.Unlock()
}

// TCP owns transport framing only. Each query owns its own real record and
// payload meter; an empty transport does not manufacture an empty "ok" flow.
func (s *Server) tunDNSTCP(ctx context.Context, c net.Conn, target Address) error {
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	for {
		_ = c.SetReadDeadline(time.Now().Add(s.cfg.Limits.UDPIdle.value()))
		var size [2]byte
		n, e := io.ReadFull(c, size[:])
		if e != nil && n == 0 && (errors.Is(e, io.EOF) || ctx.Err() != nil || timeoutError(e)) {
			return e
		}
		f, fctx := s.newFlow(ctx, "tcp", Address{})
		tunDNSMeta(f, target)
		if e != nil {
			f.udpDNS(target, "dns_query_failed", e)
			f.end("dns_query_failed")
			return e
		}
		p := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		n, e = io.ReadFull(c, p)
		if e != nil {
			f.udpUp(nil, n)
			f.udpDNS(target, "dns_query_failed", e)
			f.end("dns_query_failed")
			return e
		}
		var writeErr error
		e = s.tunDNSQuery(fctx, f, target, p, true, func(reply []byte) error {
			_ = c.SetWriteDeadline(time.Now().Add(s.cfg.Limits.DialTimeout.value()))
			wire := binary.BigEndian.AppendUint16(nil, uint16(len(reply)))
			wire = append(wire, reply...)
			writeErr = writeAll(c, wire)
			return writeErr
		})
		if e != nil {
			f.end("dns_query_failed")
			if writeErr != nil || f.down.Load() == 0 {
				return e
			}
			continue
		}
		f.end("ok")
	}
}
