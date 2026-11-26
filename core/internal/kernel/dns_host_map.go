package kernel

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	maxDNSHostEntries = 4096
	minDNSHostTTL     = 60 * time.Second
	maxDNSHostTTL     = time.Hour
)

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// isLANTargetIP reports whether ip is a private/LAN/link-local/CGNAT address.
// Loopback (127.0.0.0/8, ::1) is intentionally excluded so local test fixtures
// such as TestSniffOverrideDestination (127.0.0.2) preserve exact behavior.
func isLANTargetIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || cgnatPrefix.Contains(ip)
}

func isPublicRoutableDNSIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || isLANTargetIP(ip) || ClientFakeIP(ip) {
		return false
	}
	return true
}

func clampDNSHostTTL(d time.Duration) time.Duration {
	if d < minDNSHostTTL {
		return minDNSHostTTL
	}
	if d > maxDNSHostTTL {
		return maxDNSHostTTL
	}
	return d
}

// dnsHostScope binds reverse DNS mappings to both the physical network epoch
// and the active DNS/hosts configuration generation + manual clear revision.
type dnsHostScope struct {
	genID    uint64
	netEpoch uint64
	rev      uint64
}

func (s dnsHostScope) valid() bool {
	return s.rev != 0
}

type dnsHostEntry struct {
	host      string
	expires   time.Time
	scope     dnsHostScope
	ambiguous bool
}

type dnsHostMap struct {
	mu      sync.RWMutex
	rev     uint64
	entries map[netip.Addr]dnsHostEntry
	now     func() time.Time
}

func newDNSHostMap() *dnsHostMap {
	return &dnsHostMap{
		rev:     1,
		entries: make(map[netip.Addr]dnsHostEntry),
		now:     time.Now,
	}
}

func (m *dnsHostMap) currentRev() uint64 {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	rev := m.rev
	m.mu.RUnlock()
	return rev
}

func (m *dnsHostMap) count() uint64 {
	if m == nil {
		return 0
	}
	m.mu.RLock()
	n := len(m.entries)
	m.mu.RUnlock()
	return uint64(n)
}

func normalizeDNSHostName(host string) (string, bool) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || isECHOuterSNI(host) {
		return "", false
	}
	if _, err := dnsName(host); err != nil {
		return "", false
	}
	return host, true
}

// putScoped records or refreshes ip -> host when startScope still matches the
// live scope at commit time. When fromCache is true, ttl is treated as the
// remaining cache lifetime (capped at maxDNSHostTTL without applying the 60s
// fresh floor). Conflicting active domains on the same IP mark the IP ambiguous.
func (m *dnsHostMap) putScoped(host string, ip netip.Addr, ttl time.Duration, fromCache bool, startScope dnsHostScope, liveNetEpoch func() (uint64, uint64, bool)) {
	if m == nil || !startScope.valid() || !isPublicRoutableDNSIP(ip) {
		return
	}
	normHost, ok := normalizeDNSHostName(host)
	if !ok {
		return
	}
	if fromCache {
		if ttl <= 0 {
			return
		}
		if ttl > maxDNSHostTTL {
			ttl = maxDNSHostTTL
		}
	} else {
		ttl = clampDNSHostTTL(ttl)
	}
	ip = ip.Unmap()

	m.mu.Lock()
	defer m.mu.Unlock()
	if startScope.rev != m.rev {
		return
	}
	if liveNetEpoch != nil {
		curGen, curNet, alive := liveNetEpoch()
		if !alive || curGen != startScope.genID || curNet != startScope.netEpoch {
			return
		}
	}
	now := m.now()
	exp := now.Add(ttl)

	if cur, exists := m.entries[ip]; exists && cur.scope == startScope && cur.expires.After(now) {
		if cur.expires.After(exp) {
			exp = cur.expires
		}
		if cur.ambiguous || cur.host != normHost {
			m.entries[ip] = dnsHostEntry{
				expires:   exp,
				scope:     startScope,
				ambiguous: true,
			}
			return
		}
		m.entries[ip] = dnsHostEntry{
			host:    normHost,
			expires: exp,
			scope:   startScope,
		}
		return
	}

	if _, exists := m.entries[ip]; !exists && len(m.entries) >= maxDNSHostEntries {
		var oldest netip.Addr
		var earliest time.Time
		evictedExpired := false
		for k, v := range m.entries {
			if v.scope != startScope || !v.expires.After(now) {
				delete(m.entries, k)
				evictedExpired = true
				if len(m.entries) < maxDNSHostEntries {
					break
				}
				continue
			}
			if earliest.IsZero() || v.expires.Before(earliest) {
				oldest, earliest = k, v.expires
			}
		}
		if !evictedExpired && len(m.entries) >= maxDNSHostEntries && oldest.IsValid() {
			delete(m.entries, oldest)
		}
	}
	m.entries[ip] = dnsHostEntry{
		host:    normHost,
		expires: exp,
		scope:   startScope,
	}
}

func (m *dnsHostMap) recordIPsScoped(host string, ips []netip.Addr, ttl time.Duration, fromCache bool, startScope dnsHostScope, liveNetEpoch func() (uint64, uint64, bool)) {
	if m == nil || len(ips) == 0 || !startScope.valid() {
		return
	}
	for _, ip := range ips {
		m.putScoped(host, ip, ttl, fromCache, startScope, liveNetEpoch)
	}
}

type wireAnswerRecord struct {
	ip  netip.Addr
	ttl time.Duration
}

// extractWireChainRecords follows bounded CNAME chains starting at Question[0]
// and computes each A/AAAA record's effective TTL as min(CNAME chain TTLs, RR TTL).
func extractWireChainRecords(wire []byte) (string, []wireAnswerRecord) {
	if len(wire) < 12 {
		return "", nil
	}
	var msg dnsmessage.Message
	if msg.Unpack(wire) != nil || !msg.Response || msg.RCode != dnsmessage.RCodeSuccess || len(msg.Questions) != 1 || len(msg.Answers) == 0 {
		return "", nil
	}
	qname := strings.ToLower(strings.TrimSuffix(msg.Questions[0].Name.String(), "."))
	if _, ok := normalizeDNSHostName(qname); !ok {
		return "", nil
	}
	owner := strings.ToLower(msg.Questions[0].Name.String())
	hasChainTTL := false
	var chainMinTTL uint32
	seen := map[string]bool{}
	var out []wireAnswerRecord

	for depth := 0; depth <= 8; depth++ {
		if seen[owner] {
			break
		}
		seen[owner] = true
		var nextCNAME string
		for _, rr := range msg.Answers {
			if rr.Header.Class != dnsmessage.ClassINET || !strings.EqualFold(rr.Header.Name.String(), owner) {
				continue
			}
			switch b := rr.Body.(type) {
			case *dnsmessage.CNAMEResource:
				if nextCNAME == "" {
					nextCNAME = strings.ToLower(b.CNAME.String())
				}
				if !hasChainTTL || rr.Header.TTL < chainMinTTL {
					chainMinTTL = rr.Header.TTL
					hasChainTTL = true
				}
			case *dnsmessage.AResource:
				eff := rr.Header.TTL
				if hasChainTTL && chainMinTTL < eff {
					eff = chainMinTTL
				}
				out = append(out, wireAnswerRecord{
					ip:  netip.AddrFrom4(b.A),
					ttl: time.Duration(eff) * time.Second,
				})
			case *dnsmessage.AAAAResource:
				eff := rr.Header.TTL
				if hasChainTTL && chainMinTTL < eff {
					eff = chainMinTTL
				}
				out = append(out, wireAnswerRecord{
					ip:  netip.AddrFrom16(b.AAAA).Unmap(),
					ttl: time.Duration(eff) * time.Second,
				})
			}
		}
		if len(out) > 0 || nextCNAME == "" {
			break
		}
		owner = nextCNAME
	}
	return qname, out
}

func (m *dnsHostMap) recordWireScoped(wire []byte, remainingCap time.Duration, fromCache bool, startScope dnsHostScope, liveNetEpoch func() (uint64, uint64, bool)) {
	if m == nil || !startScope.valid() {
		return
	}
	qname, records := extractWireChainRecords(wire)
	if qname == "" || len(records) == 0 {
		return
	}
	for _, rec := range records {
		ttl := rec.ttl
		if fromCache {
			if remainingCap <= 0 {
				return
			}
			if ttl <= 0 || remainingCap < ttl {
				ttl = remainingCap
			}
		}
		m.putScoped(qname, rec.ip, ttl, fromCache, startScope, liveNetEpoch)
	}
}

func (m *dnsHostMap) lookupScoped(ip netip.Addr, expectedGen, expectedNetEpoch uint64) (string, bool) {
	if m == nil || !ip.IsValid() {
		return "", false
	}
	ip = ip.Unmap()
	now := m.now()
	m.mu.RLock()
	rev := m.rev
	e, ok := m.entries[ip]
	m.mu.RUnlock()
	if !ok {
		return "", false
	}
	expected := dnsHostScope{genID: expectedGen, netEpoch: expectedNetEpoch, rev: rev}
	if e.scope != expected || !e.expires.After(now) {
		m.mu.Lock()
		curRev := m.rev
		curExpected := dnsHostScope{genID: expectedGen, netEpoch: expectedNetEpoch, rev: curRev}
		if cur, exists := m.entries[ip]; exists && (cur.scope != curExpected || !cur.expires.After(now)) {
			delete(m.entries, ip)
		}
		m.mu.Unlock()
		return "", false
	}
	if e.ambiguous || isECHOuterSNI(e.host) {
		return "", e.ambiguous
	}
	return e.host, false
}

func (m *dnsHostMap) bump() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.rev++
	clear(m.entries)
	m.mu.Unlock()
}

func (m *dnsHostMap) clear() {
	m.bump()
}

func (s *Server) currentNetEpoch() uint64 {
	if s == nil {
		return 0
	}
	if s.dns != nil {
		return s.dns.dnsEpoch()
	}
	if s.cfg.clientEgress != nil && s.cfg.clientEgress.DNSContext != nil {
		_, cancel, ep := s.cfg.clientEgress.DNSContext(s.ctx)
		cancel()
		return ep
	}
	return 0
}

func (s *Server) beginDNSHostScope() dnsHostScope {
	if s == nil || s.core == nil || s.core.dnsHosts == nil {
		return dnsHostScope{}
	}
	return dnsHostScope{
		genID:    s.id,
		netEpoch: s.currentNetEpoch(),
		rev:      s.core.dnsHosts.currentRev(),
	}
}

func (s *Server) beginDNSHostScopeWithEpoch(netEpoch uint64) dnsHostScope {
	if s == nil || s.core == nil || s.core.dnsHosts == nil {
		return dnsHostScope{}
	}
	return dnsHostScope{
		genID:    s.id,
		netEpoch: netEpoch,
		rev:      s.core.dnsHosts.currentRev(),
	}
}

func (k *core) liveScopeState() (uint64, uint64, bool) {
	if k == nil || k.ctx.Err() != nil {
		return 0, 0, false
	}
	cur := k.gen.Load()
	if cur == nil {
		return 0, 0, false
	}
	return cur.id, cur.currentNetEpoch(), true
}

func (s *Server) lookupDNSHost(ip netip.Addr) string {
	if s == nil || s.core == nil || s.core.dnsHosts == nil {
		return ""
	}
	cur := s.core.gen.Load()
	if cur == nil || cur.id != s.id {
		return ""
	}
	host, _ := s.core.dnsHosts.lookupScoped(ip, s.id, s.currentNetEpoch())
	return host
}

func (k *core) lookupDNSHost(ip netip.Addr) string {
	if k == nil || k.dnsHosts == nil {
		return ""
	}
	genID, netEpoch, ok := k.liveScopeState()
	if !ok {
		return ""
	}
	host, _ := k.dnsHosts.lookupScoped(ip, genID, netEpoch)
	return host
}

func (k *core) isDNSHostAmbiguous(ip netip.Addr) bool {
	if k == nil || k.dnsHosts == nil {
		return false
	}
	genID, netEpoch, ok := k.liveScopeState()
	if !ok {
		return false
	}
	_, amb := k.dnsHosts.lookupScoped(ip, genID, netEpoch)
	return amb
}

func (s *Server) recordDNSWire(wire []byte, remainingCap time.Duration, fromCache bool, startScope dnsHostScope) {
	if s == nil || s.core == nil || s.core.dnsHosts == nil || !startScope.valid() {
		return
	}
	s.core.dnsHosts.recordWireScoped(wire, remainingCap, fromCache, startScope, s.core.liveScopeState)
}

func (s *Server) recordDNSResolved(host string, ips []netip.Addr, ttl time.Duration, fromCache bool, startScope dnsHostScope) {
	if s == nil || s.core == nil || s.core.dnsHosts == nil || !startScope.valid() {
		return
	}
	s.core.dnsHosts.recordIPsScoped(host, ips, ttl, fromCache, startScope, s.core.liveScopeState)
}
