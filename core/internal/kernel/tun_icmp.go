package kernel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"github.com/shui1iao/Kat/internal/route"
	"github.com/shui1iao/Kat/internal/tunstack"
	"golang.org/x/net/dns/dnsmessage"
)

var _ tunstack.ICMPIngress = (*TUNIngress)(nil)

var (
	tunVirtualDNS4 = netip.MustParseAddr("198.18.0.2")
	tunVirtualDNS6 = netip.MustParseAddr("fd4b:6174::2")
)

const (
	icmpDefaultProbeURL  = "http://www.gstatic.com/generate_204"
	icmpDocumentProbeURL = "https://www.gstatic.com/generate_204"
	icmpBurstCacheTTL    = 800 * time.Millisecond
	icmpDomainHintTTL    = 60 * time.Second
	icmpMaxDomainHints   = 512
	icmpMaxLearnedEntry  = 256
	icmpProbeTimeout     = 3200 * time.Millisecond
)

type icmpHint struct {
	host    string
	expires time.Time
}

type icmpCachedProbe struct {
	rtt     time.Duration
	expires time.Time
}

type icmpProbeFlight struct {
	done chan struct{}
	rtt  time.Duration
	err  error
}

type icmpProberClient struct {
	url       string
	target    outbound.Addr
	transport *http.Transport
	client    *http.Client
}

type icmpRuntime struct {
	entryIPs     map[netip.Addr]struct{}
	entryDomains map[string]struct{}

	mu           sync.Mutex
	closed       bool
	learnedEntry map[netip.Addr]time.Time
	hints        map[netip.Addr]icmpHint
	clients      map[string]*icmpProberClient
	cache        map[string]icmpCachedProbe
	flights      map[string]*icmpProbeFlight
}

func newICMPRuntime(outs []OutboundConfig) *icmpRuntime {
	r := &icmpRuntime{
		entryIPs:     make(map[netip.Addr]struct{}),
		entryDomains: make(map[string]struct{}),
		learnedEntry: make(map[netip.Addr]time.Time),
		hints:        make(map[netip.Addr]icmpHint),
		clients:      make(map[string]*icmpProberClient),
		cache:        make(map[string]icmpCachedProbe),
		flights:      make(map[string]*icmpProbeFlight),
	}
	for _, o := range outs {
		if o.Via != "" || o.Server == "" {
			continue
		}
		if ip, err := netip.ParseAddr(o.Server); err == nil {
			if ip.Zone() == "" {
				r.entryIPs[ip.Unmap()] = struct{}{}
			}
			continue
		}
		h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(o.Server), "."))
		if h != "" {
			r.entryDomains[h] = struct{}{}
		}
	}
	return r
}

func (r *icmpRuntime) close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	clients := make([]*icmpProberClient, 0, len(r.clients))
	for _, c := range r.clients {
		clients = append(clients, c)
	}
	r.clients = map[string]*icmpProberClient{}
	r.mu.Unlock()
	for _, c := range clients {
		c.transport.CloseIdleConnections()
	}
}

func (r *icmpRuntime) noteResolved(host string, ips []netip.Addr, recordHint bool) {
	if r == nil || len(ips) == 0 {
		return
	}
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return
	}
	_, isEntry := r.entryDomains[h]
	if !isEntry && !recordHint {
		return
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if isEntry {
		exp := now.Add(10 * time.Minute)
		for _, ip := range ips {
			if !ip.IsValid() || ip.Zone() != "" {
				continue
			}
			u := ip.Unmap()
			if len(r.learnedEntry) >= icmpMaxLearnedEntry {
				for k, v := range r.learnedEntry {
					delete(r.learnedEntry, k)
					if !v.After(now) {
						continue
					}
					break
				}
			}
			r.learnedEntry[u] = exp
		}
	}
	if recordHint {
		exp := now.Add(icmpDomainHintTTL)
		for _, ip := range ips {
			if !ip.IsValid() || ip.Zone() != "" {
				continue
			}
			u := ip.Unmap()
			if len(r.hints) >= icmpMaxDomainHints {
				for k, v := range r.hints {
					delete(r.hints, k)
					if !v.expires.After(now) {
						continue
					}
					break
				}
			}
			r.hints[u] = icmpHint{host: h, expires: exp}
		}
	}
}

func (r *icmpRuntime) noteDNSWire(wire []byte) {
	if r == nil || len(wire) < 12 {
		return
	}
	var m dnsmessage.Message
	if m.Unpack(wire) != nil || !m.Response || m.RCode != dnsmessage.RCodeSuccess || len(m.Questions) != 1 || len(m.Answers) == 0 {
		return
	}
	qname := strings.ToLower(strings.TrimSuffix(m.Questions[0].Name.String(), "."))
	if qname == "" {
		return
	}
	var ips []netip.Addr
	for _, ans := range m.Answers {
		switch b := ans.Body.(type) {
		case *dnsmessage.AResource:
			ips = append(ips, netip.AddrFrom4(b.A))
		case *dnsmessage.AAAAResource:
			ips = append(ips, netip.AddrFrom16(b.AAAA).Unmap())
		}
	}
	if len(ips) > 0 {
		r.noteResolved(qname, ips, true)
	}
}

func (r *icmpRuntime) isEntryIP(ip netip.Addr, dns *internalDNS, directDNS *internalDNS) bool {
	if r == nil || !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if _, ok := r.entryIPs[ip]; ok {
		return true
	}
	now := time.Now()
	r.mu.Lock()
	exp, ok := r.learnedEntry[ip]
	if ok && !exp.After(now) {
		delete(r.learnedEntry, ip)
		ok = false
	}
	r.mu.Unlock()
	if ok {
		return true
	}
	for host := range r.entryDomains {
		if dnsHasCachedIP(dns, host, ip) || dnsHasCachedIP(directDNS, host, ip) {
			return true
		}
	}
	return false
}

func dnsHasCachedIP(d *internalDNS, host string, ip netip.Addr) bool {
	if d == nil {
		return false
	}
	if ips, ok := d.hosts[host]; ok {
		for _, v := range ips {
			if v.Unmap() == ip {
				return true
			}
		}
	}
	now := d.now()
	d.mu.Lock()
	ce, ok := d.cache[host]
	d.mu.Unlock()
	if ok && ce.expires.After(now) {
		for _, v := range ce.ips {
			if v.Unmap() == ip {
				return true
			}
		}
	}
	return false
}

func (r *icmpRuntime) domainHint(ip netip.Addr) string {
	if r == nil || !ip.IsValid() {
		return ""
	}
	ip = ip.Unmap()
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	h, ok := r.hints[ip]
	if !ok {
		return ""
	}
	if !h.expires.After(now) {
		delete(r.hints, ip)
		return ""
	}
	return h.host
}

func effectiveICMPProbeURL(cfg *ClientEgress) (string, outbound.Addr, error) {
	raw := icmpDefaultProbeURL
	if cfg != nil && cfg.ProbeURL != "" && cfg.ProbeURL != icmpDocumentProbeURL {
		raw = cfg.ProbeURL
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		u, _ = url.Parse(icmpDefaultProbeURL)
		raw = icmpDefaultProbeURL
	}
	host := u.Hostname()
	port := uint16(80)
	if u.Scheme == "https" {
		port = 443
	}
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 {
			return "", outbound.Addr{}, errors.New("invalid probe port")
		}
		port = uint16(n)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	} else {
		host = strings.ToLower(strings.TrimSuffix(host, "."))
	}
	return raw, outbound.Addr{Host: host, Port: port}, nil
}

func (r *icmpRuntime) getOrCreateClient(key string, ob outbound.Outbound, probeURL string, target outbound.Addr) (*icmpProberClient, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, ErrCoreNotRunning
	}
	if c := r.clients[key]; c != nil && c.url == probeURL && c.target == target {
		return c, nil
	}
	if old := r.clients[key]; old != nil {
		go old.transport.CloseIdleConnections()
	}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return ob.DialTCP(ctx, target)
		},
		MaxIdleConns:           2,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        15 * time.Second,
		ResponseHeaderTimeout:  icmpProbeTimeout,
		TLSHandshakeTimeout:    icmpProbeTimeout,
		MaxResponseHeaderBytes: 16 << 10,
		DisableCompression:     true,
		ForceAttemptHTTP2:      false,
	}
	cl := &icmpProberClient{
		url:       probeURL,
		target:    target,
		transport: tr,
		client: &http.Client{
			Transport:     tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	r.clients[key] = cl
	return cl, nil
}

func (r *icmpRuntime) probeProxy(ctx context.Context, baseCtx context.Context, key string, ob outbound.Outbound, cfg *ClientEgress) error {
	if r == nil || ob == nil {
		return errors.New("ICMP proxy runtime unavailable")
	}
	probeURL, target, err := effectiveICMPProbeURL(cfg)
	if err != nil {
		return err
	}
	now := time.Now()
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrCoreNotRunning
	}
	if c, ok := r.cache[key]; ok {
		if c.expires.After(now) {
			wait := c.rtt
			r.mu.Unlock()
			if wait > 500*time.Millisecond {
				wait = 500 * time.Millisecond
			}
			if wait > 0 {
				t := time.NewTimer(wait)
				defer t.Stop()
				select {
				case <-t.C:
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			return nil
		}
		delete(r.cache, key)
	}
	f := r.flights[key]
	if f == nil {
		f = &icmpProbeFlight{done: make(chan struct{})}
		r.flights[key] = f
		go func() {
			pctx, cancel := context.WithTimeout(baseCtx, icmpProbeTimeout)
			rtt, perr := r.runHTTPProbe(pctx, key, ob, probeURL, target)
			cancel()
			r.mu.Lock()
			f.rtt, f.err = rtt, perr
			if r.flights[key] == f {
				delete(r.flights, key)
			}
			if perr == nil && !r.closed {
				r.cache[key] = icmpCachedProbe{rtt: rtt, expires: time.Now().Add(icmpBurstCacheTTL)}
			}
			close(f.done)
			r.mu.Unlock()
		}()
	}
	r.mu.Unlock()

	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *icmpRuntime) runHTTPProbe(ctx context.Context, key string, ob outbound.Outbound, probeURL string, target outbound.Addr) (time.Duration, error) {
	cl, err := r.getOrCreateClient(key, ob, probeURL, target)
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, probeURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Kat-probe")
	start := time.Now()
	resp, err := cl.client.Do(req)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusNotImplemented {
		resp.Body.Close()
		req.Method = http.MethodGet
		resp, err = cl.client.Do(req)
		if err != nil {
			return 0, err
		}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<10))
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return 0, errors.New("ICMP proxy probe upstream status failure")
	}
	return time.Since(start), nil
}

func (s *Server) resolveICMPOutbound(policy string) (string, outbound.Outbound) {
	if policy == "" || s.rt == nil {
		return "", nil
	}
	chain := s.previewPolicyChain(policy)
	name := policy
	if len(chain) > 0 {
		name = chain[len(chain)-1]
	}
	if name == "direct" || name == "reject" {
		return name, s.rt.nodes[name]
	}
	return name, s.rt.nodes[name]
}

func (s *Server) pingPhysical(ctx context.Context, req tunstack.ICMPEchoRequest) (tunstack.ICMPEchoReply, bool) {
	if s.cfg.clientEgress == nil || s.cfg.clientEgress.PingPhysical == nil {
		return tunstack.ICMPEchoReply{}, false
	}
	replyPayload, replyTTL, err := s.cfg.clientEgress.PingPhysical(ctx, req.Destination, req.TTL, req.TOS, req.DF, req.Payload)
	if err != nil {
		return tunstack.ICMPEchoReply{}, false
	}
	return tunstack.ICMPEchoReply{Payload: replyPayload, TTL: replyTTL}, true
}

func (s *Server) decideICMP(dst, src netip.Addr) (route.Decision, error) {
	if s.cfg.IPv6Disabled() && dst.Is6() {
		return route.Decision{}, direct.ErrIPv6Disabled
	}
	r, err := s.router()
	if err != nil {
		return route.Decision{}, err
	}
	if s.rt == nil {
		defer r.Close()
	}
	var hint string
	if s.rt != nil && s.rt.icmp != nil {
		hint = s.rt.icmp.domainHint(dst)
	}
	m := route.Metadata{
		Network:                "icmp",
		IP:                     dst,
		Port:                   0,
		Source:                 src,
		InName:                 "tun",
		InType:                 "tun",
		SniffHost:              hint,
		SkipUnavailableProcess: true,
	}
	d, err := r.Decide(s.trafficContext(), m, nil)
	if err != nil {
		return d, err
	}
	if d.Kind == route.Reject {
		return d, errRouteReject
	}
	return d, nil
}

func (i *TUNIngress) HandleICMP(parent context.Context, req tunstack.ICMPEchoRequest) (tunstack.ICMPEchoReply, bool) {
	if !req.Source.IsValid() || !req.Destination.IsValid() || req.Source.Is4() != req.Destination.Is4() {
		return tunstack.ICMPEchoReply{}, false
	}
	s := i.server.current()
	if !s.tryRef() {
		return tunstack.ICMPEchoReply{}, false
	}
	defer s.unref()
	s.mu.Lock()
	closing := s.closing
	s.mu.Unlock()
	if closing || s.ctx.Err() != nil {
		return tunstack.ICMPEchoReply{}, false
	}

	src := req.Source.Unmap()
	dst := req.Destination.Unmap()
	req.Source = src
	req.Destination = dst

	if s.cfg.IPv6Disabled() && dst.Is6() {
		return tunstack.ICMPEchoReply{}, false
	}
	if s.cfg.clientEgress != nil && s.cfg.clientEgress.IsPhysicalSource != nil && s.cfg.clientEgress.IsPhysicalSource(src) {
		return tunstack.ICMPEchoReply{}, false
	}
	if dst == tunVirtualDNS4 || dst == tunVirtualDNS6 {
		return tunstack.ICMPEchoReply{Payload: req.Payload, TTL: 64}, true
	}

	ctx, cancel := context.WithTimeout(s.trafficContext(), icmpProbeTimeout)
	defer cancel()
	stopParent := context.AfterFunc(parent, cancel)
	defer stopParent()

	if s.cfg.clientEgress.originalResolver(dst, 53) {
		return s.pingPhysical(ctx, req)
	}
	if s.rt != nil && s.rt.icmp.isEntryIP(dst, s.dns, s.directDNS) {
		return s.pingPhysical(ctx, req)
	}

	d, err := s.decideICMP(dst, src)
	if err != nil {
		return tunstack.ICMPEchoReply{}, false
	}
	switch d.Kind {
	case route.Reject:
		return tunstack.ICMPEchoReply{}, false
	case route.Direct:
		return s.pingPhysical(ctx, req)
	case route.Proxy:
		name, ob := s.resolveICMPOutbound(d.Outbound)
		switch {
		case name == "direct":
			return s.pingPhysical(ctx, req)
		case name == "reject" || ob == nil || s.rt == nil:
			return tunstack.ICMPEchoReply{}, false
		}
		if err := s.rt.icmp.probeProxy(ctx, s.trafficContext(), name, ob, s.cfg.clientEgress); err != nil {
			return tunstack.ICMPEchoReply{}, false
		}
		return tunstack.ICMPEchoReply{Payload: req.Payload, TTL: 56}, true
	default:
		return tunstack.ICMPEchoReply{}, false
	}
}
