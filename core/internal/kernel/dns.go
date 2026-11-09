package kernel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

type dnsCacheEntry struct {
	ips     []netip.Addr
	expires time.Time
	server  string
	epoch   uint64
}
type dnsDial func(context.Context, string, string) (net.Conn, error)

type internalDNS struct {
	diagnostic   func(context.Context, outbound.Diagnostic)
	protected    bool
	endpointDial dnsDial
	local        *internalDNS
	disableIPv6  bool
	policyOnly   bool
	rules        []dnsPolicyRuntime
	hosts        map[string][]netip.Addr
	physical     []netip.Addr
	systemQuery  func(context.Context, []byte) ([]byte, error)
	dnsContext   func(context.Context) (context.Context, func(), uint64)
	wireCache    map[string]dnsWireEntry
	upstreams    []*dnsUpstream
	// Instance-local I/O seam; production always uses the ordinary direct dialer.
	dial      func(context.Context, string, string) (net.Conn, error)
	capacity  int
	slots     chan struct{}
	mu        sync.Mutex
	cache     map[string]dnsCacheEntry
	now       func() time.Time
	bootstrap func(context.Context, string, string) ([]netip.Addr, error)
}

type dnsUpstream struct {
	ep        dnsEndpoint
	resolver  *internalDNS
	transport *http.Transport
	client    *http.Client
}

func newInternalDNS(o *DNSOptions) (*internalDNS, error) {
	eps, e := dnsEndpoints(o)
	if e != nil {
		return nil, e
	}
	r := &internalDNS{capacity: 256, slots: make(chan struct{}, 64), cache: make(map[string]dnsCacheEntry), now: time.Now, bootstrap: net.DefaultResolver.LookupNetIP, dial: (&net.Dialer{}).DialContext}
	if len(eps) == 0 {
		r.capacity = 0
	}
	if o != nil && o.CacheEntries != nil {
		r.capacity = *o.CacheEntries
	}
	if r.capacity < 0 || r.capacity > 4096 || len(eps) == 0 && r.capacity != 0 {
		return nil, errNetworkConfig
	}
	r.wireCache = map[string]dnsWireEntry{}
	r.hosts = map[string][]netip.Addr{}
	if err := validateDNSPolicy(o); err != nil {
		return nil, err
	}
	if o != nil {
		for name, addresses := range o.Hosts {
			for _, s := range addresses {
				ip, _ := netip.ParseAddr(s)
				key := strings.ToLower(strings.TrimSuffix(name, "."))
				r.hosts[key] = append(r.hosts[key], ip.Unmap())
			}
		}
		rules, _ := effectiveDNSRules(o)
		for _, rule := range rules {
			child, err := newInternalDNS(&DNSOptions{Servers: rule.Servers, CacheEntries: o.CacheEntries})
			if err != nil {
				return nil, err
			}
			child.policyOnly = true
			r.rules = append(r.rules, dnsPolicyRuntime{rule, child})
		}
	}
	for _, ep := range eps {
		u := &dnsUpstream{ep: ep, resolver: r}
		if ep.scheme == "https" {
			// No environment proxy or redirects; every endpoint owns its pool.
			u.transport = &http.Transport{MaxConnsPerHost: 64, MaxIdleConns: 8, MaxIdleConnsPerHost: 8, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 5 * time.Second, TLSHandshakeTimeout: 5 * time.Second, MaxResponseHeaderBytes: 8192, DisableCompression: true, ForceAttemptHTTP2: false}
			u.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) { return u.connect(ctx, "tcp") }
			u.client = &http.Client{Transport: u.transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("DNS redirect rejected") }}
		}
		r.upstreams = append(r.upstreams, u)
	}
	return r, nil
}
func (r *internalDNS) close() {
	if r != nil {
		for _, p := range r.rules {
			p.resolver.close()
		}
		for _, u := range r.upstreams {
			if u.transport != nil {
				u.transport.CloseIdleConnections()
			}
		}
	}
}
func (r *internalDNS) cached(name string) ([]netip.Addr, bool) {
	ips, _, ok := r.cachedAnswer(name)
	return ips, ok
}
func (r *internalDNS) cachedAnswer(name string) ([]netip.Addr, string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.cache[name]
	if !ok {
		return nil, "", false
	}
	if e.epoch != r.dnsEpoch() || !e.expires.After(r.now()) {
		delete(r.cache, name)
		return nil, "", false
	}
	return append([]netip.Addr(nil), e.ips...), e.server, true
}
func (r *internalDNS) cachePut(name string, ips []netip.Addr, ttl time.Duration) {
	r.cachePutFrom(name, ips, ttl, "")
}
func (r *internalDNS) cachePutFrom(name string, ips []netip.Addr, ttl time.Duration, server string, epoch ...uint64) {
	wanted := r.dnsEpoch()
	if len(epoch) > 0 {
		wanted = epoch[0]
	}
	if r.capacity == 0 || ttl <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if wanted != r.dnsEpoch() {
		return
	}
	now := r.now()
	var oldest string
	var earliest time.Time
	for k, e := range r.cache {
		if !e.expires.After(now) {
			delete(r.cache, k)
			continue
		}
		if earliest.IsZero() || e.expires.Before(earliest) {
			oldest, earliest = k, e.expires
		}
	}
	if _, ok := r.cache[name]; !ok && len(r.cache) >= r.capacity {
		delete(r.cache, oldest)
	}
	r.cache[name] = dnsCacheEntry{ips: append([]netip.Addr(nil), ips...), expires: now.Add(ttl), server: server, epoch: wanted}
}
func (r *internalDNS) lookup(ctx context.Context, name string) ([]netip.Addr, error) {
	ips, _, _, err := r.lookupAnswer(ctx, name)
	return ips, err
}
func (r *internalDNS) lookupAnswer(ctx context.Context, name string) (answer []netip.Addr, server string, cached bool, result error) {
	start := time.Now()
	mode := "custom"
	if len(r.upstreams) == 0 {
		mode = "system"
	}
	defer func() {
		category, native := outbound.Category(result)
		hit := cached
		r.observe(ctx, outbound.Diagnostic{Stage: "dns_lookup", Category: category, Protocol: mode, Native: native, ElapsedMS: outbound.Known(uint64(time.Since(start).Milliseconds())), CacheHit: &hit})
	}()
	ctx, cancel, epoch := r.dnsScope(ctx)
	defer cancel()
	name, e := dnsName(name)
	if e != nil {
		return nil, "", false, errDNS
	}
	if ctx.Err() != nil {
		return nil, "", false, ctx.Err()
	}
	if ips, ok := r.host(name); ok {
		return ips, "hosts", false, nil
	}
	if p := r.policy(name); p != r {
		return p.lookupAnswer(ctx, name)
	}
	if r.local != nil && localDNSName(name) {
		return r.local.lookupAnswer(ctx, name)
	}
	if len(r.upstreams) == 0 {
		ips, err := r.bootstrap(ctx, "ip", name)
		if epoch != r.dnsEpoch() {
			return nil, "", false, context.Canceled
		}
		return ips, "system", false, err
	}
	if r.capacity > 0 {
		if ips, server, ok := r.cachedAnswer(name); ok {
			if epoch != r.dnsEpoch() {
				return nil, "", false, context.Canceled
			}
			return ips, server, true, nil
		}
	}
	// Acquire BEFORE spawning the two family workers. No unbounded per-query workers.
	select {
	case r.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, "", false, ctx.Err()
	}
	defer func() { <-r.slots }()
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, "", false, errDNS
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, "", false, context.DeadlineExceeded
	}
	// The complete chain (including system) gets half the remaining caller
	// budget. Divide the current remainder equally among untried upstreams
	// plus system, reusing time saved by fast failures. Never reset dial_timeout.
	qctx, cancel := context.WithTimeout(ctx, remaining/2)
	defer cancel()
	end, _ := qctx.Deadline()
	chainError := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if qctx.Err() != nil || !time.Now().Before(end) {
			return errDNS
		}
		return nil
	}
	for i, u := range r.upstreams {
		if e := chainError(); e != nil {
			return nil, "", false, e
		}
		uctx, stop := context.WithTimeout(qctx, time.Until(end)/time.Duration(len(r.upstreams)-i+1))
		ips, ttl, complete, terminal := u.lookup(uctx, name)
		stop()
		if ctx.Err() != nil {
			return nil, "", false, ctx.Err()
		}
		if epoch != r.dnsEpoch() {
			return nil, "", false, context.Canceled
		}
		if len(ips) > 0 {
			if complete {
				r.cachePutFrom(name, ips, ttl, u.ep.label(), epoch)
			}
			return ips, u.ep.label(), false, nil
		}
		if terminal {
			return nil, "", false, errDNS
		}
	}
	if e := chainError(); e != nil {
		return nil, "", false, e
	}
	if r.policyOnly {
		return nil, "", false, errDNS
	}
	// System answers have no known TTL and must never enter our cache.
	ips, e := r.bootstrap(qctx, "ip", name)
	if e := chainError(); e != nil {
		return nil, "", false, e
	}
	if len(ips) > maxDNSAddresses {
		ips = ips[:maxDNSAddresses]
	}
	if e != nil {
		return nil, "", false, e
	}
	if len(ips) == 0 {
		return nil, "", false, errDNS
	}
	if epoch != r.dnsEpoch() {
		return nil, "", false, context.Canceled
	}
	return ips, "system", false, nil
}

// Families run concurrently, but results from different upstreams never mix.
func (r *dnsUpstream) lookup(qctx context.Context, name string) (ips []netip.Addr, ttl time.Duration, complete, terminal bool) {
	type result struct {
		answer dnsAnswer
		err    error
	}
	var results [2]result
	var wg sync.WaitGroup
	types := []dnsmessage.Type{dnsmessage.TypeA}
	if !r.resolver.disableIPv6 {
		types = append(types, dnsmessage.TypeAAAA)
	}
	for i, typ := range types {
		wg.Add(1)
		go func(i int, typ dnsmessage.Type) {
			defer wg.Done()
			results[i].answer, results[i].err = r.query(qctx, name, typ)
		}(i, typ)
	}
	wg.Wait()
	seen := map[netip.Addr]bool{}
	complete = true
	ttl = 300 * time.Second
	nxdomain := false
	for _, v := range results[:len(types)] {
		if v.err != nil {
			complete = false
			continue
		}
		if v.answer.nxdomain {
			nxdomain = true
			complete = false
		}
		if len(v.answer.ips) > 0 && v.answer.ttl < ttl {
			ttl = v.answer.ttl
		}
		for _, ip := range v.answer.ips {
			ip = ip.Unmap()
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
				if len(ips) > maxDNSAddresses {
					return nil, 0, false, false
				}
			}
		}
	}
	if len(ips) > 0 {
		return ips, ttl, complete, false
	}
	// One valid NXDOMAIN is conclusive. NODATA is conclusive only if both
	// families are valid empty answers; empty + transient may still have IPs.
	return nil, 0, false, nxdomain || complete
}
func (r *dnsUpstream) connect(ctx context.Context, network string) (net.Conn, error) {
	if r.resolver.protected {
		if r.resolver.endpointDial == nil {
			return nil, errDNS
		}
		return r.resolver.endpointDial(ctx, network, net.JoinHostPort(r.ep.host, r.ep.port))
	}
	var ips []netip.Addr
	if ip, e := netip.ParseAddr(r.ep.host); e == nil {
		ips = []netip.Addr{ip}
	} else {
		var e error
		ips, e = r.resolver.bootstrap(ctx, "ip", r.ep.host)
		if e != nil {
			r.resolver.observeError(ctx, "dns_connect", r.ep.scheme, e, time.Time{})
			return nil, errDNS
		}
	}
	if len(ips) > 16 {
		ips = ips[:16]
	}
	for _, ip := range ips {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if r.resolver.disableIPv6 && ip.Unmap().Is6() {
			continue
		}
		c, e := r.resolver.dial(ctx, network, net.JoinHostPort(ip.Unmap().String(), r.ep.port))
		r.resolver.observeError(ctx, "dns_connect", network, e, time.Time{})
		if e == nil {
			return c, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errDNS
}
func (r *dnsUpstream) query(ctx context.Context, name string, typ dnsmessage.Type) (answerResult dnsAnswer, result error) {
	start := time.Now()
	defer func() { r.resolver.observeError(ctx, "dns_exchange", r.ep.scheme, result, start) }()
	wire, q, e := dnsQuestion(name, typ)
	if e != nil {
		return dnsAnswer{}, errDNS
	}
	id := binary.BigEndian.Uint16(wire[:2])
	var answer []byte
	switch r.ep.scheme {
	case "udp", "tcp":
		answer, e = r.exchange(ctx, r.ep.scheme, wire)
	case "https":
		req, er := http.NewRequestWithContext(ctx, http.MethodPost, r.ep.url, bytes.NewReader(wire))
		if er != nil {
			r.resolver.observeError(ctx, "dns_exchange", r.ep.scheme, er, start)
			return dnsAnswer{}, errDNS
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")
		resp, er := r.client.Do(req)
		if er != nil {
			r.resolver.observeError(ctx, "dns_exchange", r.ep.scheme, er, start)
			return dnsAnswer{}, errDNS
		}
		defer resp.Body.Close()
		media, _, er := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if er != nil || media != "application/dns-message" || resp.StatusCode != http.StatusOK || resp.ContentLength > maxDNSMessage {
			return dnsAnswer{}, errDNS
		}
		answer, e = io.ReadAll(io.LimitReader(resp.Body, maxDNSMessage+1))
	default:
		return dnsAnswer{}, errDNS
	}
	if e != nil || len(answer) > maxDNSMessage {
		return dnsAnswer{}, errDNS
	}
	a, e := parseDNSAnswer(answer, id, q)
	if e != nil {
		return dnsAnswer{}, e
	}
	if a.truncated {
		r.resolver.observe(ctx, outbound.Diagnostic{Stage: "dns_fallback", Category: "truncated_tcp", Protocol: r.ep.scheme})
		if r.ep.scheme != "udp" {
			return dnsAnswer{}, errDNS
		}
		answer, e = r.exchange(ctx, "tcp", wire)
		if e != nil {
			return dnsAnswer{}, errDNS
		}
		a, e = parseDNSAnswer(answer, id, q)
		if e != nil || a.truncated {
			return dnsAnswer{}, errDNS
		}
	}
	category := "ok"
	if a.nxdomain {
		category = "nxdomain"
	} else if len(a.ips) == 0 {
		category = "nodata"
	}
	r.resolver.observe(ctx, outbound.Diagnostic{Stage: "dns_parse", Category: category, Protocol: r.ep.scheme, ElapsedMS: outbound.Known(uint64(time.Since(start).Milliseconds()))})
	return a, nil
}
func (r *dnsUpstream) exchange(ctx context.Context, network string, wire []byte) ([]byte, error) {
	c, e := r.connect(ctx, network)
	if e != nil {
		r.resolver.observeError(ctx, "dns_connect", network, e, time.Time{})
		return nil, errDNS
	}
	defer c.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if network == "tcp" {
		b := binary.BigEndian.AppendUint16(nil, uint16(len(wire)))
		b = append(b, wire...)
		if e = writeAll(c, b); e != nil {
			r.resolver.observeError(ctx, "dns_write", network, e, time.Time{})
			return nil, errDNS
		}
		var size [2]byte
		if _, e = io.ReadFull(c, size[:]); e != nil {
			r.resolver.observeError(ctx, "dns_read", network, e, time.Time{})
			return nil, errDNS
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		if n < 12 {
			return nil, errDNS
		}
		b = make([]byte, n)
		_, e = io.ReadFull(c, b)
		return b, e
	}
	if _, e = c.Write(wire); e != nil {
		r.resolver.observeError(ctx, "dns_write", network, e, time.Time{})
		return nil, errDNS
	}
	b := make([]byte, maxDNSMessage+1)
	n, e := c.Read(b)
	if e != nil || n > maxDNSMessage {
		r.resolver.observeError(ctx, "dns_read", network, e, time.Time{})
		return nil, errDNS
	}
	return b[:n], nil
}
