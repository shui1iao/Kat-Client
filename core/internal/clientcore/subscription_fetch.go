package clientcore

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/provider"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// The test seam only replaces I/O, not conversion, ownership or commit logic.
func (h *Host) fetchFull(ctx context.Context, url string, p *clientegress.Policy, limit int64) ([]byte, error) {
	if h.fullFetch != nil {
		return h.fullFetch(ctx, url, p, limit)
	}
	ctx, done := h.ipContext(ctx)
	defer done()
	if runtime, _ := ctx.Value(resourceKernelKey{}).(bool); runtime {
		return h.fetchKernelAsset(ctx, url, limit)
	}
	return fetchImportBounded(ctx, url, p, nil, limit)
}

type mainRouteKey struct{}
type mainSubscriptionRequestKey struct{}

// This capability is granted only to the call fetching the main subscription.
// The enclosing preview/refresh context (also used by dependencies) lacks it.
func setSubscriptionRequestHeaders(req *http.Request) {
	req.Header.Set("User-Agent", "clash.meta")
	main, _ := req.Context().Value(mainSubscriptionRequestKey{}).(bool)
	c, _ := req.Context().Value(legacyKey{}).(*legacyConversion)
	if !main || c == nil {
		return
	}
	origin, err := url.Parse(c.Config.URL)
	if err != nil || !provider.SameOrigin(origin, req.URL) {
		return
	}
	if c.Config.UserAgent != "" {
		req.Header.Set("User-Agent", c.Config.UserAgent)
	}
	for k, v := range c.Config.Headers {
		req.Header.Set(k, v)
	}
}

func subscriptionRedirect(req *http.Request, via []*http.Request) error {
	if e := checkHostEgress(req.Context()); e != nil {
		return e
	}
	if len(via) > 5 || !validImportURL(req.URL.String()) || req.URL.Scheme != via[0].URL.Scheme {
		return dl("url_check", "redirect_refused")
	}
	// URL/literal checks are per-hop. A Direct leaf validates its actual DNS
	// result at connect time. A proxy resolving remotely is a trust boundary;
	// a separate local DNS lookup cannot attest the address used by the proxy.
	req.Header = make(http.Header)
	req.Header.Set("User-Agent", "clash.meta")
	for _, prev := range via {
		if !provider.SameOrigin(prev.URL, req.URL) {
			return nil
		}
	}
	setSubscriptionRequestHeaders(req)
	return nil
}
func (h *Host) fetchMainSubscription(ctx context.Context, url string, policy *clientegress.Policy, limit int64, mode, last string, proxy *bootstrapProxy) ([]byte, string, error) {
	ctx = context.WithValue(ctx, mainSubscriptionRequestKey{}, true)
	ctx, done := h.ipContext(ctx)
	defer done()
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	h.mu.Lock()
	running := h.server != nil
	h.mu.Unlock()
	routes := []string{}
	add := func(route string) {
		if route == "kernel_rules" && !running || route == "windows_static_http" && proxy == nil {
			return
		}
		for _, r := range routes {
			if r == route {
				return
			}
		}
		routes = append(routes, route)
	}
	switch mode {
	case "direct":
		add("direct")
	case "proxy":
		add("kernel_rules")
		add("windows_static_http")
	default:
		if last == "direct" || last == "kernel_rules" || last == "windows_static_http" {
			add(last)
		}
		add("direct")
		add("kernel_rules")
		add("windows_static_http")
	}
	attempts := []ResourceAttempt{}
	var first, lastAttempt ResourceAttempt
	var failure error = dl("connect", "egress_unavailable")
	for i, route := range routes {
		if ctx.Err() != nil {
			break
		}
		next := context.WithValue(ctx, resourceKernelKey{}, route == "kernel_rules")
		next = context.WithValue(next, bootstrapKey{}, (*bootstrapProxy)(nil))
		if route == "windows_static_http" {
			next = context.WithValue(next, bootstrapKey{}, proxy)
		}
		if meta, ok := ctx.Value(subscriptionHeadersKey{}).(*subscriptionHeaders); ok {
			*meta = subscriptionHeaders{}
		}
		attempt, cancel := context.WithTimeout(next, 20*time.Second)
		b, e := h.fetchFull(attempt, url, policy, limit)
		cancel()
		if e == nil {
			return b, route, nil
		}
		failure = e
		lastAttempt = resourceAttempt(next, e)
		attempts = append(attempts, lastAttempt)
		if i == 0 {
			first = lastAttempt
		}
	}
	if len(routes) == 0 {
		return nil, "", failure
	}
	return nil, "", &resourceAttemptsError{first: first, last: lastAttempt, cause: failure, attempts: attempts}
}

func subscriptionRedirectPolicy(ctx context.Context) func(*http.Request, []*http.Request) error {
	if _, ok := ctx.Value(subscriptionHeadersKey{}).(*subscriptionHeaders); ok {
		return subscriptionRedirect
	}
	return func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
}

// Native injects this per-request snapshot after removing all WebView-supplied internal fields.
// It is never persisted into user configuration or ordinary logs.
type bootstrapProxy struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
}
type bootstrapKey struct{}

func bootstrapFrom(ctx context.Context) *bootstrapProxy {
	p, _ := ctx.Value(bootstrapKey{}).(*bootstrapProxy)
	return p
}
func validBootstrap(p *bootstrapProxy) bool {
	if p == nil || p.Host == "" || len(p.Host) > 253 || p.Port == 0 || strings.ContainsAny(p.Host, "/@?#\\% \t\r\n") {
		return false
	}
	if ip, e := netip.ParseAddr(p.Host); e == nil {
		return ip.Zone() == "" && !ip.IsUnspecified() && !ip.IsMulticast()
	}
	return !strings.Contains(p.Host, ":")
}
func localProxyIP(ip netip.Addr) (bool, error) {
	ip = ip.Unmap()
	if ip.IsLoopback() {
		return true, nil
	}
	as, e := net.InterfaceAddrs()
	if e != nil {
		return false, e
	}
	for _, a := range as {
		p, e := netip.ParsePrefix(a.String())
		if e == nil && p.Addr().Unmap() == ip {
			return true, nil
		}
	}
	return false, nil
}

// Tests may replace only local network I/O/ownership, not production URL or destination checks.
func dialBootstrap(ctx context.Context, address string, p *bootstrapProxy, policy *clientegress.Policy, resolve func(context.Context, string) ([]netip.Addr, error), _ []int) (net.Conn, error) {
	if !validBootstrap(p) {
		return nil, dl("proxy_connect", "proxy_unsupported")
	}
	return dialBootstrapIO(ctx, address, p, policy, resolve, nil, func(ctx context.Context, d *net.Dialer, address string) (net.Conn, error) {
		if s := hostEgress(ctx); s != nil {
			return dialHostEgress(ctx, s, "tcp", address)
		}
		return d.DialContext(ctx, "tcp", address)
	}, verifyBootstrapPeer)
}
func dialBootstrapIO(ctx context.Context, address string, p *bootstrapProxy, policy *clientegress.Policy, _ func(context.Context, string) ([]netip.Addr, error), _ []int, dial func(context.Context, *net.Dialer, string) (net.Conn, error), verify func(net.Conn) error) (net.Conn, error) {
	if !validBootstrap(p) {
		return nil, dl("proxy_connect", "proxy_unsupported")
	}
	if e := checkHostEgress(ctx); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, dl("url_check", "address_refused")
	}
	n, e := strconv.ParseUint(port, 10, 16)
	if e != nil || n == 0 {
		return nil, dl("url_check", "address_refused")
	}
	// A CONNECT proxy resolves the original hostname. Local DNS may be fake-IP;
	// never consult it for a target hostname or expand it into repeated tunnels.
	target := net.JoinHostPort(host, port)
	if ip, err := netip.ParseAddr(host); err == nil {
		if ipDisabled(ctx) && ip.Unmap().Is6() {
			return nil, errors.New("ipv6_disabled")
		}
		if !publicImportIP(ip) {
			return nil, dl("resolve", "address_refused")
		}
		target = netip.AddrPortFrom(ip, uint16(n)).String()
	} else if local := strings.ToLower(strings.TrimSuffix(host, ".")); local == "localhost" || strings.HasSuffix(local, ".localhost") {
		return nil, dl("resolve", "address_refused")
	}
	var peers []netip.Addr
	if ip, e := netip.ParseAddr(p.Host); e == nil {
		peers = []netip.Addr{ip.Unmap()}
	} else {
		if s := hostEgress(ctx); s != nil {
			peers, e = s.Bootstrap(ctx, ipNetwork(ctx), p.Host)
		} else if policy != nil {
			if !policy.Ready() {
				return nil, dl("connect", "egress_unavailable")
			}
			peers, e = policy.Bootstrap(ctx, ipNetwork(ctx), p.Host)
		} else {
			peers, e = net.DefaultResolver.LookupNetIP(ctx, ipNetwork(ctx), p.Host)
		}
		if e != nil || len(peers) == 0 {
			return nil, safeFailure(ctx, "resolve", e)
		}
	}
	// A snapshot must not select differently scoped addresses on retry.
	for _, ip := range peers {
		if !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() {
			return nil, dl("proxy_connect", "proxy_unsupported")
		}
		// Configuration port numbers prove no socket ownership. The connected
		// exact reverse tuple is verified below before sending any CONNECT bytes.
	}
	var last error
	for _, peer := range peers {
		if ipDisabled(ctx) && peer.Unmap().Is6() && !peer.IsLoopback() {
			return nil, errors.New("ipv6_disabled")
		}
		local, e := localProxyIP(peer)
		if e != nil {
			return nil, dl("proxy_connect", "proxy_identity_unknown")
		}
		d := &net.Dialer{}
		// Loopback must not be bound to a physical adapter. External peer sockets retain controlled egress.
		if policy != nil {
			if !policy.Ready() {
				return nil, dl("connect", "egress_unavailable")
			}
			if !peer.Unmap().IsLoopback() {
				d.ControlContext = policy.Control
			}
		}
		c, e := dial(ctx, d, netip.AddrPortFrom(peer.Unmap(), p.Port).String())
		if e != nil {
			last = safeFailure(ctx, "connect", e)
			continue
		}
		if local {
			if e = verify(c); e != nil {
				c.Close()
				return nil, e
			}
		}
		tunnel, e := connectBootstrap(ctx, c, target)
		if e == nil {
			return tunnel, nil
		}
		c.Close()
		last = e
		// Do not retry authentication/protocol/status/self-loop failures or silently change route.
		return nil, last
	}
	if last == nil {
		last = dl("connect", "connect_failed")
	}
	return nil, last
}
func connectBootstrap(ctx context.Context, c net.Conn, target string) (net.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		c.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if _, e := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); e != nil {
		return nil, safeFailure(ctx, "proxy_connect", e)
	}
	// Read just the bounded header before switching back to the unbounded tunnel reader.
	var header []byte
	b := make([]byte, 1)
	for !(len(header) >= 4 && string(header[len(header)-4:]) == "\r\n\r\n") {
		if len(header) >= 64<<10 {
			return nil, dl("proxy_connect", "header_limit")
		}
		if _, e := io.ReadFull(c, b); e != nil {
			return nil, safeFailure(ctx, "proxy_connect", e)
		}
		header = append(header, b[0])
	}
	r, e := http.ReadResponse(bufio.NewReader(strings.NewReader(string(header))), &http.Request{Method: "CONNECT"})
	if e != nil {
		return nil, dl("proxy_connect", "proxy_protocol")
	}
	if r.StatusCode < 200 || r.StatusCode > 299 {
		category := "proxy_http"
		if r.StatusCode == 407 {
			category = "proxy_auth_required"
		}
		return nil, &downloadFailure{stage: "proxy_connect", category: category, status: r.StatusCode}
	}
	if ctx.Err() != nil {
		return nil, safeFailure(ctx, "proxy_connect", ctx.Err())
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

// Native reads the current egress under its short operation lock. The core
// atomically checks that exact generation before admitting a bootstrap request.
type bootstrapEgress struct {
	Generation uint64 `json:"generation"`
	Enabled    bool   `json:"enabled"`
}

// All methods below require h.mu; only cancellation signals cross the lock.
func (h *Host) bootstrapContextLocked(parent context.Context) (context.Context, func()) {
	if h.bootstrapLife == nil {
		h.bootstrapLife, h.bootstrapCancel = context.WithCancel(context.Background())
	}
	if clientegress.Supported || h.tunSession != nil {
		p, g, frozen := h.egressSwitch.PolicySnapshot()
		parent = context.WithValue(parent, hostEgressKey{}, hostEgressRequest{switcher: &h.egressSwitch, policy: p, generation: g, ordinary: h.hostOrdinaryLocked(), frozen: frozen})
	}
	ctx, cancel := context.WithCancel(parent)
	// Register the actual child cancellations: AfterFunc propagation alone can
	// be delayed past activation. Cancel them synchronously under the same Host
	// operation lock BEFORE TUN changes a route/epoch or replaces nil policy.
	if h.bootstrapRequests == nil {
		h.bootstrapRequests = make(map[context.Context]context.CancelFunc)
	}
	h.bootstrapRequests[ctx] = cancel
	stop := context.AfterFunc(h.bootstrapLife, cancel)
	if h.bootstrapLife.Err() != nil {
		cancel()
	}
	return ctx, func() {
		stop()
		cancel()
		h.mu.Lock()
		delete(h.bootstrapRequests, ctx)
		h.mu.Unlock()
	}
}
func (h *Host) cancelBootstrapLocked() {
	for ctx, cancel := range h.bootstrapRequests {
		cancel()
		delete(h.bootstrapRequests, ctx)
	}
	if h.bootstrapCancel != nil {
		h.bootstrapCancel()
	}
	h.bootstrapLife = nil
	h.bootstrapCancel = nil
}

// Pure bounded table decoder shared with Windows API path and host regression tests.
func bootstrapPeerPIDTable(b []byte, ipv6 bool, local, peer netip.AddrPort) (uint32, error) {
	size := 24
	if ipv6 {
		size = 56
	}
	if len(b) < 4 {
		return 0, dl("proxy_connect", "proxy_identity_unknown")
	}
	count := int(binary.LittleEndian.Uint32(b))
	if count > (len(b)-4)/size {
		return 0, dl("proxy_connect", "proxy_identity_unknown")
	}
	found := uint32(0)
	matches := 0
	for i := 0; i < count; i++ {
		v := b[4+i*size : 4+(i+1)*size]
		var src, dst netip.Addr
		var sp, dp uint16
		var pid uint32
		if !ipv6 {
			if binary.LittleEndian.Uint32(v) != 5 {
				continue
			}
			src = netip.AddrFrom4([4]byte(v[4:8]))
			sp = binary.BigEndian.Uint16(v[8:10])
			dst = netip.AddrFrom4([4]byte(v[12:16]))
			dp = binary.BigEndian.Uint16(v[16:18])
			pid = binary.LittleEndian.Uint32(v[20:24])
		} else {
			if binary.LittleEndian.Uint32(v[48:52]) != 5 || binary.LittleEndian.Uint32(v[16:20]) != 0 || binary.LittleEndian.Uint32(v[40:44]) != 0 {
				continue
			}
			src = netip.AddrFrom16([16]byte(v[:16]))
			sp = binary.BigEndian.Uint16(v[20:22])
			dst = netip.AddrFrom16([16]byte(v[24:40]))
			dp = binary.BigEndian.Uint16(v[44:46])
			pid = binary.LittleEndian.Uint32(v[52:56])
		}
		if src.Unmap() == peer.Addr().Unmap() && sp == peer.Port() && dst.Unmap() == local.Addr().Unmap() && dp == local.Port() {
			matches++
			found = pid
		}
	}
	if matches != 1 || found == 0 {
		return 0, dl("proxy_connect", "proxy_identity_unknown")
	}
	return found, nil
}
func bootstrapPeerOwner(b []byte, ipv6 bool, local, peer netip.AddrPort, self uint32) error {
	pid, e := bootstrapPeerPIDTable(b, ipv6, local, peer)
	if e != nil {
		return e
	}
	if pid == self {
		return dl("proxy_connect", "self_loop")
	}
	return nil
}
