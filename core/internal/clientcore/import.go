package clientcore

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"github.com/shui1iao/Kat/internal/provider"
)

func (h *Host) importParse(ctx context.Context, raw json.RawMessage) (any, *Error) {
	var p struct {
		Text json.RawMessage `json:"text"`
		URL  json.RawMessage `json:"url"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	if (len(p.Text) == 0) == (len(p.URL) == 0) {
		return nil, fail("invalid_params", "params", "Exactly one text or url required")
	}
	var text string
	value := p.Text
	if len(p.URL) > 0 {
		value = p.URL
	}
	if string(value) == "null" || json.Unmarshal(value, &text) != nil {
		return nil, fail("invalid_params", "params", "Expected string")
	}
	h.mu.Lock()
	probe := h.doc.client.ProbeURL
	if len(p.URL) > 0 {
		h.syncTUNEgressLocked()
		if !h.hostEgressReadyLocked() {
			h.mu.Unlock()
			return nil, fail("import_fetch_failed", "params.url", "Physical egress is unavailable")
		}
	}
	policy := h.egress
	if len(p.URL) > 0 {
		var stop func()
		ctx, stop = h.bootstrapContextLocked(ctx)
		defer stop()
	}
	taken := map[string]bool{}
	for _, o := range h.doc.config.Outbounds {
		taken[o.Name] = true
	}
	for _, g := range h.doc.config.Groups {
		taken[g.Name] = true
	}
	if h.server != nil {
		c := h.server.CurrentConfig()
		for _, o := range c.Outbounds {
			taken[o.Name] = true
		}
		for _, g := range c.Groups {
			taken[g.Name] = true
		}
	}
	h.mu.Unlock()
	b := []byte(text)
	if len(p.URL) > 0 {
		// One budget includes fetch and subsequent parse/materialization; the
		// transport's child deadline cannot restart it after receiving the body.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if !validImportURL(text) {
			return nil, fail("invalid_params", "params.url", "Expected public HTTPS subscription URL")
		}
		var err error
		ctx, done := h.ipContext(ctx)
		defer done()
		b, err = fetchImport(ctx, text, policy, nil)
		if err != nil {
			return nil, fail("import_fetch_failed", "params.url", "Subscription fetch failed")
		}
	}
	if ctx.Err() != nil {
		return nil, fail("import_canceled", "params", "Import canceled")
	}
	r, err := provider.Parse(b, provider.FormatAuto)
	if err != nil {
		return nil, fail("import_failed", "params", "Unsupported or invalid node content")
	}
	outs, groups, _, err := r.Materialize("", probe, taken, nil)
	if err != nil {
		return nil, fail("import_dependency_failed", "params", "Invalid subscription dependency graph")
	}
	skipped := []any{}
	for _, v := range r.Skipped {
		skipped = append(skipped, map[string]any{"name": v.Name, "type": v.Type, "reason": v.Reason})
	}
	result := map[string]any{"outbounds": outs, "skipped": skipped, "dependency_groups": groups}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > MaxFrame-1024 {
		return nil, fail("import_too_large", "params", "Import result exceeds response budget")
	}
	if ctx.Err() != nil {
		return nil, fail("import_canceled", "params", "Import canceled")
	}
	if checkHostEgress(ctx) != nil {
		return nil, fail("import_canceled", "params", "Import canceled")
	}
	return result, nil
}
func validImportURL(raw string) bool {
	if raw == "" || len(raw) > 8192 || strings.ContainsFunc(raw, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) {
		return false
	}
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Opaque != "" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
		return false
	}
	if strings.HasSuffix(u.Host, ":") {
		return false
	}
	if p := u.Port(); p != "" {
		n, e := strconv.ParseUint(p, 10, 16)
		if e != nil || n == 0 {
			return false
		}
	}
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil {
		return publicImportIP(ip)
	}
	return !strings.Contains(u.Hostname(), ":") && !strings.Contains(u.Hostname(), "%")
}

var importReserved = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range strings.Fields("0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/3 2001::/23 2001:db8::/32 2002::/16 3fff::/20") {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

func publicImportIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" || ip.Is4In6() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, p := range importReserved {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// seam replaces only RoundTrip for local tests; production always uses the
// checked resolver + literal dial below, with ordinary certificate validation.
func fetchImport(ctx context.Context, raw string, policy *clientegress.Policy, seam func(*http.Transport) http.RoundTripper) ([]byte, error) {
	return fetchImportBounded(ctx, raw, policy, seam, provider.MaxSize)
}
func fetchImportBounded(ctx context.Context, raw string, policy *clientegress.Policy, seam func(*http.Transport) http.RoundTripper, limit int64) ([]byte, error) {
	budget := 30 * time.Second
	if c, _ := ctx.Value(legacyKey{}).(*legacyConversion); c != nil && c.Config.Timeout > 0 {
		budget = min(budget, time.Duration(c.Config.Timeout))
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	resolve := func(ctx context.Context, host string) ([]netip.Addr, error) {
		var ips []netip.Addr
		var e error
		if e := checkHostEgress(ctx); e != nil {
			return nil, e
		}
		if s := hostEgress(ctx); s != nil {
			ips, e = s.Bootstrap(ctx, ipNetwork(ctx), host)
		} else if policy != nil {
			if !policy.Ready() {
				return nil, dl("connect", "egress_unavailable")
			}
			ips, e = policy.Bootstrap(ctx, ipNetwork(ctx), host)
		} else {
			ips, e = net.DefaultResolver.LookupNetIP(ctx, ipNetwork(ctx), host)
		}
		if e != nil {
			return nil, safeFailure(ctx, "resolve", e)
		}
		return checkedImportAddresses(ips, e)
	}
	options := direct.Options{DisableIPv6: ipDisabled(ctx), Resolve: resolve, Guard: func(_ context.Context, ip netip.Addr) bool { return !publicImportIP(ip) }, Timeout: 10 * time.Second}
	if s := hostEgress(ctx); s != nil {
		// Borrow the exact Switch: freeze and post-dial epoch/socket ownership
		// checks apply even to a request that originally captured nil policy.
		options.DialContext = func(ctx context.Context, n, a string) (net.Conn, error) { return dialHostEgress(ctx, s, n, a) }
	} else if policy != nil {
		options.Control = policy.Control
	}
	d := direct.New(options)
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if e := checkHostEgress(ctx); e != nil {
			return nil, e
		}
		if policy != nil && !policy.Ready() {
			return nil, dl("connect", "egress_unavailable")
		}
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, dl("resolve", "address_refused")
		}
		n, e := strconv.ParseUint(port, 10, 16)
		if e != nil || n == 0 {
			return nil, dl("resolve", "address_refused")
		}
		if p := bootstrapFrom(ctx); p != nil {
			return dialBootstrap(ctx, address, p, policy, resolve, nil)
		}
		c, e := d.DialTCP(ctx, outbound.Addr{Host: host, Port: uint16(n)})
		if e != nil {
			return nil, safeFailure(ctx, "connect", e)
		}
		return c, nil
	}}
	defer tr.CloseIdleConnections()
	var rt http.RoundTripper = tr
	if seam != nil {
		rt = seam(tr)
	}
	client := &http.Client{Transport: rt, CheckRedirect: subscriptionRedirectPolicy(ctx)}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if e != nil {
		return nil, dl("url_check", "address_refused")
	}
	var transportStage atomic.Int32
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{TLSHandshakeStart: func() { transportStage.Store(1) }, TLSHandshakeDone: func(_ tls.ConnectionState, e error) {
		if e == nil {
			transportStage.Store(2)
		}
	}}))
	req.Header.Set("User-Agent", "clash.meta")
	if c, _ := ctx.Value(legacyKey{}).(*legacyConversion); c != nil {
		if c.Config.UserAgent != "" {
			req.Header.Set("User-Agent", c.Config.UserAgent)
		}
		for k, v := range c.Config.Headers {
			req.Header.Set(k, v)
		}
	}
	resp, e := client.Do(req)
	if e != nil {
		stage := "connect"
		if transportStage.Load() == 1 {
			stage = "tls"
		}
		if transportStage.Load() == 2 {
			stage = "http_status"
		}
		return nil, safeFailure(ctx, stage, e)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		category := "http_status"
		if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
			category = "redirect_refused"
		}
		return nil, &downloadFailure{stage: "http_status", category: category, status: resp.StatusCode}
	}
	captureSubscriptionHeaders(ctx, resp.Header)
	b, e := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if e != nil {
		return nil, safeFailure(ctx, "body_read", e)
	}
	if int64(len(b)) > limit {
		return nil, dl("body_read", "size_limit")
	}
	return b, nil
}

// Called on the exact resolver result used for the ensuing literal socket.
func checkedImportAddresses(ips []netip.Addr, e error) ([]netip.Addr, error) {
	if e != nil || len(ips) == 0 {
		return nil, dl("resolve", "dns_failed")
	}
	for _, ip := range ips {
		if !publicImportIP(ip) {
			// Classification only: fake-IP remains refused on the direct route.
			if netip.MustParsePrefix("198.18.0.0/15").Contains(ip) {
				return nil, dl("resolve", "fake_ip")
			}
			return nil, dl("resolve", "address_refused")
		}
	}
	return ips, nil
}
