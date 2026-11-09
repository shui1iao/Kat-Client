package clientcore

import (
	"context"
	"github.com/shui1iao/Kat/internal/clientegress"
	"net"
	"net/http"
	"net/netip"
	"time"
)

type mainRouteKey struct{}

func subscriptionRedirect(req *http.Request, via []*http.Request) error {
	if e := checkHostEgress(req.Context()); e != nil {
		return e
	}
	if len(via) > 5 || !validImportURL(req.URL.String()) || req.URL.Scheme != via[0].URL.Scheme {
		return dl("url_check", "redirect_refused")
	}
	// Explicitly validate each hop, also on the SOCKS route where DNS may be
	// remote. Never let redirects acquire access to loopback/private services.
	if ip, e := netip.ParseAddr(req.URL.Hostname()); e == nil {
		if !publicImportIP(ip) {
			return dl("url_check", "redirect_refused")
		}
	} else {
		var ips []netip.Addr
		var e error
		if s := hostEgress(req.Context()); s != nil {
			ips, e = s.Bootstrap(req.Context(), ipNetwork(req.Context()), req.URL.Hostname())
		} else {
			ips, e = net.DefaultResolver.LookupNetIP(req.Context(), ipNetwork(req.Context()), req.URL.Hostname())
		}
		if _, e = checkedImportAddresses(ips, e); e != nil {
			return dl("url_check", "redirect_refused")
		}
	}
	if e := checkHostEgress(req.Context()); e != nil {
		return e
	}
	req.Header = make(http.Header)
	req.Header.Set("User-Agent", "clash.meta")
	return nil
}
func (h *Host) fetchMainSubscription(ctx context.Context, url string, policy *clientegress.Policy, limit int64, mode, last string, proxy *bootstrapProxy) ([]byte, string, error) {
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
