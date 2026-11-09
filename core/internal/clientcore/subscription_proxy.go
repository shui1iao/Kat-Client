package clientcore

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/clientegress"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

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
