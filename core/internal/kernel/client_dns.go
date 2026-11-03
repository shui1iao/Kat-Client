package kernel

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

var ErrDNSInvalidName = errors.New("invalid DNS name")
var ErrCoreNotRunning = errors.New("core not running")

type DNSAddress struct {
	Addr string `json:"addr"`
	Type string `json:"type"`
}
type DNSQueryReply struct {
	Name       string       `json:"name"`
	Addresses  []DNSAddress `json:"addresses"`
	Server     string       `json:"server"`
	DurationMS int64        `json:"duration_ms"`
	Cached     bool         `json:"cached"`
}

func (e dnsEndpoint) label() string {
	if e.scheme == "https" {
		return "HTTPS " + e.url
	}
	host := e.host
	if e.port != "53" {
		host = net.JoinHostPort(e.host, e.port)
	}
	return strings.ToUpper(e.scheme) + " " + host
}
func (s *Server) QueryDNS(ctx context.Context, name, typ string) (DNSQueryReply, error) {
	start := time.Now()
	name, err := dnsName(name)
	if err != nil {
		return DNSQueryReply{}, ErrDNSInvalidName
	}
	if typ != "A" && typ != "AAAA" && typ != "both" {
		return DNSQueryReply{}, ErrDNSInvalidName
	}
	if s.core.ctx.Err() != nil {
		return DNSQueryReply{}, ErrCoreNotRunning
	}
	g := s.current()
	if !g.tryRef() {
		return DNSQueryReply{}, ErrCoreNotRunning
	}
	defer g.unref()
	ctx, cancel := context.WithTimeout(ctx, g.cfg.Limits.DialTimeout.value())
	defer cancel()
	stop := context.AfterFunc(s.core.ctx, cancel)
	defer stop()
	if typ == "AAAA" && g.cfg.IPv6Disabled() {
		return DNSQueryReply{Name: name, Addresses: []DNSAddress{}, Server: "IPv6 已关闭"}, nil
	}
	// Query exactly the ordinary dual-family chain, including its existing cache.
	// Type only filters the returned view; it cannot change cache keys or TTLs.
	ips, server, cached, err := g.dns.lookupAnswer(ctx, name)
	if err != nil {
		return DNSQueryReply{}, err
	}
	out := DNSQueryReply{Name: name, Addresses: []DNSAddress{}, Server: server, Cached: cached, DurationMS: time.Since(start).Milliseconds()}
	for _, ip := range ips {
		t := "AAAA"
		if ip.Is4() {
			t = "A"
		}
		if typ == "both" || typ == t {
			out.Addresses = append(out.Addresses, DNSAddress{ip.String(), t})
		}
	}
	return out, nil
}
