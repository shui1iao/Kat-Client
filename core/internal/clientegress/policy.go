// Package clientegress is the instance-local Windows physical egress policy.
// It does not change interfaces, DNS settings, routes, or any other process.
package clientegress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"syscall"
)

type Options struct {
	Enabled bool     `json:"enabled"`
	IPv4    *uint32  `json:"ipv4_if_index"`
	IPv6    *uint32  `json:"ipv6_if_index"`
	DNS     []string `json:"bootstrap_dns"`
}
type View struct {
	Options
	Ready      bool     `json:"ready"`
	Generation uint64   `json:"generation"`
	Coverage   []string `json:"coverage"`
}

var Coverage = []string{"tcp", "udp", "dns", "bootstrap", "provider", "probe"}

type Policy struct {
	Options     Options
	failed      atomic.Bool
	disableIPv6 atomic.Bool
	resolver    *net.Resolver
	dial        func(context.Context, string, string) (net.Conn, error)
	next        atomic.Uint64
	bind        func(string, syscall.RawConn) error
}

func New(o Options) (*Policy, error) {
	if !Supported {
		return nil, errors.New("Windows egress is unsupported on this platform")
	}
	return newPolicy(o, platformBind(o), platformValidate)
}
func newPolicy(o Options, bind func(string, syscall.RawConn) error, validate func(Options) error) (*Policy, error) {
	if !o.Enabled {
		return nil, nil
	}
	if (o.IPv4 == nil && o.IPv6 == nil) || len(o.DNS) == 0 || len(o.DNS) > 8 {
		return nil, errors.New("physical indices and literal bootstrap DNS required")
	}
	for _, n := range []*uint32{o.IPv4, o.IPv6} {
		if n != nil && *n == 0 {
			return nil, errors.New("invalid physical interface index")
		}
	}
	for _, s := range o.DNS {
		ip, e := netip.ParseAddr(s)
		if e != nil || ip.Zone() != "" || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || (ip.Unmap().Is4() && o.IPv4 == nil) || (ip.Is6() && !ip.Is4In6() && o.IPv6 == nil) {
			return nil, errors.New("bootstrap DNS must be physical literal addresses with an interface")
		}
	}
	if validate != nil {
		if e := validate(o); e != nil {
			return nil, e
		}
	}
	// Copy host-owned slices/pointers so future IPC decoding cannot mutate policy.
	o.DNS = append([]string(nil), o.DNS...)
	if o.IPv4 != nil {
		v := *o.IPv4
		o.IPv4 = &v
	}
	if o.IPv6 != nil {
		v := *o.IPv6
		o.IPv6 = &v
	}
	p := &Policy{Options: o, bind: bind}
	p.dial = (&net.Dialer{ControlContext: p.Control}).DialContext
	p.resolver = &net.Resolver{PreferGo: true, StrictErrors: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		for range o.DNS {
			i := p.next.Add(1) - 1
			ip := o.DNS[i%uint64(len(o.DNS))]
			addr, _ := netip.ParseAddr(ip)
			if p.disableIPv6.Load() && addr.Unmap().Is6() {
				continue
			}
			return p.dial(ctx, network, net.JoinHostPort(ip, "53"))
		}
		return nil, errors.New("ipv6_disabled: no IPv4 bootstrap DNS")
	}}
	return p, nil
}
func (p *Policy) Ready() bool { return p != nil && !p.failed.Load() }
func (p *Policy) Fail() {
	if p != nil {
		p.failed.Store(true)
	}
}
func (p *Policy) Control(ctx context.Context, network, address string, raw syscall.RawConn) error {
	host, _, e := net.SplitHostPort(address)
	if e != nil {
		p.Fail()
		return errors.New("egress requires a literal socket address")
	}
	ip, e := netip.ParseAddr(host)
	if e != nil {
		p.Fail()
		return errors.New("unresolved socket address refused")
	}
	if p.disableIPv6.Load() && ip.Unmap().Is6() && !ip.IsLoopback() {
		return errors.New("ipv6_disabled")
	}
	if ip.Unmap().IsLoopback() {
		return nil
	}
	family := "tcp6"
	if ip.Is4() || ip.Is4In6() {
		family = "tcp4"
	}
	if len(network) >= 3 && network[:3] == "udp" {
		family = "udp" + family[3:]
	}
	if (family[len(family)-1] == '4' && p.Options.IPv4 == nil) || (family[len(family)-1] == '6' && p.Options.IPv6 == nil) {
		p.Fail()
		return errors.New("no controlled physical interface for address family")
	}
	if e = p.bind(family, raw); e != nil {
		p.Fail()
		return errors.New("physical socket binding failed")
	}
	return nil
}
func (p *Policy) PacketControl(network string, c *net.UDPConn) error {
	raw, e := c.SyscallConn()
	if e != nil {
		p.Fail()
		return e
	}
	host := "0.0.0.0"
	if network == "udp6" {
		host = "::"
	}
	return p.Control(context.Background(), network, net.JoinHostPort(host, strconv.Itoa(0)), raw)
}
func (p *Policy) Bootstrap(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if p.disableIPv6.Load() {
		if network == "ip6" {
			return []netip.Addr{}, nil
		}
		network = "ip4"
	}
	return p.resolver.LookupNetIP(ctx, network, host)
}

func (p *Policy) SetIPv6(enabled bool) {
	if p != nil {
		p.disableIPv6.Store(!enabled)
	}
}
