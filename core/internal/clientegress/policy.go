// Package clientegress is the instance-local Windows physical egress policy.
// It does not change interfaces, DNS settings, routes, or any other process.
package clientegress

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"syscall"
)

const Schema = 3
const MaxSystemDNS = 16

type DNSEndpoint struct {
	Address string `json:"address"`
	Owner   uint64 `json:"owner_luid"`
	IfIndex uint32 `json:"if_index"`
	Scope   uint32 `json:"scope_id"`
}
type Options struct {
	MetricDigest  string        `json:"metric_digest"`
	GatewayDigest string        `json:"gateway_digest"`
	AddressDigest string        `json:"address_digest"`
	Schema        int           `json:"schema"`
	Enabled       bool          `json:"enabled"`
	IPv4          *uint32       `json:"ipv4_if_index"`
	IPv6          *uint32       `json:"ipv6_if_index"`
	LUID4         *uint64       `json:"ipv4_luid"`
	LUID6         *uint64       `json:"ipv6_luid"`
	DNS           []DNSEndpoint `json:"system_dns"`
	Identity      string        `json:"identity"`
	Fingerprint   string        `json:"fingerprint"`
}

func (o Options) Clone() Options {
	o.DNS = append([]DNSEndpoint{}, o.DNS...)
	if o.IPv4 != nil {
		v := *o.IPv4
		o.IPv4 = &v
	}
	if o.IPv6 != nil {
		v := *o.IPv6
		o.IPv6 = &v
	}
	if o.LUID4 != nil {
		v := *o.LUID4
		o.LUID4 = &v
	}
	if o.LUID6 != nil {
		v := *o.LUID6
		o.LUID6 = &v
	}
	return o
}

type View struct {
	Options
	Ready       bool     `json:"ready"`
	Generation  uint64   `json:"generation"`
	Coverage    []string `json:"coverage"`
	DNSRevision uint64   `json:"dns_revision"`
}

var Coverage = []string{"tcp", "udp", "dns", "bootstrap", "provider", "probe"}

type Policy struct {
	Options     Options
	failed      atomic.Bool
	disableIPv6 atomic.Bool
	dns         atomic.Pointer[dnsRevision]
	dnsSlots    chan struct{}
	bind        func(string, syscall.RawConn) error
	owner       func(DNSEndpoint) error
	dnsConnect  func(context.Context, string, string, func(context.Context, string, string, syscall.RawConn) error) (net.Conn, error)
}

func New(o Options) (*Policy, error) {
	if !Supported {
		return nil, errors.New("Windows egress is unsupported on this platform")
	}
	o = o.Clone()
	for _, s := range []string{o.MetricDigest, o.GatewayDigest, o.AddressDigest} {
		if len(s) != 64 {
			return nil, errors.New("egress v3 change categories required")
		}
		if _, e := hex.DecodeString(s); e != nil {
			return nil, errors.New("invalid egress change category")
		}
	}
	return newPolicy(o, platformBind(o), platformValidate)
}
func newPolicy(o Options, bind func(string, syscall.RawConn) error, validate func(Options) error) (*Policy, error) {
	if !o.Enabled {
		return nil, nil
	}
	if o.Schema != Schema || (o.IPv4 == nil && o.IPv6 == nil) || len(o.DNS) == 0 || len(o.DNS) > MaxSystemDNS || len(o.Identity) != 64 || len(o.Fingerprint) != 64 {
		return nil, errors.New("physical egress v2 endpoints required")
	}
	if _, e := hex.DecodeString(o.Identity); e != nil {
		return nil, errors.New("invalid egress identity")
	}
	if _, e := hex.DecodeString(o.Fingerprint); e != nil {
		return nil, errors.New("invalid physical fingerprint")
	}
	if (o.IPv4 == nil) != (o.LUID4 == nil) || (o.IPv6 == nil) != (o.LUID6 == nil) {
		return nil, errors.New("physical owner required")
	}
	for _, n := range []*uint32{o.IPv4, o.IPv6} {
		if n != nil && *n == 0 {
			return nil, errors.New("invalid physical index")
		}
	}
	for _, n := range []*uint64{o.LUID4, o.LUID6} {
		if n != nil && *n == 0 {
			return nil, errors.New("invalid physical owner")
		}
	}
	seen := map[DNSEndpoint]bool{}
	for _, d := range o.DNS {
		ip, e := netip.ParseAddr(d.Address)
		if e != nil || ip.Zone() != "" || !dnsAddressAllowed(ip) || d.Owner == 0 || d.IfIndex == 0 || seen[d] || (o.LUID4 == nil || d.Owner != *o.LUID4) && (o.LUID6 == nil || d.Owner != *o.LUID6) {
			return nil, errors.New("invalid registered system DNS endpoint")
		}
		if ip.Is6() && ip.IsLinkLocalUnicast() {
			if d.Scope != d.IfIndex {
				return nil, errors.New("invalid DNS scope")
			}
		} else if d.Scope != 0 {
			return nil, errors.New("unexpected DNS scope")
		}
		seen[d] = true
	}
	if validate != nil {
		if e := validate(o); e != nil {
			return nil, e
		}
	}
	// Freeze the full endpoint identity, including owner and scope.
	o = o.Clone()
	p := &Policy{Options: o, bind: bind, dnsSlots: make(chan struct{}, 64), owner: platformDNSOwner, dnsConnect: connectDNS}
	// The Go resolver retains its CNAME/dual-family/StrictErrors semantics, but
	// its wire requests and raw gateway requests share exactly one transport.
	p.installDNS(o, 1)
	return p, nil
}
func (p *Policy) Ready() bool { return p != nil && !p.failed.Load() }
func (p *Policy) Fail() {
	if p != nil {
		p.failed.Store(true)
		if state := p.dns.Load(); state != nil {
			state.cancel()
		}
	}
}
func (p *Policy) Control(ctx context.Context, network, address string, raw syscall.RawConn) error {
	if !p.Ready() {
		return errors.New("physical lease unavailable")
	}
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
		return errors.New("no controlled physical interface for address family")
	}
	owner, index := p.Options.LUID4, p.Options.IPv4
	if family[len(family)-1] == '6' {
		owner, index = p.Options.LUID6, p.Options.IPv6
	}
	if owner != nil && index != nil {
		if e = p.owner(DNSEndpoint{Address: ip.String(), Owner: *owner, IfIndex: *index}); e != nil {
			p.Fail()
			return errors.New("physical owner family unavailable")
		}
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
	if !p.Ready() {
		return nil, errors.New("physical lease unavailable")
	}
	if p.disableIPv6.Load() {
		if network == "ip6" {
			return []netip.Addr{}, nil
		}
		network = "ip4"
	}
	ctx, cancel, _ := p.DNSContext(ctx)
	defer cancel()
	state := p.dns.Load()
	ips, e := state.resolver.LookupNetIP(ctx, network, host)
	if ctx.Err() != nil || state != p.dns.Load() {
		return nil, context.Canceled
	}
	if !p.Ready() {
		return nil, errors.New("physical lease unavailable")
	}
	return ips, e
}

func (p *Policy) SetIPv6(enabled bool) {
	if p != nil {
		p.disableIPv6.Store(!enabled)
	}
}

func Blocked() *Policy {
	p := &Policy{Options: Options{Schema: Schema, Enabled: true, DNS: []DNSEndpoint{}}}
	p.failed.Store(true)
	p.installDNS(p.Options, 1)
	return p
}
func NewRevision(o Options, number uint64) (*Policy, error) {
	p, e := New(o)
	if e == nil && p != nil {
		p.installDNS(o, number)
	}
	return p, e
}
