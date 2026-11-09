package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/shui1iao/Kat/internal/outbound"
)

// Desktop-only policy. Nothing is added to the standalone server JSON schema.
type ClientDNSOptions struct {
	// Deprecated compatibility fields: validated and retained in source only.
	// Neither value can enable synthetic DNS or affect real DNS routing.
	FakeIP       *bool            `json:"fake_ip,omitempty"`
	FakeIPFilter []string         `json:"fake_ip_filter,omitempty"`
	Remote       *ClientDNSRemote `json:"remote,omitempty"`
}
type ClientDNSRemote struct {
	Servers  []string `json:"servers,omitempty"`
	Detour   string   `json:"detour,omitempty"`
	Fallback string   `json:"fallback,omitempty"`
}

func (o *ClientDNSOptions) UnmarshalJSON(b []byte) error {
	type plain ClientDNSOptions
	var v plain
	if e := strictNetworkJSON(b, &v); e != nil {
		return e
	}
	if len(v.FakeIPFilter) > 256 {
		return errNetworkConfig
	}
	for i, n := range v.FakeIPFilter {
		name, e := dnsName(n)
		if e != nil {
			return e
		}
		v.FakeIPFilter[i] = name
	}
	*o = ClientDNSOptions(v)
	return nil
}
func (o *ClientDNSRemote) UnmarshalJSON(b []byte) error {
	type plain ClientDNSRemote
	var v plain
	if e := strictNetworkJSON(b, &v); e != nil {
		return e
	}
	if v.Fallback != "" && v.Fallback != "fail_closed" {
		return errNetworkConfig
	}
	if len(v.Servers) > maxDNSServers {
		return errNetworkConfig
	}
	for _, s := range v.Servers {
		ep, e := parseDNS(s)
		if e != nil || ep.scheme != "https" {
			return errNetworkConfig
		}
		if ip, e := netip.ParseAddr(ep.host); e == nil && ClientFakeIP(ip) {
			return errNetworkConfig
		}
	}
	if strings.TrimSpace(v.Detour) != v.Detour {
		return errNetworkConfig
	}
	*o = ClientDNSRemote(v)
	return nil
}

type clientDNSPolicy struct {
	Source       *DNSOptions
	Options      ClientDNSOptions
	Mode, Detour string
}

func (c *Config) SetClientDNSConfig(source *DNSOptions, o *ClientDNSOptions, mode, detour string) {
	p := &clientDNSPolicy{Source: cloneDNSOptions(source), Mode: mode, Detour: detour}
	if o != nil {
		b, _ := json.Marshal(o)
		_ = json.Unmarshal(b, &p.Options)
	}
	if p.Options.Remote != nil && p.Options.Remote.Detour != "" {
		p.Detour = p.Options.Remote.Detour
	}
	c.clientDNS = p
	c.clientDNSSet = true
	// Project only the effective desktop default; Source keeps all user values,
	// including cache sizing for explicit per-domain upstreams.
	if !explicitDNSRoot(source) {
		c.DNS = systemDNSOptions(source)
	}
}
func (s *Server) tunDNSActive() bool     { return s.cfg.clientDNS != nil && s.cfg.clientEgress.active() }
func explicitDNSRoot(o *DNSOptions) bool { return o != nil && (o.Server != "" || len(o.Servers) > 0) }
func systemDNSOptions(source *DNSOptions) *DNSOptions {
	o := cloneDNSOptions(source)
	if o == nil {
		o = &DNSOptions{}
	}
	o.Server = "system"
	o.Servers = nil
	// System replies have no known TTL. Keep the source's numeric cache setting
	// untouched, but never cache un-TTL'd system answers in this role.
	if o.CacheEntries != nil && *o.CacheEntries != 0 {
		o.CacheEntries = nil
	}
	return o
}
func (s *Server) configureClientDNS(bootstrap func(context.Context, string, string) ([]netip.Addr, error), dial dnsDial, physical []netip.Addr, system ...func(context.Context, []byte) ([]byte, error)) error {
	if s.cfg.clientDNS == nil || s.cfg.clientEgress == nil {
		// Provider/resource rebuilds retain the original raw source. Reapply the
		// desktop default even when TUN is off, never the standalone public DNS.
		if p := s.cfg.clientDNS; p != nil && !explicitDNSRoot(p.Source) {
			dns, e := newInternalDNS(systemDNSOptions(p.Source))
			if e != nil {
				return e
			}
			if p.Source != nil && p.Source.CacheEntries != nil {
				for _, child := range dns.rules {
					child.resolver.capacity = *p.Source.CacheEntries
				}
			}
			dns.setDiagnostic(s.runtimeDiagnostic)
			dns.configureIO(s.cfg.IPv6Disabled(), bootstrap, dial, physical, system...)
			s.dns.close()
			s.dns = dns
		}
		return nil
	}
	p := s.cfg.clientDNS
	if p.Source != nil {
		for _, ips := range p.Source.Hosts {
			for _, value := range ips {
				ip, _ := netip.ParseAddr(value)
				if ClientFakeIP(ip) {
					return errFakeIP
				}
			}
		}
	}
	directOptions := cloneDNSOptions(p.Source)
	if !explicitDNSRoot(directOptions) {
		directOptions = systemDNSOptions(directOptions)
	}
	directDNS, e := newInternalDNS(directOptions)
	if e != nil {
		return e
	}
	s.directDNS = directDNS
	// Preserve explicit per-policy cache sizing even when the implicit root is
	// system-only (whose answers have no trustworthy TTL).
	if p.Source != nil && p.Source.CacheEntries != nil {
		for _, child := range s.directDNS.rules {
			child.resolver.capacity = *p.Source.CacheEntries
		}
	}
	bootOptions := &DNSOptions{Server: "system"}
	if p.Source != nil {
		bootOptions.Hosts = cloneDNSOptions(p.Source).Hosts
	}
	bootDNS, e := newInternalDNS(bootOptions)
	if e != nil {
		return e
	}
	s.bootstrapDNS = bootDNS
	s.directDNS.setDiagnostic(s.runtimeDiagnostic)
	s.bootstrapDNS.setDiagnostic(s.runtimeDiagnostic)
	s.directDNS.configureIO(s.cfg.IPv6Disabled(), bootstrap, dial, physical, system...)
	s.bootstrapDNS.configureIO(s.cfg.IPv6Disabled(), bootstrap, dial, physical, system...)
	options := cloneDNSOptions(p.Source)
	protected := !explicitDNSRoot(options) && p.Mode != "direct" && p.Options.Remote != nil && len(p.Options.Remote.Servers) > 0
	if !explicitDNSRoot(options) {
		if protected {
			if options == nil {
				options = &DNSOptions{}
			}
			options.Server = ""
			options.Servers = append([]string(nil), p.Options.Remote.Servers...)
		} else {
			options = systemDNSOptions(options)
		}
	}
	dns, e := newInternalDNS(options)
	if e != nil {
		return e
	}
	if !protected && !explicitDNSRoot(p.Source) && p.Source != nil && p.Source.CacheEntries != nil {
		for _, child := range dns.rules {
			child.resolver.capacity = *p.Source.CacheEntries
		}
	}
	dns.setDiagnostic(s.runtimeDiagnostic)
	dns.configureIO(s.cfg.IPv6Disabled(), bootstrap, dial, physical, system...)
	dns.protected = protected
	if protected {
		dns.policyOnly = true
	}
	// Only omitted root upstreams get the LAN system escape. Explicit source
	// policies/hosts are evaluated before this branch, including on raw queries.
	if !explicitDNSRoot(p.Source) {
		dns.local = s.directDNS
	}
	s.dns.close()
	s.dns = dns
	return nil
}
func (s *Server) bindClientDNS() error {
	if !s.tunDNSActive() || !s.dns.protected {
		return nil
	}
	p := s.cfg.clientDNS
	if p.Detour == "" || p.Detour == "direct" || p.Detour == "reject" {
		return errors.New("TUN DNS requires an explicit proxy final/detour")
	}
	dial, e := s.rt.dialVia(p.Detour)
	if e != nil {
		return e
	}
	s.dns.endpointDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dial(context.WithValue(ctx, protectedDNSKey{}, true), network, addr)
	}
	return nil
}
func (s *Server) closeDNS() {
	s.dns.close()
	s.directDNS.close()
	s.bootstrapDNS.close()
}
func (s *Server) directLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if s.directDNS != nil {
		ips, e := s.directDNS.lookup(ctx, host)
		return s.realDNSAnswer(ips, e)
	}
	return s.lookup(ctx, host)
}
func (s *Server) bootstrapLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if s.bootstrapDNS != nil {
		ips, e := s.bootstrapDNS.lookup(ctx, host)
		return s.realDNSAnswer(ips, e)
	}
	return s.lookup(ctx, host)
}
func (s *Server) realDNSAnswer(ips []netip.Addr, e error) ([]netip.Addr, error) {
	if s.cfg.clientDNS != nil {
		for _, ip := range ips {
			if ClientFakeIP(ip) {
				return nil, errFakeIP
			}
		}
	}
	return ips, e
}

type protectedDNSKey struct{}
type bootstrapDNSKey struct{}

// Select the role before ListenPacket: its WriteTo resolver intentionally has
// a background context, but keeps the selected independent direct instance.
type clientDirect struct {
	outbound.Outbound
	bootstrap outbound.Outbound
}

func (d clientDirect) selectRole(ctx context.Context) (outbound.Outbound, error) {
	if v, _ := ctx.Value(protectedDNSKey{}).(bool); v {
		return nil, errors.New("protected DNS direct leaf refused")
	}
	if v, _ := ctx.Value(bootstrapDNSKey{}).(bool); v {
		return d.bootstrap, nil
	}
	return d.Outbound, nil
}
func (d clientDirect) DialTCP(ctx context.Context, a outbound.Addr) (net.Conn, error) {
	if ip, ok := a.IP(); ok && ClientFakeIP(ip) {
		return nil, errFakeIP
	}
	ob, e := d.selectRole(ctx)
	if e != nil {
		return nil, e
	}
	return ob.DialTCP(ctx, a)
}
func (d clientDirect) ListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	ob, e := d.selectRole(ctx)
	if e != nil {
		return nil, e
	}
	pc, e := ob.ListenPacket(ctx)
	if e != nil {
		return nil, e
	}
	return clientDirectPacket{pc}, nil
}

// A protocol carrier may use literal server addresses in UDP WriteTo without
// asking Resolve. Guard that path too, before physical transmission.
type clientDirectPacket struct{ outbound.PacketConn }

func (p clientDirectPacket) WriteTo(b []byte, a outbound.Addr) (int, error) {
	if ip, ok := a.IP(); ok && ClientFakeIP(ip) {
		return 0, errFakeIP
	}
	return p.PacketConn.WriteTo(b, a)
}

func (s *Server) strictRuleDNS(host string) bool {
	if !s.tunDNSActive() || !s.dns.protected {
		return false
	}
	if s.dns.policy(host) != s.dns {
		return false
	}
	if _, ok := s.dns.host(host); ok {
		return false
	}
	return !(s.dns.local != nil && localDNSName(host))
}
