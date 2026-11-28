package kernel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"io"
	"net"
	"net/netip"
	"strings"
)

type dnsPolicyRuntime struct {
	rule     DNSRule
	resolver *internalDNS
}

func validateDNSPolicy(o *DNSOptions) error {
	if o == nil {
		return nil
	}
	rules, e := effectiveDNSRules(o)
	if e != nil {
		return e
	}
	if len(rules) > 256 || len(o.Hosts) > 1024 {
		return errNetworkConfig
	}
	for _, r := range rules {
		if r.Match != "domain" && r.Match != "domain_suffix" && r.Match != "keyword" {
			return errNetworkConfig
		}
		if r.Domain == "" || len(r.Domain) > 253 || strings.TrimSpace(r.Domain) != r.Domain {
			return errNetworkConfig
		}
		if r.Match != "keyword" {
			if _, e := dnsName(r.Domain); e != nil {
				return e
			}
		}
		if len(r.Servers) == 0 {
			return errNetworkConfig
		}
		if _, e := dnsEndpoints(&DNSOptions{Servers: r.Servers}); e != nil {
			return e
		}
	}
	seen := map[string]bool{}
	for name, addresses := range o.Hosts {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if _, e := dnsName(strings.TrimPrefix(name, "*.")); e != nil {
			return e
		}
		if seen[name] || len(addresses) == 0 || len(addresses) > maxDNSAddresses {
			return errNetworkConfig
		}
		seen[name] = true
		for _, s := range addresses {
			ip, e := netip.ParseAddr(s)
			if e != nil || ip.Zone() != "" {
				return errNetworkConfig
			}
		}
	}
	return nil
}
func (r DNSRule) matches(name string) bool {
	value := strings.ToLower(r.Domain)
	if r.Match != "keyword" {
		value = strings.TrimSuffix(value, ".")
	}
	switch r.Match {
	case "domain":
		return name == value
	case "domain_suffix":
		return name == value || strings.HasSuffix(name, "."+value)
	case "keyword":
		return strings.Contains(name, value)
	}
	return false
}
func (r *internalDNS) policy(name string) *internalDNS {
	for _, p := range r.rules {
		if p.rule.matches(name) {
			return p.resolver
		}
	}
	return r
}
func (r *internalDNS) host(name string) ([]netip.Addr, bool) {
	addresses, ok := r.hosts[name]
	if !ok {
		// Exact keys win, then the longest wildcard suffix (deterministic for maps).
		longest := 0
		for key, ips := range r.hosts {
			if strings.HasPrefix(key, "*.") && strings.HasSuffix(name, key[1:]) && len(key) > longest {
				addresses, ok, longest = ips, true, len(key)
			}
		}
	}
	if !ok {
		return nil, false
	}
	out := make([]netip.Addr, 0, len(addresses))
	for _, ip := range addresses {
		if !r.disableIPv6 || ip.Is4() {
			out = append(out, ip)
		}
	}
	return out, true
}
func (r *internalDNS) configureIO(disabled bool, bootstrap func(context.Context, string, string) ([]netip.Addr, error), dial dnsDial, physical []netip.Addr, system ...func(context.Context, []byte) ([]byte, error)) {
	r.disableIPv6 = disabled
	r.bootstrap = func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if disabled {
			if network == "ip6" {
				return []netip.Addr{}, nil
			}
			network = "ip4"
		}
		ips, e := bootstrap(ctx, network, host)
		if disabled {
			filtered := ips[:0:0]
			for _, ip := range ips {
				if ip.Unmap().Is4() {
					filtered = append(filtered, ip.Unmap())
				}
			}
			ips = filtered
		}
		return ips, e
	}
	r.dial = dial
	for _, p := range r.rules {
		p.resolver.configureIO(disabled, bootstrap, dial, physical, system...)
	}
	// Keep legacy target metadata for non-opted-in internal callers. Production
	// desktop system wire I/O uses SystemQuery, never this flattened address set
	// or Windows' resolver (which could loop back through the TUN peer).
	r.physical = append([]netip.Addr(nil), physical...)
	if len(system) > 0 {
		r.systemQuery = system[0]
	}
}
func (r *internalDNS) clearCache() int {
	return r.clearCacheVisited(map[*internalDNS]bool{})
}

func (r *internalDNS) clearCacheVisited(visited map[*internalDNS]bool) int {
	if r == nil || visited[r] {
		return 0
	}
	visited[r] = true
	r.mu.Lock()
	r.clearSeq++
	n := len(r.cache) + len(r.wireCache)
	clear(r.cache)
	clear(r.wireCache)
	r.mu.Unlock()
	for _, p := range r.rules {
		n += p.resolver.clearCacheVisited(visited)
	}
	if r.local != nil {
		n += r.local.clearCacheVisited(visited)
	}
	return n
}

func (r *internalDNS) closeVisited(visited map[*internalDNS]bool) {
	if r == nil || visited[r] {
		return
	}
	visited[r] = true
	for _, p := range r.rules {
		p.resolver.closeVisited(visited)
	}
	if r.local != nil {
		r.local.closeVisited(visited)
	}
	for _, u := range r.upstreams {
		if u.transport != nil {
			u.transport.CloseIdleConnections()
		}
	}
}

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
			dns.setEventSink(s.core.dnsSink)
			dns.setOwner(s)
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
	s.directDNS.setEventSink(s.core.dnsSink)
	s.directDNS.setOwner(s)
	s.bootstrapDNS.setDiagnostic(s.runtimeDiagnostic)
	s.bootstrapDNS.setEventSink(s.core.dnsSink)
	s.bootstrapDNS.setOwner(s)
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
	dns.setEventSink(s.core.dnsSink)
	dns.setOwner(s)
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
	var ips []netip.Addr
	var e error
	if s.directDNS != nil {
		ips, e = s.directDNS.lookup(ctx, host)
		ips, e = s.realDNSAnswer(ips, e)
	} else {
		ips, e = s.lookup(ctx, host)
	}
	if e == nil && s.rt != nil && s.rt.icmp != nil {
		s.rt.icmp.noteResolved(host, ips, false)
	}
	return ips, e
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

func (p clientDirectPacket) SelectCandidate(c []netip.AddrPort) (netip.AddrPort, error) {
	selector, ok := p.PacketConn.(interface {
		SelectCandidate([]netip.AddrPort) (netip.AddrPort, error)
	})
	if !ok {
		return netip.AddrPort{}, errRouteReject
	}
	return selector.SelectCandidate(c)
}

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

// DNSHosts accepts mihomo's scalar-or-list values, but marshals the native
// multi-address form. Source documents are never marshalled from this runtime.
type DNSHosts map[string][]string

func (h *DNSHosts) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil || raw == nil {
		return errNetworkConfig
	}
	out := DNSHosts{}
	for name, v := range raw {
		var addresses []string
		var one string
		if json.Unmarshal(v, &one) == nil {
			addresses = []string{one}
		} else if json.Unmarshal(v, &addresses) != nil || addresses == nil {
			return errNetworkConfig
		}
		out[name] = addresses
	}
	*h = out
	return nil
}

// DecodeMihomoDNSPolicy preserves declaration order (first match wins). The
// supported import subset is exact / +.suffix. Document export retains the
// original DNS field spelling in both JSON and YAML; native keyword rules stay
// in rules and never undergo a forced mihomo conversion. Unsupported selectors
// are rejected on import, not guessed or silently dropped.
func DecodeMihomoDNSPolicy(b []byte) ([]DNSRule, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	tok, e := d.Token()
	if e != nil || tok != json.Delim('{') {
		return nil, errNetworkConfig
	}
	rules := []DNSRule{}
	seen := map[string]bool{}
	for d.More() {
		tok, e := d.Token()
		if e != nil {
			return nil, errNetworkConfig
		}
		key, ok := tok.(string)
		if !ok || seen[key] {
			return nil, errNetworkConfig
		}
		seen[key] = true
		r := DNSRule{Match: "domain", Domain: key}
		switch {
		case strings.HasPrefix(key, "+."):
			r.Match = "domain_suffix"
			r.Domain = key[2:]
		case strings.ContainsAny(key, ":*+"):
			return nil, errNetworkConfig
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, errNetworkConfig
		}
		var server string
		if json.Unmarshal(value, &server) == nil {
			r.Servers = []string{server}
		} else if json.Unmarshal(value, &r.Servers) != nil {
			return nil, errNetworkConfig
		}
		rules = append(rules, r)
	}
	if _, e = d.Token(); e != nil {
		return nil, errNetworkConfig
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errNetworkConfig
	}
	if e := validateDNSPolicy(&DNSOptions{Rules: rules}); e != nil {
		return nil, e
	}
	return rules, nil
}
func effectiveDNSRules(o *DNSOptions) ([]DNSRule, error) {
	if o == nil {
		return nil, nil
	}
	if o.NameserverPolicy != nil {
		if len(o.Rules) > 0 {
			return nil, errNetworkConfig
		}
		return DecodeMihomoDNSPolicy(o.NameserverPolicy)
	}
	return o.Rules, nil
}
