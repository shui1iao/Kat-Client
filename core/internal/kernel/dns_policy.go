package kernel

import (
	"context"
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
func (r *internalDNS) configureIO(disabled bool, bootstrap func(context.Context, string, string) ([]netip.Addr, error), dial dnsDial, physical []netip.Addr) {
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
		p.resolver.configureIO(disabled, bootstrap, dial, physical)
	}
	// TUN's existing original physical DNS addresses are kept unchanged. System
	// wire fallback uses these literal servers and the same bound socket hooks,
	// never Windows' resolver (which would loop back through TUN).
	r.physical = append([]netip.Addr(nil), physical...)
}
func (r *internalDNS) clearCache() int {
	r.mu.Lock()
	n := len(r.cache) + len(r.wireCache)
	clear(r.cache)
	clear(r.wireCache)
	r.mu.Unlock()
	for _, p := range r.rules {
		n += p.resolver.clearCache()
	}
	return n
}
