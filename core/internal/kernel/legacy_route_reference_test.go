package kernel

import (
	"net/netip"
	"strings"
)

func (r RouteRule) matchDomain(name string) bool {
	return name != "" && (r.Domain == name || r.DomainSuffix != "" && (name == r.DomainSuffix || strings.HasSuffix(name, "."+r.DomainSuffix)))
}
func (s *Server) routeDirect(name string, ip netip.Addr) bool {
	if s.cfg.Routing == nil {
		return true
	}
	ip = ip.Unmap()
	for _, r := range s.cfg.Routing.Rules {
		if r.matchDomain(name) || r.IPCIDR != "" && r.prefix.Contains(ip) {
			return r.Action == "direct"
		}
	}
	return true
}
