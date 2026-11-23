package kernel

import (
	"context"
	"net"
	"net/netip"
)

type carrierEndpointKey struct{}

// The port is the actual listener (including ephemeral bindings); a different
// local proxy remains available. Only a wildcard port match needs OS lookup.
func (s *Server) blockOwnCarrier(ctx context.Context, dst netip.AddrPort) bool {
	carrier, _ := ctx.Value(carrierEndpointKey{}).(bool)
	if !carrier {
		return false
	}
	for _, l := range s.current().listeners {
		a, ok := l.Addr().(*net.TCPAddr)
		if !ok || a.Port != int(dst.Port()) {
			continue
		}
		bound := a.AddrPort().Addr().Unmap()
		ip := dst.Addr().Unmap()
		if ip.IsUnspecified() {
			if ip.Is4() {
				ip = netip.AddrFrom4([4]byte{127, 0, 0, 1})
			} else {
				ip = netip.IPv6Loopback()
			}
		}
		if bound == ip {
			return true
		}
		if !bound.IsUnspecified() || bound.Is4() && !ip.Is4() {
			continue
		}
		if ip.IsLoopback() || ip.IsUnspecified() {
			return true
		}
		addrs, e := net.InterfaceAddrs()
		if e != nil {
			return true
		}
		for _, a := range addrs {
			if addr, ok := a.(*net.IPNet); ok {
				local, ok := netip.AddrFromSlice(addr.IP)
				if ok && local.Unmap() == ip {
					return true
				}
			}
		}
	}
	return false
}
