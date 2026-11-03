package kernel

import (
	"context"
	"net"
	"net/netip"
	"syscall"
)

// ClientEgress is a non-JSON, instance-local hook. Servers not opting into it
// retain their existing dialing/resolver/reload behavior.
type ClientEgress struct {
	Failure       func()
	Control       func(context.Context, string, string, syscall.RawConn) error
	PacketControl func(string, *net.UDPConn) error
	Bootstrap     func(context.Context, string, string) ([]netip.Addr, error)
	// DNSServers are the host's original physical resolvers (literal bootstrap DNS).
	DNSServers []netip.Addr
}

// SetClientIPv6 opts a desktop instance into the local address-family policy.
// Standalone servers retain dual-stack behaviour.
func (c *Config) SetClientIPv6(enabled bool) { c.clientIPv6 = &enabled }
func (c *Config) IPv6Disabled() bool         { return c.clientIPv6 != nil && !*c.clientIPv6 }

func (c *Config) SetClientEgress(e *ClientEgress) { c.clientEgress = e; c.clientEgressSet = true }

// originalResolver reports whether ip:port is one of the host's original
// physical resolvers. While client egress (TUN) is on, the host routes these
// literal addresses into TUN; such DNS traffic is sent directly over the bound
// physical interface instead of through a node, which usually cannot reach a
// private LAN resolver.
func (e *ClientEgress) originalResolver(ip netip.Addr, port uint16) bool {
	if e == nil || port != 53 || !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	for _, d := range e.DNSServers {
		if d.Unmap() == ip {
			return true
		}
	}
	return false
}

func (s *Server) trafficContext() context.Context {
	if s.clientLife != nil {
		return s.clientLife
	}
	return s.ctx
}
