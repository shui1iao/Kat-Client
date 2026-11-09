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
	UDPAssociationBinding func() (uint64, string, error)
	UDPBinding            func(ipv6 bool) (uint64, string, error)
	Active                func() bool
	Servers               func() []netip.Addr
	DialContext           func(context.Context, string, string) (net.Conn, error)
	PacketRelease         func(*net.UDPConn)
	Failure               func()
	Control               func(context.Context, string, string, syscall.RawConn) error
	// PacketSource selects a real local source before the single net UDP bind.
	PacketSource  func(network string, configured netip.Addr) (netip.Addr, error)
	PacketControl func(string, *net.UDPConn) error
	Bootstrap     func(context.Context, string, string) ([]netip.Addr, error)
	// DNSServers is only the non-scoped compatibility target set for
	// originalResolver. It is NOT used to dial system DNS when SystemQuery is set;
	// that closure retains full immutable owner/scope endpoint identities.
	DNSServers []netip.Addr
	// SystemQuery is the owner/scope-preserving physical DNS-only transport.
	SystemQuery func(context.Context, []byte) ([]byte, error)
	DNSContext  func(context.Context) (context.Context, func(), uint64)
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
	if !e.active() || port != 53 || !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	dns := e.DNSServers
	if e.Servers != nil {
		dns = e.Servers()
	}
	for _, d := range dns {
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

func (e *ClientEgress) active() bool { return e != nil && (e.Active == nil || e.Active()) }
