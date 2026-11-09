package clientegress

// Switch is a Windows desktop instance's stable dispatch boundary. All current
// and retained kernel generations borrow it; swapping a lease never rebuilds
// groups/listeners. Socket ownership is exact Go objects, never numeric FDs.
import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
)

type Switch struct {
	mu           sync.Mutex
	current      *Policy
	epoch        uint64
	sockets      map[net.Conn]bool
	packets      map[*net.UDPConn]bool
	owners       map[net.Conn]SocketOwner
	packetOwners map[*net.UDPConn]SocketOwner
	snapshot     *EgressSnapshot
	generation   uint64
	frozen       bool
	ipv6Set      bool
	ipv6Enabled  bool
}

// PolicySnapshot borrows the current policy together with its physical
// generation and admission fence in one locked read. It does not change policy
// ownership or grant an admission lease. A frozen snapshot (including nil
// policy), or a non-nil policy with !Ready(), must never fall back to direct.
// A nil policy is not a direct-mode authorization either: controlled resource
// callers must reject nil; only Host's explicit ordinary mode may use direct.
// Callers must treat the returned policy as read-only and account for later
// cancellation/fencing; generation alone is not a lifecycle token.
func (s *Switch) PolicySnapshot() (*Policy, uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current, s.generation, s.frozen
}

func (s *Switch) policy() *Policy { s.mu.Lock(); defer s.mu.Unlock(); return s.current }
func (s *Switch) Enabled() bool   { return s.policy() != nil }
func (s *Switch) Replace(p *Policy) {
	s.mu.Lock()
	old := s.current
	s.current = p
	s.epoch++
	s.snapshot = nil
	s.owners = nil
	s.packetOwners = nil
	s.frozen = false
	sockets := s.sockets
	packets := s.packets
	s.sockets = map[net.Conn]bool{}
	s.packets = map[*net.UDPConn]bool{}
	s.mu.Unlock()
	if old != nil {
		old.Fail()
	}
	for c := range sockets {
		c.Close()
	}
	for c := range packets {
		c.Close()
	}
}
func (s *Switch) Pause() {
	p := s.policy()
	if p != nil {
		p.Fail()
	}
	s.mu.Lock()
	s.epoch++
	s.snapshot = nil
	s.owners = nil
	s.packetOwners = nil
	s.frozen = true
	sockets := s.sockets
	packets := s.packets
	s.sockets = map[net.Conn]bool{}
	s.packets = map[*net.UDPConn]bool{}
	s.mu.Unlock()
	for c := range sockets {
		c.Close()
	}
	for c := range packets {
		c.Close()
	}
}
func (s *Switch) Fail() {
	if p := s.policy(); p != nil {
		p.Fail()
	}
}
func (s *Switch) Control(ctx context.Context, n, a string, c syscall.RawConn) error {
	p := s.policy()
	if p == nil {
		return nil
	}
	return p.Control(ctx, n, a, c)
}

type switchConn struct {
	net.Conn
	s    *Switch
	once sync.Once
}

func (c *switchConn) Close() error {
	e := c.Conn.Close()
	c.once.Do(func() { c.s.mu.Lock(); delete(c.s.sockets, c); delete(c.s.owners, c); c.s.mu.Unlock() })
	return e
}

// Preserve the transport's optional half-close capability without changing
// the original switchConn ownership entry or full-close lifecycle.
type switchConnCW struct{ *switchConn }

func (c *switchConnCW) CloseWrite() error {
	return c.Conn.(interface{ CloseWrite() error }).CloseWrite()
}

func (s *Switch) DialContext(ctx context.Context, n, a string) (net.Conn, error) {
	s.mu.Lock()
	p, epoch, generation, snapshot, frozen := s.current, s.epoch, s.generation, s.snapshot, s.frozen
	s.mu.Unlock()
	if frozen {
		return nil, errors.New("physical egress fenced")
	}
	d := net.Dialer{}
	if p != nil {
		d.ControlContext = p.Control
	}
	var ownership SocketOwner
	if snapshot != nil {
		host, _, e := net.SplitHostPort(a)
		if e != nil {
			return nil, e
		}
		dest, e := netip.ParseAddr(host)
		if e != nil {
			return nil, errors.New("egress literal destination required")
		}
		if !dest.IsLoopback() {
			owner, e := snapshot.selected(dest.Is6())
			if e != nil {
				return nil, e
			}
			source, e := platformSelectSource(owner, dest, netip.Addr{})
			if e != nil {
				return nil, e
			}
			ownership = SocketOwner{Epoch: snapshot.Epoch, LUID: owner.LUID, IfIndex: owner.IfIndex, Family: owner.Family, Source: source.WithZone(""), Scope: sourceScope(source, owner.IfIndex)}
			if strings.HasPrefix(n, "udp") {
				d.LocalAddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(source, 0))
			} else {
				d.LocalAddr = net.TCPAddrFromAddrPort(netip.AddrPortFrom(source, 0))
			}
		}
	}
	c, e := d.DialContext(ctx, n, a)
	if e != nil {
		return nil, e
	}
	if ownership.LUID != 0 {
		if e = confirmLocal(ownership, c.LocalAddr()); e == nil {
			e = platformConfirmSource(OwnerState{LUID: ownership.LUID, IfIndex: ownership.IfIndex, Family: ownership.Family}, ownership.Source)
		}
		if e != nil {
			c.Close()
			return nil, e
		}
	}
	s.mu.Lock()
	stale := s.frozen
	if snapshot == nil {
		stale = stale || s.epoch != epoch || s.current != p || (p != nil && !p.Ready())
	} else {
		stale = stale || s.snapshot == nil || s.snapshot.Epoch != snapshot.Epoch || ownership.LUID != 0 && !s.snapshot.valid(ownership) || s.generation < generation
	}
	if stale {
		s.mu.Unlock()
		c.Close()
		return nil, errors.New("egress revision superseded")
	}
	w := &switchConn{Conn: c, s: s}
	if s.sockets == nil {
		s.sockets = map[net.Conn]bool{}
	}
	s.sockets[w] = true
	if ownership.LUID != 0 {
		if s.owners == nil {
			s.owners = map[net.Conn]SocketOwner{}
		}
		s.owners[w] = ownership
	}
	s.mu.Unlock()
	if _, ok := c.(interface{ CloseWrite() error }); ok {
		return &switchConnCW{w}, nil
	}
	return w, nil
}
func (s *Switch) PacketControl(n string, c *net.UDPConn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.frozen {
		return errors.New("physical egress fenced")
	}
	if s.current != nil {
		if e := s.current.PacketControl(n, c); e != nil {
			return e
		}
	}
	if s.snapshot != nil {
		owner, e := s.snapshot.selected(strings.HasSuffix(n, "6"))
		if e != nil {
			return e
		}
		local, e := addrIP(c.LocalAddr())
		if e != nil || local.IsUnspecified() {
			return errors.New("physical UDP source must be resolved before ListenUDP")
		}
		proof := SocketOwner{Epoch: s.snapshot.Epoch, LUID: owner.LUID, IfIndex: owner.IfIndex, Family: owner.Family, Source: local.WithZone(""), Scope: sourceScope(local, owner.IfIndex)}
		if !s.snapshot.valid(proof) {
			return errors.New("UDP actual source no longer owned")
		}
		if e = platformConfirmSource(owner, proof.Source); e != nil {
			return e
		}
		if s.packetOwners == nil {
			s.packetOwners = map[*net.UDPConn]SocketOwner{}
		}
		s.packetOwners[c] = proof
	}
	if s.packets == nil {
		s.packets = map[*net.UDPConn]bool{}
	}
	s.packets[c] = true
	return nil
}
func (s *Switch) PacketRelease(c *net.UDPConn) {
	s.mu.Lock()
	delete(s.packets, c)
	delete(s.packetOwners, c)
	s.mu.Unlock()
}
func (s *Switch) Bootstrap(ctx context.Context, n, h string) ([]netip.Addr, error) {
	p := s.policy()
	if p == nil {
		return net.DefaultResolver.LookupNetIP(ctx, n, h)
	}
	return p.Bootstrap(ctx, n, h)
}
func (s *Switch) SystemQuery(ctx context.Context, b []byte) ([]byte, error) {
	p := s.policy()
	if p == nil {
		return nil, errors.New("no controlled DNS lease")
	}
	return p.SystemQuery(ctx, b)
}
func (s *Switch) DNSContext(ctx context.Context) (context.Context, func(), uint64) {
	s.mu.Lock()
	p, epoch := s.current, s.epoch
	s.mu.Unlock()
	if p == nil {
		return ctx, func() {}, epoch << 32
	}
	child, cancel, rev := p.DNSContext(ctx)
	return child, cancel, epoch<<32 | rev
}
func (s *Switch) Servers() []netip.Addr {
	p := s.policy()
	if p == nil {
		return nil
	}
	o, _ := p.DNSSnapshot()
	out := []netip.Addr{}
	for _, d := range o.DNS {
		if d.Scope == 0 {
			ip, _ := netip.ParseAddr(d.Address)
			out = append(out, ip)
		}
	}
	return out
}

// UDPBinding is a read-only NAT admission snapshot. Existing socket ownership
// is still revalidated by PacketSource/PacketControl and retired by reconcile.
func (s *Switch) UDPBinding(ipv6 bool) (uint64, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.frozen || s.current == nil || !s.current.Ready() || s.snapshot == nil {
		return 0, "", errors.New("physical UDP binding unavailable")
	}
	o, e := s.snapshot.selected(ipv6)
	if e != nil {
		return 0, "", e
	}
	return s.snapshot.Epoch, fmt.Sprintf("%d/%d/%d", o.LUID, o.IfIndex, o.Family), nil
}

// UDPAssociationBinding snapshots the physical domain for a destination-
// independent proxy association. Its transport family need not equal the
// inner application's family (e.g. IPv6 payload over an IPv4 SS server).
// Each actual socket is still independently bound/proved by the stable switch.
func (s *Switch) UDPAssociationBinding() (uint64, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.frozen || s.current == nil || !s.current.Ready() || s.snapshot == nil {
		return 0, "", errors.New("physical UDP binding unavailable")
	}
	var parts []string
	for _, ipv6 := range []bool{false, true} {
		o, err := s.snapshot.selected(ipv6)
		if err == nil {
			parts = append(parts, fmt.Sprintf("%d/%d/%d", o.LUID, o.IfIndex, o.Family))
		}
	}
	if len(parts) == 0 {
		return 0, "", errors.New("physical UDP binding unavailable")
	}
	return s.snapshot.Epoch, strings.Join(parts, ";"), nil
}
