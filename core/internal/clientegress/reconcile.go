package clientegress

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
)

type SocketOwner struct {
	Epoch   uint64
	LUID    uint64
	IfIndex uint32
	Family  uint16
	Source  netip.Addr
	Scope   uint32
}
type SourceState struct {
	Address netip.Addr
	Scope   uint32
	Usable  bool
}
type OwnerState struct {
	LUID     uint64
	IfIndex  uint32
	Family   uint16
	Up, Safe bool
	Sources  []SourceState
}
type EgressSnapshot struct {
	Generation, Epoch uint64
	Options           Options
	Owners            []OwnerState
}

func (e EgressSnapshot) clone() EgressSnapshot {
	e.Options = e.Options.Clone()
	e.Owners = append([]OwnerState(nil), e.Owners...)
	for i := range e.Owners {
		e.Owners[i].Sources = append([]SourceState(nil), e.Owners[i].Sources...)
	}
	return e
}
func (e *EgressSnapshot) selected(ipv6 bool) (OwnerState, error) {
	luid, index, family := e.Options.LUID4, e.Options.IPv4, uint16(2)
	if ipv6 {
		luid, index, family = e.Options.LUID6, e.Options.IPv6, 23
	}
	if luid == nil || index == nil {
		return OwnerState{}, errors.New("physical family unavailable")
	}
	for _, o := range e.Owners {
		if o.LUID == *luid && o.IfIndex == *index && o.Family == family {
			if !o.Up || !o.Safe {
				return OwnerState{}, errors.New("EGRESS_BIND_UNSAFE")
			}
			return o, nil
		}
	}
	return OwnerState{}, errors.New("physical owner unavailable")
}
func (e *EgressSnapshot) valid(p SocketOwner) bool {
	for _, o := range e.Owners {
		if o.LUID == p.LUID && o.IfIndex == p.IfIndex && o.Family == p.Family && o.Up && o.Safe {
			for _, s := range o.Sources {
				if s.Usable && s.Address.WithZone("") == p.Source && s.Scope == p.Scope {
					return true
				}
			}
		}
	}
	return false
}
func sourceScope(ip netip.Addr, index uint32) uint32 {
	if ip.Is6() && ip.IsLinkLocalUnicast() {
		return index
	}
	return 0
}
func addrIP(a net.Addr) (netip.Addr, error) {
	switch a := a.(type) {
	case *net.TCPAddr:
		return a.AddrPort().Addr(), nil
	case *net.UDPAddr:
		return a.AddrPort().Addr(), nil
	}
	return netip.Addr{}, errors.New("socket local tuple unavailable")
}
func confirmLocal(o SocketOwner, a net.Addr) error {
	ip, e := addrIP(a)
	if e != nil {
		return e
	}
	if ip.IsUnspecified() || ip.WithZone("") != o.Source || sourceScope(ip, o.IfIndex) != o.Scope {
		return errors.New("socket actual source mismatch")
	}
	return nil
}

// PacketSource runs BEFORE net.ListenUDP. It returns a real local source and
// never performs bind itself. PacketControl later proves that exact LocalAddr.
func (s *Switch) PacketSource(network string, configured netip.Addr) (netip.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.frozen {
		return netip.Addr{}, errors.New("physical egress fenced")
	}
	if s.snapshot == nil {
		return configured, nil
	}
	o, e := s.snapshot.selected(network == "udp6")
	if e != nil {
		return netip.Addr{}, e
	}
	return platformSelectSource(o, netip.Addr{}, configured)
}

// FreezeNew blocks new sockets without destroying any known-valid old socket.
func (s *Switch) FreezeNew() { s.mu.Lock(); s.frozen = true; s.mu.Unlock() }

// Reconcile never calls Replace/Pause. Actual proof controls retirement, not
// whole-address digest or DNS order. Old-owner sockets survive a safe owner
// switch while new dials use the new epoch; no TCP migration is promised.
func (s *Switch) Reconcile(next EgressSnapshot) error { return s.reconcile(next, NewRevision) }
func (s *Switch) reconcile(next EgressSnapshot, makePolicy func(Options, uint64) (*Policy, error)) error {
	next = next.clone()
	if next.Generation == 0 || next.Epoch == 0 {
		return errors.New("physical generation required")
	}
	s.mu.Lock()
	if next.Generation <= s.generation {
		s.mu.Unlock()
		return errors.New("physical stale generation")
	}
	s.mu.Unlock()
	p, e := makePolicy(next.Options, next.Generation)
	if e != nil {
		return e
	}
	return s.installSnapshot(next, p)
}
func (s *Switch) installSnapshot(next EgressSnapshot, p *Policy) error {
	s.mu.Lock()
	if next.Generation <= s.generation {
		s.mu.Unlock()
		if p != nil {
			p.Fail()
		}
		return errors.New("physical stale generation")
	}
	old := s.current
	if p != nil {
		if s.ipv6Set {
			p.SetIPv6(s.ipv6Enabled)
		} else if old != nil {
			p.SetIPv6(!old.disableIPv6.Load())
		}
	}
	s.current = p
	s.generation = next.Generation
	s.epoch = next.Epoch
	s.snapshot = &next
	s.frozen = false
	var sockets []net.Conn
	var packets []*net.UDPConn
	for c, o := range s.owners {
		if !next.valid(o) {
			sockets = append(sockets, c)
			delete(s.owners, c)
			delete(s.sockets, c)
		}
	}
	for c, o := range s.packetOwners {
		if !next.valid(o) {
			packets = append(packets, c)
			delete(s.packetOwners, c)
			delete(s.packets, c)
		}
	}
	s.mu.Unlock()
	if old != nil && old != p {
		old.Fail()
	}
	for _, c := range sockets {
		c.Close()
	}
	for _, c := range packets {
		c.Close()
	}
	return nil
}

// RetireObserved accepts only a complete successful owner/source reread. It can
// retire unsafe/down/deleted-source proofs while retaining the current new-flow
// policy until a stable validated candidate is committed. Query failure callers
// must FreezeNew instead of passing an invented empty observation.
func (s *Switch) RetireObserved(owners []OwnerState) {
	next := EgressSnapshot{Owners: owners}
	s.mu.Lock()
	var sockets []net.Conn
	var packets []*net.UDPConn
	for c, o := range s.owners {
		if !next.valid(o) {
			sockets = append(sockets, c)
			delete(s.owners, c)
			delete(s.sockets, c)
		}
	}
	for c, o := range s.packetOwners {
		if !next.valid(o) {
			packets = append(packets, c)
			delete(s.packetOwners, c)
			delete(s.packets, c)
		}
	}
	s.mu.Unlock()
	for _, c := range sockets {
		c.Close()
	}
	for _, c := range packets {
		c.Close()
	}
}
func (s *Switch) OwnedSockets() []SocketOwner {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []SocketOwner
	for _, o := range s.owners {
		out = append(out, o)
	}
	for _, o := range s.packetOwners {
		out = append(out, o)
	}
	return out
}
func chooseSnapshotSource(o OwnerState, dest, configured netip.Addr) (netip.Addr, error) {
	if !o.Up || !o.Safe {
		return netip.Addr{}, errors.New("EGRESS_BIND_UNSAFE")
	}
	wanted := configured.IsValid() && !configured.IsUnspecified()
	for _, s := range o.Sources {
		if !s.Usable || s.Address.IsUnspecified() || s.Address.IsLoopback() || s.Address.Is4() != (o.Family == 2) {
			continue
		}
		if wanted && configured.WithZone("") != s.Address.WithZone("") {
			continue
		}
		if !wanted && s.Address.IsLinkLocalUnicast() && (!dest.IsValid() || !dest.IsLinkLocalUnicast()) {
			continue
		}
		ip := s.Address
		if s.Scope != 0 {
			ip = ip.WithZone(strconv.FormatUint(uint64(s.Scope), 10))
		}
		return ip, nil
	}
	return netip.Addr{}, errors.New("physical source unavailable")
}

// SetIPv6 preserves Host business-family intent across physical/DNS policy
// replacement. It does not remove the registered physical IPv6 DNS exception.
func (s *Switch) SetIPv6(enabled bool) {
	s.mu.Lock()
	s.ipv6Set = true
	s.ipv6Enabled = enabled
	if s.current != nil {
		s.current.SetIPv6(enabled)
	}
	s.mu.Unlock()
}

// ReleasePhysical is called only after owned routes/settings and DATA have
// closed successfully. Ordinary proxy mode resumes unbound new dialing; it
// does not kill unrelated established proxy sockets or fake successful cleanup.
func (s *Switch) ReleasePhysical() {
	s.mu.Lock()
	old := s.current
	s.current = nil
	s.snapshot = nil
	s.epoch++
	s.generation = 0
	s.frozen = false
	s.mu.Unlock()
	if old != nil {
		old.Fail()
	}
}
