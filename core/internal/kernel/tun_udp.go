package kernel

import (
	"context"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/procattr"
	"github.com/shui1iao/Kat/internal/tunstack"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// The source lives in tunstack. A key NEVER contains the remote endpoint.
// Distinct rule/policy and physical safety epochs cannot share a PacketConn.
type tunNATKey struct {
	name    string
	rule    int
	epoch   uint64
	binding string
}
type tunUDPState struct {
	a        *udpAssociation
	c        net.Conn
	t        tunstack.Flow
	owner    procattr.Identity
	dnsBusy  atomic.Bool
	mu       sync.Mutex
	sessions map[tunNATKey]*tunNATSession
	pcWG     sync.WaitGroup
}
type tunNATSession struct {
	u           *tunUDPState
	key         tunNATKey
	pc          outbound.PacketConn
	chain       []string
	f           *flow
	defaultRt   *udpRoute
	assocID     string
	policyStr   string
	lastDecided Address
	metaDone    bool
	metaShared  bool
	metaPeer    netip.AddrPort
	metaUnvis   bool
	last        atomic.Int64
	closed    atomic.Bool
	closeOnce sync.Once
	sendMu    sync.Mutex // terminal record waits for the one sender's accounting
	endCode   string     // routeMu protects the first failure; later success cannot erase it
	shared    bool
	firstPeer netip.AddrPort
	replyPeer netip.AddrPort
	unvisited bool
	routeMu   sync.Mutex
	routes    map[netip.AddrPort]*udpRoute
}

func (s *Server) tunUDP(ctx context.Context, t tunstack.Flow, c net.Conn) (result error) {
	ctx, cancel := context.WithCancel(ctx)
	a := &udpAssociation{server: s, ctx: ctx, cancel: cancel, source: t.Source.Addr(), queue: make(chan packet, s.cfg.Limits.UDPQueue)}
	u := &tunUDPState{a: a, c: c, t: t, sessions: map[tunNATKey]*tunNATSession{}}
	a.tunSend = u.send
	maxActivity(a)
	// Only this sender can create sessions. Cancellation interrupts ingress;
	// after sendLoop exits this owner closes and joins every external reader.
	ioStopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { defer close(ioStopped); _ = c.Close() })
	defer func() {
		cancel()
		_ = c.Close()
		if !stop() {
			<-ioStopped
		}
		u.closePC()
		u.pcWG.Wait() // no Add remains possible: the sole sender has returned
		for {
			select {
			case p := <-a.queue:
				a.queuedBytes.Add(-int64(len(p.payload)))
			default:
				return
			}
		}
	}()
	reader := make(chan error, 1)
	go func() {
		idle := s.cfg.Limits.UDPIdle.value()
		b := make([]byte, 65535)
		for {
			deadline := time.Unix(0, a.activity.Load()).Add(idle)
			if u.dnsBusy.Load() || len(a.queue) > 0 {
				deadline = time.Now().Add(idle)
			}
			_ = c.SetReadDeadline(deadline)
			var n int
			var dst netip.AddrPort
			var e error
			if dc, ok := c.(tunstack.DatagramConn); ok {
				n, dst, e = dc.ReadDatagram(b)
			} else {
				n, e = c.Read(b)
				dst = t.Destination
			}
			if e != nil {
				if timeoutError(e) && (time.Since(time.Unix(0, a.activity.Load())) < idle || u.dnsBusy.Load() || len(a.queue) > 0) && ctx.Err() == nil {
					continue
				}
				reader <- e
				cancel()
				return
			}
			if n > u.maxPayload() || !dst.IsValid() {
				s.counters.Dropped.Add(1)
				continue
			}
			maxActivity(a)
			a.enqueue(packet{Address{dst.Addr().String(), dst.Port()}, append([]byte(nil), b[:n]...)})
		}
	}()
	a.sendLoop()
	result = <-reader
	if errors.Is(result, net.ErrClosed) || errors.Is(result, context.Canceled) || errors.Is(result, io.EOF) || timeoutError(result) {
		return nil
	}
	return result
}
func (u *tunUDPState) closePC() {
	u.mu.Lock()
	list := make([]*tunNATSession, 0, len(u.sessions))
	for _, v := range u.sessions {
		list = append(list, v)
	}
	u.mu.Unlock()
	for _, v := range list {
		v.close()
	}
}
func (v *tunNATSession) close() {
	v.closeOnce.Do(func() { v.closed.Store(true); _ = v.pc.Close() })
}
func (u *tunUDPState) maxPayload() int {
	if u.t.Source.Addr().Is6() {
		return 65527
	}
	return 65507
}

// Identity is a source boundary, not merely display metadata. Losing evidence
// retires the old known owner's mappings; unknown traffic still follows the
// existing skip-unavailable-process-rule semantics, in a fresh association.
func (u *tunUDPState) identity(id procattr.Identity) {
	old := u.owner
	if old.Status != "" && (old.Status != id.Status || old.PID != id.PID || old.Stamp != id.Stamp) {
		revoked := id
		if id.Status == "known" {
			revoked = procattr.Identity{Status: "changed"}
		}
		u.mu.Lock()
		for _, v := range u.sessions {
			v.f.tunIdentity(revoked)
		}
		u.mu.Unlock()
		u.closePC()
		u.pcWG.Wait() // called by the only session creator, never its readers
	}
	u.owner = id
}
func (v *tunNATSession) failure(target Address, code string, e error) {
	v.routeMu.Lock()
	if v.endCode == "" {
		v.endCode = code
	}
	v.routeMu.Unlock()
	if target.Port == 0 {
		v.f.setError(e)
		_, rule := v.u.a.server.ruleCounter(v.key.rule)
		v.f.emitConnection(v.f.info(time.Now()).Target, rule, v.chain, "error", code)
	} else {
		v.f.udpFailure(target, v.key.rule, v.chain, code, e)
	}
}
func (u *tunUDPState) packetContext(ctx context.Context, p packet) context.Context {
	t := u.t
	if ip, e := netip.ParseAddr(p.target.Host); e == nil {
		t.Destination = netip.AddrPortFrom(ip.Unmap(), p.target.Port)
	}
	ctx = context.WithValue(ctx, tunFlowKey{}, t)
	return context.WithValue(withOriginalTarget(ctx, p.target), packetProcessKey{}, &packetProcess{})
}
func (u *tunUDPState) failure(ctx context.Context, p packet, rule int, chain []string, code string, e error) {
	f, _ := u.a.server.newFlow(ctx, "udp", p.target)
	f.tunProcess(ctx, p.target)
	f.udpFailure(p.target, rule, chain, code, e)
	f.end(code)
	u.a.server.counters.Dropped.Add(1)
}
func (u *tunUDPState) output(b []byte, peer netip.AddrPort) error {
	if u.a.ctx.Err() != nil {
		return u.a.ctx.Err()
	}
	if u.a.server.cfg.IPv6Disabled() && peer.Addr().Is6() {
		return errors.New("ipv6_disabled")
	}
	if dc, ok := u.c.(tunstack.DatagramConn); ok {
		n, e := dc.WriteFrom(b, peer)
		if e == nil && n != len(b) {
			e = io.ErrShortWrite
		}
		return e
	}
	if peer != u.t.Destination {
		return errors.New("TUN_UDP_INJECTION_UNSUPPORTED")
	}
	n, e := u.c.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	return e
}
func (u *tunUDPState) send(ctx context.Context, p packet, idle time.Duration) {
	a, s := u.a, u.a.server
	u.dnsBusy.Store(true)
	maxActivity(a)
	if idle > 0 {
		_ = u.c.SetReadDeadline(time.Now().Add(idle))
	}
	defer func() {
		maxActivity(a)
		if idle > 0 {
			_ = u.c.SetReadDeadline(time.Unix(0, a.activity.Load()).Add(idle))
		}
		u.dnsBusy.Store(false)
	}()
	ctx = u.packetContext(ctx, p)
	if p.target.Port == 53 {
		// One real query is one DNS activity/record. No empty association row.
		f, fctx := s.newFlow(ctx, "udp", Address{})
		tunDNSMeta(f, p.target)
		e := s.tunDNSQuery(fctx, f, p.target, p.payload, false, func(b []byte) error {
			return u.output(b, netip.AddrPortFrom(netip.MustParseAddr(p.target.Host), p.target.Port))
		})
		if e != nil {
			f.end("dns_query_failed")
		} else {
			f.end("ok")
		}
		return
	}
	u.identity(processIdentity(ctx, "udp", p.target)())
	candidates, name, host, rule, e := s.routeUDP(ctx, p.target, a.source)
	if e != nil {
		u.failure(ctx, p, rule, nil, dialResult(e), e)
		return
	}
	if name == "" {
		name = "direct"
	}
	epoch, binding, e := u.binding(name)
	if e != nil {
		u.failure(ctx, p, rule, []string{name}, "udp_setup_failed", e)
		return
	}
	dst := Address{host, p.target.Port}
	if name == "direct" && len(candidates) > 0 {
		dst = Address{candidates[0].Addr().String(), candidates[0].Port()}
	}
	if dst.Host == "" || name != "direct" && sniffOf(ctx).target(p.target) != p.target {
		dst = p.target
	}
	key := tunNATKey{name, rule, epoch, binding}
	v, e := u.session(ctx, key, p.target)
	if e != nil {
		code := "udp_setup_failed"
		if errors.Is(e, outbound.ErrUDPUnsupported) {
			code = "udp_unsupported"
		}
		u.failure(ctx, p, rule, []string{name}, code, e)
		return
	}
	v.sendMu.Lock()
	defer v.sendMu.Unlock()
	if v.closed.Load() {
		u.failure(ctx, p, rule, v.chain, "udp_send_failed", net.ErrClosed)
		return
	}
	v.f.tunProcess(ctx, p.target)
	v.f.sniffHost(ctx)
	rt := v.defaultRt
	if rt == nil {
		rt = v.f.udpRouteFor(rule, v.chain)
		v.defaultRt = rt
	}
	firstWrite := v.f.up.Load() == 0
	// Install reply accounting BEFORE write: even an immediate peer cannot race it.
	if ip, pe := netip.ParseAddr(dst.Host); pe == nil {
		peer := netip.AddrPortFrom(ip.Unmap(), dst.Port)
		v.routeMu.Lock()
		if v.routes[peer] != rt {
			if len(v.routes) >= 4096 {
				clear(v.routes)
			}
			v.routes[peer] = rt
		}
		if !v.firstPeer.IsValid() {
			v.firstPeer = peer
		} else if peer != v.firstPeer {
			v.shared = true
		}
		v.routeMu.Unlock()
	}
	if e = u.bindingCurrent(key); e != nil {
		v.failure(p.target, "udp_setup_failed", e)
		v.close()
		return
	}
	_ = v.pc.SetWriteDeadline(time.Now().Add(s.cfg.Limits.DialTimeout.value()))
	n, e := v.pc.WriteTo(p.payload, outbound.Addr{Host: dst.Host, Port: dst.Port})
	if e == nil && n != len(p.payload) {
		e = io.ErrShortWrite
	}
	if e != nil {
		v.failure(p.target, "udp_send_failed", e)
		s.counters.Dropped.Add(1)
		v.close()
		return
	}
	v.f.udpUp(rt, n)
	// ListenPacket can create its physical socket lazily on the first write.
	// A reconcile during creation may never leave a new socket under an old key.
	if firstWrite {
		if e = u.bindingCurrent(key); e != nil {
			v.failure(p.target, "udp_setup_failed", e)
			v.close()
			return
		}
	}
	v.touch()
	maxActivity(a)
	if v.lastDecided != p.target {
		v.lastDecided = p.target
		v.f.mu.Lock()
		v.f.details.DestIP = p.target.Host
		v.f.mu.Unlock()
		v.f.udpDecided(p.target, rule, v.chain)
	}
	if firstWrite {
		v.metadataForce(true)
	} else {
		v.metadata()
	}
}
func (u *tunUDPState) binding(name string) (uint64, string, error) {
	e := u.a.server.cfg.clientEgress
	if e != nil {
		if name != "direct" && e.UDPAssociationBinding != nil {
			return e.UDPAssociationBinding()
		}
		if e.UDPBinding != nil {
			return e.UDPBinding(u.t.Source.Addr().Is6())
		}
	}
	return u.t.Epoch, "standalone", nil
}
func (u *tunUDPState) bindingCurrent(key tunNATKey) error {
	epoch, binding, err := u.binding(key.name)
	if err != nil {
		return err
	}
	if epoch != key.epoch || binding != key.binding {
		return errors.New("physical UDP binding superseded")
	}
	return nil
}
func (u *tunUDPState) session(ctx context.Context, key tunNATKey, target Address) (*tunNATSession, error) {
	u.mu.Lock()
	old := u.sessions[key]
	u.mu.Unlock()
	if old != nil && !old.closed.Load() {
		return old, nil
	}
	s := u.a.server
	if !s.udpSlots.try() {
		return nil, errors.New("TUN_UDP_ASSOCIATION_LIMIT")
	}
	release := true
	defer func() {
		if release {
			s.udpSlots.release()
		}
	}()
	if s.rt == nil || s.rt.nodes[key.name] == nil {
		return nil, errUnknownOutbound
	}
	ob := s.rt.nodes[key.name]
	if !ob.UDP() {
		return nil, outbound.ErrUDPUnsupported
	}
	h := &hops{}
	qctx, cancel := context.WithTimeout(withHops(outbound.WithEndpointIndependent(ctx, true), h), s.cfg.Limits.DialTimeout.value()+s.cfg.Limits.HandshakeTimeout.value())
	pc, e := ob.ListenPacket(qctx)
	cancel()
	if e != nil {
		return nil, e
	}
	f, fctx := s.newFlow(ctx, "udp", target)
	assocID := ""
	if f != nil {
		assocID = fmt.Sprintf("%d:%d", s.started.UnixNano(), f.id)
	}
	v := &tunNATSession{u: u, key: key, pc: pc, chain: h.chain(key.name), f: f, assocID: assocID, policyStr: fmt.Sprintf("rule:%d", key.rule), routes: map[netip.AddrPort]*udpRoute{}}
	v.touch()
	v.metadataForce(true)
	u.mu.Lock()
	if u.a.ctx.Err() != nil {
		u.mu.Unlock()
		_ = pc.Close()
		f.end("idle")
		return nil, u.a.ctx.Err()
	}
	u.sessions[key] = v
	u.pcWG.Add(1)
	u.mu.Unlock()
	release = false
	go func() {
		defer u.pcWG.Done()
		defer s.udpSlots.release()
		stop := context.AfterFunc(fctx, v.close)
		defer stop()
		defer v.close()
		defer func() {
			u.mu.Lock()
			if u.sessions[key] == v {
				delete(u.sessions, key)
			}
			u.mu.Unlock()
		}()
		reason := v.read()
		v.close() // fence reuse BEFORE terminal accounting, including fatal reads
		v.sendMu.Lock()
		if v.f.up.Load() == 0 && v.f.down.Load() == 0 {
			reason = "idle"
		}
		v.routeMu.Lock()
		if v.endCode != "" {
			reason = v.endCode
		}
		v.routeMu.Unlock()
		f.end(reason)
		v.sendMu.Unlock()
	}()
	return v, nil
}
func (v *tunNATSession) touch() {
	now := time.Now().UnixNano()
	for old := v.last.Load(); now > old; old = v.last.Load() {
		if v.last.CompareAndSwap(old, now) {
			break
		}
	}
}
func (v *tunNATSession) metadata() { v.metadataForce(false) }

func (v *tunNATSession) metadataForce(force bool) {
	if v.f == nil {
		return
	}
	v.routeMu.Lock()
	shared, peer, unvisited := v.shared, v.replyPeer, v.unvisited
	changed := force || !v.metaDone || v.metaShared != shared || v.metaPeer != peer || v.metaUnvis != unvisited
	if changed {
		v.metaDone, v.metaShared, v.metaPeer, v.metaUnvis = true, shared, peer, unvisited
	}
	v.routeMu.Unlock()
	if !changed {
		return
	}
	var locals []string
	if m, ok := v.pc.(interface{ LocalEndpoints() []string }); ok {
		locals = m.LocalEndpoints()
	}
	id := v.assocID
	if id == "" {
		id = fmt.Sprintf("%d:%d", v.f.s.started.UnixNano(), v.f.id)
	}
	policy := v.policyStr
	if policy == "" {
		policy = fmt.Sprintf("rule:%d", v.key.rule)
	}
	info := &UDPAssociationInfo{ID: id, Policy: policy, Outbound: v.key.name, Epoch: v.key.epoch, Binding: v.key.binding, LocalEndpoints: locals, Shared: shared, UnmatchedPeer: unvisited}
	if peer.IsValid() {
		info.ReplyPeer = peer.String()
	}
	v.f.mu.Lock()
	v.f.details.UDPAssociation = info
	if shared {
		// Payload totals belong to this mapping, NOT the last visited target.
		v.f.target = "udp-association"
		v.f.details.DestIP, v.f.details.DestHost = "", ""
	}
	v.f.mu.Unlock()
}
func (v *tunNATSession) read() string {
	a := v.u.a
	s := a.server
	idle := s.cfg.Limits.UDPIdle.value()
	b := make([]byte, 65535)
	var armedDeadline time.Time
	for {
		targetDeadline := time.Unix(0, v.last.Load()).Add(idle)
		if armedDeadline.IsZero() || targetDeadline.Sub(armedDeadline) > idle/4 || time.Until(armedDeadline) < idle/4 {
			armedDeadline = targetDeadline
			_ = v.pc.SetReadDeadline(armedDeadline)
		}
		n, src, e := v.pc.ReadFrom(b)
		if e != nil {
			if timeoutError(e) {
				// Expiry cannot race an in-flight send or its activity refresh.
				v.sendMu.Lock()
				active := time.Since(time.Unix(0, v.last.Load())) < idle && !v.closed.Load() && a.ctx.Err() == nil
				if !active {
					v.close()
				}
				v.sendMu.Unlock()
				if active {
					continue
				}
				return "idle"
			}
			if !v.closed.Load() && a.ctx.Err() == nil {
				v.failure(Address{}, "udp_receive_failed", e)
				return "udp_receive_failed"
			}
			return "ok"
		}
		ip, e := netip.ParseAddr(src.Host)
		if e != nil || src.Port == 0 || n > v.u.maxPayload() || ip.Unmap().Is4() != v.u.t.Source.Addr().Is4() {
			s.counters.Dropped.Add(1)
			continue
		}
		peer := netip.AddrPortFrom(ip.Unmap(), src.Port)
		// EIF: there is intentionally NO previously-sent peer allowlist here.
		if v.closed.Load() {
			return "ok"
		}
		if e = v.u.output(b[:n], peer); e != nil {
			if a.ctx.Err() == nil {
				v.failure(Address{src.Host, src.Port}, "udp_response_failed", e)
			}
			s.counters.Dropped.Add(1)
			continue
		}
		v.routeMu.Lock()
		rt := v.routes[peer]
		unvisited := rt == nil
		if unvisited {
			// The policy meter belongs to this mapping, but no visited peer owns it.
			rt = v.f.udpRouteFor(v.key.rule, v.chain)
			v.shared = true
		}
		v.replyPeer, v.unvisited = peer, unvisited
		v.routeMu.Unlock()
		if m, ok := v.pc.(interface{ ReadMember() string }); ok {
			if actual := m.ReadMember(); actual != "" {
				r := &udpRoute{}
				if rt != nil && rt.rule != nil {
					r.rule = rt.rule
					r.meters = append(r.meters, rt.rule)
				}
				r.meters = append(r.meters, sesMemberCounters(s, v.chain, actual)...)
				rt = r
			}
		}
		v.f.udpDown(rt, n)
		v.metadata()
		if unvisited {
			_, rule := s.ruleCounter(v.key.rule)
			v.f.emitConnection(peer.String(), rule, v.chain, "ok", "udp_eif_reply")
		}
		v.touch()
		maxActivity(a)
	}
}
