package kernel

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/udpmmsg"
	"github.com/shui1iao/Kat/internal/stats"
)

// proxySession is one association's datagram channel through one outbound or
// group. It is created on the first datagram routed there, read by exactly one
// goroutine, recycled after udp_idle without traffic in either direction and
// closed when the association ends.
type proxySession struct {
	name          string
	pc            outbound.PacketConn
	last          atomic.Int64 // unix nanos of the last datagram sent or received
	lastWDeadline atomic.Int64 // unix nanos of the last SetWriteDeadline
	chain         []string     // outbound chain chosen at creation (name, group members)
	members       sync.Map     // member name -> most recent route for that member
	route         atomic.Pointer[udpRoute]
}

func udpUnavailable(e error) bool {
	return errors.Is(e, outbound.ErrUDPUnsupported) || errors.Is(e, outbound.ErrNoMember)
}

// sendProxy forwards one datagram through the named outbound/group. Any
// failure drops only this datagram (counted and reported by fixed category).
func (a *udpAssociation) sendProxyFast(name string, dst Address, payload []byte, target Address, rule int, rt *udpRoute) {
	s := a.server
	ses := a.proxySessionFor(name)
	if ses == nil {
		a.rcValid.Store(false)
	a.rcSnap.Store(nil)
		if a.flow != nil {
			a.flow.udpFailure(target, rule, []string{name}, "udp_setup_failed")
		}
		return
	}
	now := time.Now()
	nowNano := now.UnixNano()
	ses.last.Store(nowNano)
	if nowNano-ses.lastWDeadline.Load() >= int64(time.Second) {
		ses.pc.SetWriteDeadline(now.Add(s.cfg.Limits.DialTimeout.value()))
		ses.lastWDeadline.Store(nowNano)
	}
	if _, e := ses.pc.WriteTo(payload, outbound.Addr{Host: dst.Host, Port: dst.Port}); e != nil {
		a.rcValid.Store(false)
	a.rcSnap.Store(nil)
		a.flow.udpFailure(target, rule, ses.chain, dialResult(e), e)
		s.counters.Dropped.Add(1)
		switch {
		case blockedError(e):
			s.failure(failBlocked, "udp", -1)
			return
		case udpUnavailable(e):
			s.failure(failOutboundUDP, "udp", -1)
		case !quietFailure(e):
			s.failure(failUDPIO, "udp", -1)
		}
		a.dropProxy(ses)
		return
	}
	a.flow.udpUp(rt, len(payload))
	a.activity.Store(nowNano)
}


func (a *udpAssociation) sendProxyFastBatch(name string, dst Address, payloads [][]byte, target Address, rule int, rt *udpRoute) {
	s := a.server
	ses := a.proxySessionFor(name)
	if ses == nil {
		a.rcValid.Store(false)
	a.rcSnap.Store(nil)
		if a.flow != nil {
			a.flow.udpFailure(target, rule, []string{name}, "udp_setup_failed")
		}
		return
	}
	bw, ok := ses.pc.(outbound.BatchPacketWriter)
	if !ok {
		for _, pay := range payloads {
			a.sendProxyFast(name, dst, pay, target, rule, rt)
		}
		return
	}
	now := time.Now()
	nowNano := now.UnixNano()
	ses.last.Store(nowNano)
	if nowNano-ses.lastWDeadline.Load() >= int64(time.Second) {
		ses.pc.SetWriteDeadline(now.Add(s.cfg.Limits.DialTimeout.value()))
		ses.lastWDeadline.Store(nowNano)
	}
	sent, e := bw.WriteBatch(payloads, outbound.Addr{Host: dst.Host, Port: dst.Port})
	for i := 0; i < sent; i++ {
		a.flow.udpUp(rt, len(payloads[i]))
	}
	if sent > 0 {
		a.activity.Store(nowNano)
	}
	if e != nil {
		a.rcValid.Store(false)
	a.rcSnap.Store(nil)
		a.flow.udpFailure(target, rule, ses.chain, dialResult(e), e)
		s.counters.Dropped.Add(int64(len(payloads) - sent))
		switch {
		case blockedError(e):
			s.failure(failBlocked, "udp", -1)
			return
		case udpUnavailable(e):
			s.failure(failOutboundUDP, "udp", -1)
		case !quietFailure(e):
			s.failure(failUDPIO, "udp", -1)
		}
		a.dropProxy(ses)
	}
}

func (a *udpAssociation) sendProxy(name string, dst Address, payload []byte, target Address, rule int, allowed []netip.AddrPort) (*udpRoute, bool) {
	s := a.server
	ses := a.proxySessionFor(name)
	if ses == nil {
		if a.flow != nil {
			a.flow.udpFailure(target, rule, []string{name}, "udp_setup_failed")
		}
		return nil, false
	}
	if name == "direct" {
		// The router already evaluated each resolved IP. Never pass the domain
		// to the session's independent resolver/cache, including on sniff override.
		selector, ok := ses.pc.(interface {
			SelectCandidate([]netip.AddrPort) (netip.AddrPort, error)
		})
		if !ok {
			a.flow.udpFailure(target, rule, []string{name}, "udp_setup_failed")
			s.counters.Dropped.Add(1)
			return nil, false
		}
		ap, e := selector.SelectCandidate(allowed)
		if e != nil {
			a.flow.udpFailure(target, rule, []string{name}, dialResult(e), e)
			s.counters.Dropped.Add(1)
			return nil, false
		}
		dst = Address{ap.Addr().String(), ap.Port()}
	}
	chain := ses.chain
	memberName := ""
	memberPC, hasMember := ses.pc.(interface{ MemberFor(outbound.Addr) string })
	if hasMember {
		memberName = memberPC.MemberFor(outbound.Addr{Host: dst.Host, Port: dst.Port})
		if memberName != "" {
			chain = append(append([]string(nil), chain...), memberName)
		}
	}
	a.flow.setRemoteDNS(chain, dst.Host)
	rt := a.flow.udpDecided(target, rule, chain)
	if memberName != "" {
		ses.members.Store(memberName, rt)
	}
	if rt != nil {
		ses.route.Store(rt)
	}
	now := time.Now()
	nowNano := now.UnixNano()
	ses.last.Store(nowNano)
	if nowNano-ses.lastWDeadline.Load() >= int64(time.Second) {
		ses.pc.SetWriteDeadline(now.Add(s.cfg.Limits.DialTimeout.value()))
		ses.lastWDeadline.Store(nowNano)
	}
	if _, e := ses.pc.WriteTo(payload, outbound.Addr{Host: dst.Host, Port: dst.Port}); e != nil {
		a.flow.udpFailure(target, rule, chain, dialResult(e), e)
		s.counters.Dropped.Add(1)
		switch {
		case blockedError(e):
			// Only this destination is refused; the session itself is fine.
			s.failure(failBlocked, "udp", -1)
			return nil, false
		case udpUnavailable(e):
			s.failure(failOutboundUDP, "udp", -1)
		case !quietFailure(e):
			s.failure(failUDPIO, "udp", -1)
		}
		// A broken session (e.g. its UoT stream died) is replaced on the next datagram.
		a.dropProxy(ses)
		return nil, false
	}
	if hasMember {
		if actual := memberPC.MemberFor(outbound.Addr{Host: dst.Host, Port: dst.Port}); actual != "" && actual != memberName {
			chain = append(append([]string(nil), ses.chain...), actual)
			a.flow.setRemoteDNS(chain, dst.Host)
			rt = a.flow.udpDecided(target, rule, chain)
			ses.members.Store(actual, rt)
		}
	}
	a.flow.udpUp(rt, len(payload))
	a.activity.Store(nowNano)
	return rt, !hasMember && name != "direct"
}

func (a *udpAssociation) proxySessionFor(name string) *proxySession {
	s := a.server
	a.mu.Lock()
	ses, closed := a.proxies[name], a.proxyClosed
	count := len(a.proxies)
	a.mu.Unlock()
	if ses != nil {
		return ses
	}
	if closed || a.ctx.Err() != nil {
		s.counters.Dropped.Add(1)
		return nil
	}
	var ob outbound.Outbound
	if s.rt != nil {
		ob = s.rt.nodes[name]
	}
	full := false
	if s.rt != nil {
		full = count >= s.rt.proxies
	}
	if ob == nil || full {
		s.counters.Dropped.Add(1)
		s.failure(failUDPTargets, "udp", -1)
		return nil
	}
	if !ob.UDP() {
		s.counters.Dropped.Add(1)
		s.failure(failOutboundUDP, "udp", -1)
		return nil
	}
	l := s.cfg.Limits
	ctx, cancel := context.WithTimeout(a.ctx, l.DialTimeout.value()+l.HandshakeTimeout.value())
	h := &hops{}
	pc, e := ob.ListenPacket(context.WithValue(ctx, hopsKey{}, h))
	cancel()
	if e != nil {
		a.flow.setError(e)
		s.counters.Dropped.Add(1)
		switch {
		case udpUnavailable(e):
			s.failure(failOutboundUDP, "udp", -1)
		case errors.Is(e, outbound.ErrRejected):
			s.failure(failRoute, "outbound", -1)
		case a.ctx.Err() != nil:
		default:
			s.failure(failOutboundDial, "udp", -1)
		}
		return nil
	}
	ses = &proxySession{name: name, pc: pc, chain: h.chain(name)}
	ses.last.Store(time.Now().UnixNano())
	a.mu.Lock()
	if a.proxyClosed {
		a.mu.Unlock()
		pc.Close()
		s.counters.Dropped.Add(1)
		return nil
	}
	if a.proxies == nil {
		a.proxies = map[string]*proxySession{}
	}
	a.proxies[name] = ses
	// The sender itself holds a wg count, so this Add never races a Wait at zero.
	a.wg.Add(1)
	a.mu.Unlock()
	go func() { defer a.wg.Done(); a.proxyReturnLoop(ses) }()
	return ses
}

// proxyReturnLoop delivers replies of one proxy session to the client via the
// association's normal output path. Replies come only from the session the
// association created, so each one renews both the session and the
// association (the same rule as an accepted direct reply).
func (a *udpAssociation) proxyReturnLoop(ses *proxySession) {
	defer a.dropProxy(ses)
	idle := a.server.cfg.Limits.UDPIdle.value()
	b := make([]byte, 65535)
	var (
		lastDeadlineSet int64
		forceDeadline   = true
		cachedClient    netip.AddrPort
		lastHostRaw     string
		lastHostClean   string
		pktSeen         int
		batchReader, _  = ses.pc.(outbound.BatchPacketReader)
		_, hasMember    = ses.pc.(interface{ ReadMember() string })
		rb              *udpmmsg.RecvBatch
		batchSrcs       [udpmmsg.BatchSize]outbound.Addr
		outAddrs        [udpmmsg.BatchSize]Address
		outPays         [udpmmsg.BatchSize][]byte
	)
	defer func() {
		if rb != nil {
			udpmmsg.ReleaseRecvBatch(rb)
		}
	}()
	for {
		lastAct := ses.last.Load()
		if forceDeadline || lastAct-lastDeadlineSet >= int64(time.Second) {
			ses.pc.SetReadDeadline(time.Unix(0, lastAct).Add(idle))
			lastDeadlineSet = lastAct
			forceDeadline = false
		}
		if rb != nil {
			cnt, e := batchReader.ReadBatch(rb.Bufs[:], rb.Lens[:], batchSrcs[:])
			if e != nil {
				var ne net.Error
				if (errors.Is(e, os.ErrDeadlineExceeded) || errors.As(e, &ne) && ne.Timeout()) && time.Since(time.Unix(0, ses.last.Load())) < idle && a.ctx.Err() == nil {
					forceDeadline = true
					continue
				}
				return
			}
			nowNano := time.Now().UnixNano()
			ses.last.Store(nowNano)
			a.activity.Store(nowNano)
			client := cachedClient
			if client.Port() == 0 {
				a.mu.Lock()
				client = a.client
				a.mu.Unlock()
				if client.Port() != 0 {
					cachedClient = client
				}
			}
			valid := 0
			totalBytes := 0
			for i := 0; i < cnt; i++ {
				n := rb.Lens[i]
				if n > maxDatagram {
					a.server.counters.Dropped.Add(1)
					a.server.failure(failUDPInvalid, "udp", -1)
					continue
				}
				host := batchSrcs[i].Host
				if host == lastHostRaw && lastHostClean != "" {
					host = lastHostClean
				} else {
					lastHostRaw = host
					if ip, pe := netip.ParseAddr(host); pe == nil {
						host = ip.WithZone("").Unmap().String()
					}
					lastHostClean = host
				}
				outAddrs[valid] = Address{host, batchSrcs[i].Port}
				outPays[valid] = rb.Bufs[i][:n]
				totalBytes += n
				valid++
			}
			if valid == 0 {
				continue
			}
			if e = a.outputBatch(client, outAddrs[:valid], outPays[:valid], idle); e != nil {
				a.cancel()
				return
			}
			a.flow.udpDown(ses.route.Load(), totalBytes)
			continue
		}
		n, src, e := ses.pc.ReadFrom(b)
		if e != nil {
			var ne net.Error
			if (errors.Is(e, os.ErrDeadlineExceeded) || errors.As(e, &ne) && ne.Timeout()) && time.Since(time.Unix(0, ses.last.Load())) < idle && a.ctx.Err() == nil {
				forceDeadline = true
				continue
			}
			return
		}
		if n > maxDatagram {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPInvalid, "udp", -1)
			continue
		}
		nowNano := time.Now().UnixNano()
		ses.last.Store(nowNano)
		a.activity.Store(nowNano)
		host := src.Host
		if host == lastHostRaw && lastHostClean != "" {
			host = lastHostClean
		} else {
			lastHostRaw = host
			if ip, pe := netip.ParseAddr(host); pe == nil {
				host = ip.WithZone("").Unmap().String()
			}
			lastHostClean = host
		}
		client := cachedClient
		if client.Port() == 0 {
			a.mu.Lock()
			client = a.client
			a.mu.Unlock()
			if client.Port() != 0 {
				cachedClient = client
			}
		}
		source := Address{host, src.Port}
		if e = a.output(client, source, b[:n], idle); e != nil {
			// Same as a direct reply write failure: the client side is gone.
			a.cancel()
			return
		}
		rt := ses.route.Load()
		if pc, ok := ses.pc.(interface{ ReadMember() string }); ok {
			actual := pc.ReadMember()
			if v, ok := ses.members.Load(actual); ok {
				rt, _ = v.(*udpRoute)
			}
			// A fast reply from a fallback member can precede WriteTo's return.
			// Meter the member carried by the datagram, not the previous target.
			if actual != "" {
				r := &udpRoute{}
				if rt != nil && rt.rule != nil {
					r.rule = rt.rule
					r.meters = append(r.meters, rt.rule)
				}
				r.meters = append(r.meters, sesMemberCounters(a.server, ses.chain, actual)...)
				rt = r
			}
		}
		a.flow.udpDown(rt, n)
		pktSeen++
		if pktSeen == udpmmsg.UpgradeCnt && batchReader != nil && !hasMember && a.native != nil && a.rawNative != nil {
			rb = udpmmsg.AcquireRecvBatch()
			b = nil
		}
	}
}

func (a *udpAssociation) dropProxy(ses *proxySession) {
	a.mu.Lock()
	if a.proxies[ses.name] == ses {
		delete(a.proxies, ses.name)
	}
	a.mu.Unlock()
	ses.pc.Close()
}

// closeProxies closes every proxy session and refuses new ones; their readers
// then exit and are joined through the association's wait group.
func (a *udpAssociation) closeProxies() {
	a.mu.Lock()
	a.proxyClosed = true
	list := a.proxies
	a.proxies = nil
	a.mu.Unlock()
	for _, ses := range list {
		ses.pc.Close()
	}
}

func sesMemberCounters(s *Server, chain []string, member string) []*stats.Counter {
	return s.chainCounters(append(append([]string(nil), chain...), member))
}
