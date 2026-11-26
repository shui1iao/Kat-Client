package kernel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/shui1iao/Kat/internal/udpmmsg"
	"golang.org/x/net/dns/dnsmessage"
)

const maxDatagram = 65507

const udpPayloadPoolCap = 2048

var udpPayloadPool = sync.Pool{
	New: func() any {
		b := make([]byte, udpPayloadPoolCap)
		return &b
	},
}

func acquireUDPPayload(n int) []byte {
	if n <= udpPayloadPoolCap {
		bp := udpPayloadPool.Get().(*[]byte)
		return (*bp)[:n]
	}
	return make([]byte, n)
}

func releaseUDPPayload(b []byte) {
	if cap(b) == udpPayloadPoolCap {
		s := b[:udpPayloadPoolCap]
		udpPayloadPool.Put(&s)
	}
}

type packet struct {
	target  Address
	payload []byte
}
type udpAssociation struct {
	// TUN uses the existing bounded queue/sniffer, never its proxy codec/socket lifecycle.
	tunSend func(context.Context, packet, time.Duration)

	server                       *Server
	ctx                          context.Context
	cancel                       context.CancelFunc
	stream                       net.Conn
	outbound4, outbound6, native *net.UDPConn
	rawNative                    syscall.RawConn
	v6Native                     bool
	activity                     atomic.Int64
	receivedDatagram             atomic.Bool
	queuedBytes                  atomic.Int64
	outputMu                     sync.Mutex
	req                          request
	queue                        chan packet
	mu                           sync.Mutex
	client                       netip.AddrPort
	allowed                      map[netip.AddrPort]time.Time
	wg                           sync.WaitGroup
	// Routing: client address (src_ip_cidr only, never logged) and the lazily
	// created per-outbound proxy sessions (guarded by mu).
	source      netip.Addr
	proxies     map[string]*proxySession
	proxyClosed bool
	// Statistics: the association's flow and the route of each direct
	// target (same lifetime as allowed, guarded by mu) for reply metering.
	flow   *flow
	routes map[netip.AddrPort]*udpRoute
	// Sniffing (0.7.0): with override_destination a direct reply from the
	// resolved address is reported from the client's original target.
	reverse map[netip.AddrPort]Address
	// Hot-path buffers & caches (outBuf/lastNativeWDeadline under outputMu; rc* owned by sendLoop).
	outBuf              []byte
	lastNativeWDeadline int64
	rcTarget            Address
	rcProxy             string
	rcDst               Address
	rcRule              int
	rcRoute             *udpRoute
	rcValid             atomic.Bool
	rcSnap              atomic.Pointer[udpFastRoute]
	hasSniffer          atomic.Bool
}

type udpFastRoute struct {
	target Address
	proxy  string
	dst    Address
	rule   int
	rt     *udpRoute
}

func (s *Server) resolve(ctx context.Context, a Address) (netip.AddrPort, error) {
	if a.Port == 0 {
		return netip.AddrPort{}, errors.New("zero destination port")
	}
	if ip, e := netip.ParseAddr(a.Host); e == nil {
		return netip.AddrPortFrom(ip.Unmap(), a.Port), nil
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.DialTimeout.value())
	defer cancel()
	if e := s.dialSlots.acquire(ctx); e != nil {
		return netip.AddrPort{}, e
	}
	s.counters.Dials.Add(1)
	defer func() { s.dialSlots.release(); s.counters.Dials.Add(-1) }()
	ips, e := s.lookup(ctx, a.Host)
	if e != nil {
		return netip.AddrPort{}, e
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, errors.New("no address")
	}
	return netip.AddrPortFrom(ips[0].Unmap(), a.Port), nil
}
func (s *Server) serveUDP(c net.Conn, r request) (retErr error) {
	if !s.udpSlots.try() {
		s.failure(failUDPBudget, "udp", -1)
		_ = r.respond(c, nil, false)
		return errors.New("UDP association limit")
	}
	s.counters.UDP.Add(1)
	defer func() { s.udpSlots.release(); s.counters.UDP.Add(-1) }()
	parent := s.ctx
	if r.Context != nil {
		parent = r.Context
	}
	f, fparent := s.newFlow(parent, "udp", Address{})
	ctx, cancel := context.WithCancel(fparent)
	a := &udpAssociation{server: s, ctx: ctx, cancel: cancel, stream: c, req: r, queue: make(chan packet, s.cfg.Limits.UDPQueue), allowed: make(map[netip.AddrPort]time.Time), flow: f}
	a.source = sourceOf(parent)
	if !a.source.IsValid() {
		a.source = addrIP(c.RemoteAddr())
	}
	f.setSource(a.source)
	established := false
	defer func() {
		result := "ok"
		if retErr != nil && (!established || !(errors.Is(retErr, io.EOF) || errors.Is(retErr, net.ErrClosed) || errors.Is(retErr, context.Canceled) || errors.Is(retErr, io.ErrClosedPipe))) {
			result = "udp_association_failed"
			if f != nil {
				f.mu.Lock()
				failureRecorded := f.lastOutcome == "error" || f.lastOutcome == "rejected"
				f.mu.Unlock()
				if !failureRecorded {
					f.setError(retErr)
				}
			}
		} else if established && !a.receivedDatagram.Load() {
			// An accepted control association is not a transmitted UDP datagram.
			result = "idle"
		}
		f.end(result)
	}()
	defer cancel()
	var e error
	a.outbound4, e = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(s.cfg.UDPBindIPv4)})
	if e != nil {
		return e
	}
	defer a.outbound4.Close()
	if !s.cfg.IPv6Disabled() {
		a.outbound6, e = net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP(s.cfg.UDPBindIPv6)})
	}
	if e != nil && s.cfg.UDPBindIPv6 != "" {
		return e
	}
	if a.outbound6 != nil {
		defer a.outbound6.Close()
	}
	if r.Mode == "socks5" {
		peer := c.RemoteAddr().(*net.TCPAddr).AddrPort()
		peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
		ip, err := netip.ParseAddr(r.Target.Host)
		if err != nil {
			v, err := s.resolve(ctx, Address{r.Target.Host, 1})
			if err != nil {
				return err
			}
			ip = v.Addr()
		}
		if !ip.IsUnspecified() && ip.Unmap() != peer.Addr() {
			_ = r.respond(c, nil, false)
			return errors.New("UDP client address must match TCP peer")
		}
		a.client = netip.AddrPortFrom(peer.Addr(), r.Target.Port)
		local := c.LocalAddr().(*net.TCPAddr)
		a.native, e = net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Zone: local.Zone})
		if e != nil {
			return e
		}
		a.rawNative, _ = a.native.SyscallConn()
		a.v6Native = udpmmsg.IsIPv6Socket(a.native)
		defer a.native.Close()
	}
	var bound net.Addr
	if a.native != nil {
		bound = a.native.LocalAddr()
	}
	if e = r.respond(c, bound, true); e != nil {
		return e
	}
	established = true
	a.activity.Store(time.Now().UnixNano())
	// One cancellation watcher, sender and return reader per association; never per packet.
	a.wg.Add(2)
	go func() {
		defer a.wg.Done()
		<-ctx.Done()
		c.Close()
		a.outbound4.Close()
		if a.outbound6 != nil {
			a.outbound6.Close()
		}
		if a.native != nil {
			a.native.Close()
		}
	}()
	go func() { defer a.wg.Done(); defer cancel(); a.sendLoop() }()
	for _, socket := range []*net.UDPConn{a.outbound4, a.outbound6} {
		if socket == nil {
			continue
		}
		a.wg.Add(1)
		go func() { defer a.wg.Done(); defer cancel(); a.returnLoop(socket) }()
	}
	if a.native != nil {
		a.wg.Add(1)
		go func() { defer a.wg.Done(); defer cancel(); var b [1]byte; _, _ = c.Read(b[:]) }()
		e = a.nativeLoop()
	} else {
		e = errors.New("missing local SOCKS5 UDP socket")
	}
	cancel()
	a.wg.Wait()
	// Release all queued payloads; they are private bounded allocations, not shared pool references.
	for {
		select {
		case p := <-a.queue:
			a.queuedBytes.Add(-int64(len(p.payload)))
			releaseUDPPayload(p.payload)
		default:
			return e
		}
	}
}
func (a *udpAssociation) enqueue(p packet) {
	a.receivedDatagram.Store(true)
	n := int64(len(p.payload))
	limit := int64(a.server.cfg.Limits.UDPQueueBytes)
	// A zero limit only exists in isolated unit fixtures; validated servers always set it.
	if limit == 0 {
		limit = int64(a.server.cfg.Limits.UDPQueue * maxDatagram)
	}
	if a.ctx.Err() != nil {
		releaseUDPPayload(p.payload)
		return
	}
	for {
		old := a.queuedBytes.Load()
		if n > limit-old {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPQueue, "udp", -1)
			releaseUDPPayload(p.payload)
			return
		}
		if a.queuedBytes.CompareAndSwap(old, old+n) {
			break
		}
	}
	select {
	case <-a.ctx.Done():
		a.queuedBytes.Add(-n)
		releaseUDPPayload(p.payload)
	case a.queue <- p:
	default:
		a.queuedBytes.Add(-n)
		a.server.counters.Dropped.Add(1)
		a.server.failure(failUDPQueue, "udp", -1)
		releaseUDPPayload(p.payload)
	}
}
func (a *udpAssociation) nativeLoop() error {
	b := make([]byte, 65535)
	var frags *reassembly // created by the first fragment (FRAG != 0)
	defer func() {
		if frags != nil {
			frags.close()
		}
	}()
	var (
		cachedClient netip.AddrPort
		cacheIP4     [4]byte
		cacheStr     string
		cacheInit    bool
	)
	var rb *udpmmsg.RecvBatch
	pktSeen := 0
	defer func() {
		if rb != nil {
			udpmmsg.ReleaseRecvBatch(rb)
		}
	}()
	handleDatagram := func(pkt []byte, src netip.AddrPort) {
		n := len(pkt)
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		client := cachedClient
		if client.Port() == 0 {
			a.mu.Lock()
			client = a.client
			a.mu.Unlock()
			if client.Port() != 0 {
				cachedClient = client
			}
		}
		if src.Addr() != client.Addr() || (client.Port() != 0 && src.Port() != client.Port()) {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPInvalid, "udp", -1)
			return
		}
		if n < 4 || pkt[0] != 0 || pkt[1] != 0 {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPInvalid, "udp", -1)
			return
		}
		target, consumed, e := parseAddressBytes(pkt[3:n], &cacheIP4, &cacheStr, &cacheInit)
		payOff := 3 + consumed
		if e != nil || n-payOff > maxDatagram || target.Port == 0 {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPInvalid, "udp", -1)
			return
		}
		if cachedClient.Port() == 0 {
			a.mu.Lock()
			if a.client.Port() == 0 {
				a.client = src
			}
			cachedClient = a.client
			a.mu.Unlock()
		}
		if pkt[2] != 0 {
			payload := append([]byte(nil), pkt[payOff:n]...)
			if frags == nil {
				frags = a.newReassembly()
			}
			if frags == nil {
				a.server.frags.dropped.Add(1)
				return
			}
			var ok bool
			if target, payload, ok = frags.add(pkt[2], target, payload); !ok {
				return
			}
			a.enqueue(packet{target: target, payload: payload})
			return
		}
		payload := acquireUDPPayload(n - payOff)
		copy(payload, pkt[payOff:n])
		a.enqueue(packet{target: target, payload: payload})
	}
	for {
		if rb == nil {
			n, src, e := a.native.ReadFromUDPAddrPort(b)
			if e != nil {
				return e
			}
			handleDatagram(b[:n], src)
			pktSeen++
			if pktSeen == udpmmsg.UpgradeCnt && a.rawNative != nil {
				rb = udpmmsg.AcquireRecvBatch()
				b = nil
			}
			continue
		}
		cnt, e := udpmmsg.ReadBatch(a.native, a.rawNative, rb)
		if e != nil {
			return e
		}
		if snap := a.rcSnap.Load(); snap != nil && !a.hasSniffer.Load() && len(a.queue) == 0 && cachedClient.Port() != 0 {
			var fastPays [udpmmsg.BatchSize][]byte
			fastN := 0
			allFast := true
			for i := 0; i < cnt; i++ {
				src := rb.Addrs[i]
				if !src.IsValid() {
					continue
				}
				pkt := rb.Bufs[i][:rb.Lens[i]]
				if src != cachedClient || len(pkt) < 4 || pkt[0] != 0 || pkt[1] != 0 || pkt[2] != 0 {
					allFast = false
					break
				}
				target, consumed, pe := parseAddressBytes(pkt[3:], &cacheIP4, &cacheStr, &cacheInit)
				payOff := 3 + consumed
				if pe != nil || len(pkt)-payOff > maxDatagram || target != snap.target {
					allFast = false
					break
				}
				fastPays[fastN] = pkt[payOff:]
				fastN++
			}
			if allFast && fastN > 0 {
				a.receivedDatagram.Store(true)
				a.sendProxyFastBatch(snap.proxy, snap.dst, fastPays[:fastN], snap.target, snap.rule, snap.rt)
				continue
			}
		}
		for i := 0; i < cnt; i++ {
			if rb.Addrs[i].IsValid() {
				handleDatagram(rb.Bufs[i][:rb.Lens[i]], rb.Addrs[i])
			}
		}
	}
}
func (a *udpAssociation) sendLoop() {
	idle := a.server.cfg.Limits.UDPIdle.value()
	// Proxy sessions never outlive the association's sender.
	defer a.closeProxies()
	sn := a.newUDPSniffer()
	if sn != nil {
		a.hasSniffer.Store(true)
	}
	var batch [udpmmsg.BatchSize]packet
	var payBatch [udpmmsg.BatchSize][]byte
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-sn.timerC():
			sn.expire(a, time.Now(), idle)
		case p := <-a.queue:
			batch[0] = p
			n := 1
			drainedBytes := int64(len(p.payload))
			if sn == nil && a.tunSend == nil {
				for n < udpmmsg.BatchSize {
					select {
					case p2 := <-a.queue:
						batch[n] = p2
						drainedBytes += int64(len(p2.payload))
						n++
					default:
						goto drained
					}
				}
			}
		drained:
			a.queuedBytes.Add(-drainedBytes)
			if sn != nil {
				sn.packet(a, batch[0], idle)
				batch[0] = packet{}
				continue
			}
			if n > 1 && a.rcValid.Load() {
				allSame := true
				for i := 0; i < n; i++ {
					if batch[i].target != a.rcTarget {
						allSame = false
						break
					}
					payBatch[i] = batch[i].payload
				}
				if allSame {
					a.sendProxyFastBatch(a.rcProxy, a.rcDst, payBatch[:n], a.rcTarget, a.rcRule, a.rcRoute)
					for i := 0; i < n; i++ {
						releaseUDPPayload(batch[i].payload)
						batch[i] = packet{}
						payBatch[i] = nil
					}
					continue
				}
			}
			for i := 0; i < n; i++ {
				a.send(a.ctx, batch[i], idle)
				releaseUDPPayload(batch[i].payload)
				batch[i] = packet{}
			}
		}
	}
}

// send routes and forwards one datagram (ctx may carry a sniff result).
func (a *udpAssociation) send(ctx context.Context, p packet, idle time.Duration) {
	if a.tunSend != nil {
		a.tunSend(ctx, p, idle)
		return
	}
	if a.rcValid.Load() && p.target == a.rcTarget && sniffOf(ctx).target(p.target) == p.target {
		a.sendProxyFast(a.rcProxy, a.rcDst, p.payload, p.target, a.rcRule, a.rcRoute)
		return
	}
	if a.native != nil {
		a.mu.Lock()
		source := a.client
		a.mu.Unlock()
		ctx = context.WithValue(ctx, udpProcessKey{}, udpProcessTuple{source: source, destination: addrPort(a.native.LocalAddr())})
	}
	ctx = withOriginalTarget(ctx, p.target)
	if ip, e := netip.ParseAddr(p.target.Host); e == nil && a.server.cfg.clientDNS != nil && ClientFakeIP(ip) {
		a.server.counters.Dropped.Add(1)
		a.flow.setError(errFakeIP)
		return
	}
	if a.server.controlledDNS(p.target) {
		a.sendDNS(ctx, p, idle)
		return
	}
	a.flow.scheduleDetails(ctx, p.target)
	a.flow.sniffHost(ctx, p.target)
	candidates, proxy, host, rule, e := a.server.routeUDP(ctx, p.target, a.source)
	if e != nil {
		if errors.Is(e, errRouteReject) {
			a.flow.udpDecided(p.target, rule, []string{"reject"})
		} else if a.flow != nil {
			a.flow.setError(e)
			a.flow.emitConnection(p.target.String(), "", nil, "error", dialResult(e))
		}
		a.server.counters.Dropped.Add(1)
		a.server.resolutionFailure(e)
		return
	}
	overridden := sniffOf(ctx).target(p.target) != p.target
	if proxy != "" {
		dst := Address{host, p.target.Port}
		if overridden {
			// Replies through a proxy cannot be mapped back reliably:
			// the outbound gets the original target.
			dst = p.target
		}
		rt, cacheable := a.sendProxy(proxy, dst, p.payload, p.target, rule, candidates)
		if cacheable && !overridden && proxy != "direct" {
			a.rcTarget = p.target
			a.rcProxy = proxy
			a.rcDst = dst
			a.rcRule = rule
			a.rcRoute = rt
			a.rcValid.Store(true)
		}
		return
	}
	var target netip.AddrPort
	var socket *net.UDPConn
	blocked := false
	for _, ip := range candidates {
		if a.server.cfg.blockedDestination(ip.Addr()) {
			blocked = true
			if a.flow != nil {
				a.flow.emitConnection(p.target.String(), "", []string{"direct"}, "rejected", "blocked")
			}
			return
		}
		sock := a.outbound4
		if ip.Addr().Is6() {
			sock = a.outbound6
		}
		if sock != nil {
			target, socket = ip, sock
			break
		}
	}
	if socket == nil {
		a.flow.udpFailure(p.target, rule, []string{"direct"}, "udp_socket_failed")
		a.server.counters.Dropped.Add(1)
		if blocked {
			a.server.failure(failBlocked, "udp", -1)
		} else {
			a.server.failure(failUDPInvalid, "udp", -1)
		}
		return
	}
	a.flow.setRemoteDNS([]string{"direct"}, "")
	rt := a.flow.udpDecided(p.target, rule, []string{"direct"})
	now := time.Now()
	a.mu.Lock()
	for k, t := range a.allowed {
		if now.Sub(t) > idle {
			delete(a.allowed, k)
			delete(a.routes, k)
			delete(a.reverse, k)
		}
	}
	_, exists := a.allowed[target]
	if !exists && len(a.allowed) >= a.server.cfg.Limits.UDPTargets {
		a.mu.Unlock()
		a.server.counters.Dropped.Add(1)
		a.server.failure(failUDPTargets, "udp", -1)
		a.flow.udpFailure(p.target, rule, []string{"direct"}, "udp_targets_limit")
		return
	}
	a.allowed[target] = now
	if overridden {
		if a.reverse == nil {
			a.reverse = map[netip.AddrPort]Address{}
		}
		a.reverse[target] = p.target
	}
	if rt != nil {
		if a.routes == nil {
			a.routes = map[netip.AddrPort]*udpRoute{}
		}
		a.routes[target] = rt
	}
	a.mu.Unlock()
	socket.SetWriteDeadline(now.Add(a.server.cfg.Limits.DialTimeout.value()))
	if _, e = socket.WriteToUDPAddrPort(p.payload, target); e != nil {
		a.flow.udpFailure(p.target, rule, []string{"direct"}, "udp_send_failed", e)
		a.server.counters.Dropped.Add(1)
		a.server.failure(failUDPIO, "udp", -1)
		return
	}
	ips := make([]netip.Addr, 0, len(candidates))
	for _, v := range candidates {
		ips = append(ips, v.Addr())
	}
	a.flow.dialIPs(ips, target.Addr())
	a.flow.udpUp(rt, len(p.payload))
	{
		a.activity.Store(time.Now().UnixNano())
	}
}

// sendDNS accounts only the client DNS payload, not upstream attempts/cache
// traffic. The target is the requested DNS endpoint, never the question name.
func (a *udpAssociation) sendDNS(ctx context.Context, p packet, idle time.Duration) {
	a.touchDNSActivity(idle)
	a.flow.udpUp(nil, len(p.payload))
	a.flow.udpDNS(p.target, "", nil)
	qctx, cancel := context.WithTimeout(ctx, a.server.cfg.Limits.DialTimeout.value())
	reply, e := a.server.answerDNS(qctx, p.payload, false)
	cancel()
	if e != nil {
		a.flow.udpDNS(p.target, "dns_query_failed", e)
		a.server.counters.Dropped.Add(1)
		return
	}
	// The gateway deliberately returns a wire SERVFAIL when all upstreams fail.
	// Deliver that response unchanged, but do not describe the query as ok.
	var parser dnsmessage.Parser
	header, e := parser.Start(reply)
	if e != nil || !header.Response || (header.RCode != dnsmessage.RCodeSuccess && header.RCode != dnsmessage.RCodeNameError) {
		a.flow.udpDNS(p.target, "dns_query_failed", errors.New("DNS upstream returned a failure response"))
	}
	a.mu.Lock()
	client := a.client
	a.mu.Unlock()
	if e = a.output(client, p.target, reply, idle); e != nil {
		a.flow.udpDNS(p.target, "dns_response_failed", e)
		a.server.counters.Dropped.Add(1)
		return
	}
	a.flow.udpDown(nil, len(reply))
	a.touchDNSActivity(idle)
}

// DNS-only associations have unused outbound readers too. Renew both their
// blocking read deadlines and the timestamp checked after a raced timeout.
func (a *udpAssociation) touchDNSActivity(idle time.Duration) {
	n := time.Now().UnixNano()
	for old := a.activity.Load(); n > old; old = a.activity.Load() {
		if a.activity.CompareAndSwap(old, n) {
			break
		}
	}
	deadline := time.Unix(0, a.activity.Load()).Add(idle)
	for _, socket := range []*net.UDPConn{a.outbound4, a.outbound6} {
		if socket != nil {
			_ = socket.SetReadDeadline(deadline)
		}
	}
}

func (a *udpAssociation) returnLoop(socket *net.UDPConn) {
	b := make([]byte, 65535)
	idle := a.server.cfg.Limits.UDPIdle.value()
	for {
		socket.SetReadDeadline(time.Unix(0, a.activity.Load()).Add(idle))
		n, src, e := socket.ReadFromUDPAddrPort(b)
		if e != nil {
			if timeout, ok := e.(net.Error); ok && timeout.Timeout() && time.Since(time.Unix(0, a.activity.Load())) < idle {
				continue
			}
			return
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		now := time.Now()
		a.mu.Lock()
		client := a.client
		a.mu.Unlock()
		if !a.acceptReturn(src, n, now, idle) {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPSource, "udp", -1)
			continue
		}
		payload := b[:n]
		source := Address{src.Addr().String(), src.Port()}
		a.mu.Lock()
		if o, ok := a.reverse[src]; ok {
			source = o
		}
		a.mu.Unlock()
		if e = a.output(client, source, payload, idle); e != nil {
			return
		}
		if a.flow != nil {
			a.mu.Lock()
			rt := a.routes[src]
			a.mu.Unlock()
			a.flow.udpDown(rt, n)
		}
	}
}

// output writes one reply datagram back to the client through whichever
// inbound path owns this association (SS native writeBack, UDPWrite stream,
// SOCKS5 native socket or a datagram codec). Shared by direct and proxy replies.
func (a *udpAssociation) output(client netip.AddrPort, source Address, payload []byte, idle time.Duration) error {
	var e error
	a.outputMu.Lock()
	defer a.outputMu.Unlock()
	if a.native != nil {
		if client.Port() == 0 {
			return nil
		}
		out := append(a.outBuf[:0], 0, 0, 0)
		out = appendAddress(out, source)
		out = append(out, payload...)
		a.outBuf = out
		if len(out) > maxDatagram {
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPInvalid, "udp", -1)
			return nil
		}
		now := time.Now()
		if nowNano := now.UnixNano(); nowNano-a.lastNativeWDeadline >= int64(time.Second) {
			a.native.SetWriteDeadline(now.Add(a.server.cfg.Limits.DialTimeout.value()))
			a.lastNativeWDeadline = nowNano
		}
		_, e = a.native.WriteToUDPAddrPort(out, client)
	}
	return e
}

// Datagram-over-stream parsing always uses ReadFull, never TCP Read boundaries.

// ssIdleExpired uses the same last-valid-activity timestamp as target readers.
// It is SS-only: other protocols retain their existing idle/default behavior.
// An exact target must already be authorized and not idle-expired BEFORE a reply
// can renew it. Unknown/expired sources and oversized datagrams never keep it alive.
// Refreshing only native SS preserves other protocol target-expiry semantics.
func (a *udpAssociation) acceptReturn(src netip.AddrPort, n int, now time.Time, idle time.Duration) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	last, ok := a.allowed[src]
	expired := now.Sub(last) > idle
	if !ok || expired || n > maxDatagram {
		return false
	}
	a.activity.Store(now.UnixNano())
	return true
}

// Concurrent SS readers/replies must not move the idle deadline backwards.

// touchActivity preserves the monotonic activity timestamp shared by TUN workers.
func (a *udpAssociation) touchActivity(now time.Time) {
	n := now.UnixNano()
	for old := a.activity.Load(); n > old; old = a.activity.Load() {
		if a.activity.CompareAndSwap(old, n) {
			return
		}
	}
}

func (a *udpAssociation) outputBatch(client netip.AddrPort, sources []Address, payloads [][]byte, idle time.Duration) error {
	if len(payloads) == 0 {
		return nil
	}
	if len(payloads) == 1 || a.native == nil || a.rawNative == nil || client.Port() == 0 {
		for i := range payloads {
			if e := a.output(client, sources[i], payloads[i], idle); e != nil {
				return e
			}
		}
		return nil
	}
	a.outputMu.Lock()
	defer a.outputMu.Unlock()
	var (
		pkts  [udpmmsg.BatchSize][]byte
		addrs [udpmmsg.BatchSize]netip.AddrPort
		sb    udpmmsg.SendBatch
		n     int
	)
	// Reuse a.outBuf as contiguous scratch for all SOCKS5 UDP frames in this batch.
	totalEst := 0
	for i := range payloads {
		totalEst += 24 + len(sources[i].Host) + len(payloads[i])
	}
	if cap(a.outBuf) < totalEst {
		a.outBuf = make([]byte, 0, totalEst)
	}
	buf := a.outBuf[:0]
	for i := range payloads {
		start := len(buf)
		buf = append(buf, 0, 0, 0)
		buf = appendAddress(buf, sources[i])
		buf = append(buf, payloads[i]...)
		frame := buf[start:]
		if len(frame) > maxDatagram {
			buf = buf[:start]
			a.server.counters.Dropped.Add(1)
			a.server.failure(failUDPInvalid, "udp", -1)
			continue
		}
		pkts[n] = frame
		addrs[n] = client
		n++
	}
	a.outBuf = buf[:0]
	if n == 0 {
		return nil
	}
	now := time.Now()
	nowNano := now.UnixNano()
	if nowNano-a.lastNativeWDeadline >= int64(time.Second) {
		a.native.SetWriteDeadline(now.Add(a.server.cfg.Limits.DialTimeout.value()))
		a.lastNativeWDeadline = nowNano
	}
	_, e := udpmmsg.WriteBatch(a.native, a.rawNative, a.v6Native, &sb, pkts[:n], addrs[:n])
	return e
}
