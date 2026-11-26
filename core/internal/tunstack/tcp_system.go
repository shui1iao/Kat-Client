package tunstack

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	natPortMin      uint16 = 10000
	natPortMax      uint16 = 65000
	natClosedGrace         = 5 * time.Second
	natUnacceptIdle        = 15 * time.Second
	natTCPBufSize          = 4 << 20
	defaultTUNIPv4         = "198.18.0.1"
	defaultTUNIPv6         = "fd4b:6174::1"
)

type tcpTuple struct {
	src netip.AddrPort
	dst netip.AddrPort
}

type tcpNATEntry struct {
	origSrc      netip.AddrPort
	origDst      netip.AddrPort
	tunIP        netip.Addr
	peerIP       netip.Addr
	natPort      uint16
	v6           bool
	epoch        uint64
	createdNano  int64
	accepted     atomic.Bool
	closedAtNano atomic.Int64
}

type tcpSystemStack struct {
	r *Runtime

	ln4   *net.TCPListener
	ln6   *net.TCPListener
	port4 uint16
	port6 uint16

	mu         sync.RWMutex
	byTuple    map[tcpTuple]*tcpNATEntry
	byPort4    [65536]*tcpNATEntry
	byPort6    [65536]*tcpNATEntry
	nextPort4  uint16
	nextPort6  uint16
	closed     bool
}

// derivePeerIP derives a deterministic on-link peer address inside the same
// /30 (IPv4) or /126 (IPv6) subnet as tunIP so the OS routes return packets
// directly into the TUN adapter without colliding with tunIP or network/broadcast.
func derivePeerIP(tunIP netip.Addr) netip.Addr {
	if tunIP.Is4() {
		b := tunIP.As4()
		switch b[3] & 0x03 {
		case 1:
			b[3] = (b[3] &^ 0x03) | 2
		case 2:
			b[3] = (b[3] &^ 0x03) | 1
		default:
			b[3] ^= 1
		}
		return netip.AddrFrom4(b)
	}
	b := tunIP.As16()
	switch b[15] & 0x03 {
	case 1:
		b[15] = (b[15] &^ 0x03) | 2
	case 2:
		b[15] = (b[15] &^ 0x03) | 1
	default:
		b[15] ^= 1
	}
	return netip.AddrFrom16(b)
}

func listenPreferAddr(network, preferred, fallback string) (*net.TCPListener, uint16, error) {
	if preferred != "" {
		if addr, err := net.ResolveTCPAddr(network, preferred); err == nil {
			if ln, err := net.ListenTCP(network, addr); err == nil {
				return ln, uint16(ln.Addr().(*net.TCPAddr).Port), nil
			}
		}
	}
	addr, err := net.ResolveTCPAddr(network, fallback)
	if err != nil {
		return nil, 0, err
	}
	ln, err := net.ListenTCP(network, addr)
	if err != nil {
		return nil, 0, err
	}
	return ln, uint16(ln.Addr().(*net.TCPAddr).Port), nil
}

func newTCPSystemStack(r *Runtime) (*tcpSystemStack, error) {
	pref4 := defaultTUNIPv4 + ":0"
	if r.cfg.LocalIPv4.IsValid() && r.cfg.LocalIPv4.Is4() {
		pref4 = netip.AddrPortFrom(r.cfg.LocalIPv4, 0).String()
	}
	ln4, port4, err := listenPreferAddr("tcp4", pref4, "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("tunstack tcp4 listen: %w", err)
	}

	pref6 := "[" + defaultTUNIPv6 + "]:0"
	if r.cfg.LocalIPv6.IsValid() && r.cfg.LocalIPv6.Is6() {
		pref6 = netip.AddrPortFrom(r.cfg.LocalIPv6, 0).String()
	}
	ln6, port6, err6 := listenPreferAddr("tcp6", pref6, "[::]:0")
	if err6 != nil {
		// IPv6 may be disabled on the host; degrade cleanly to IPv4-only.
		ln6 = nil
		port6 = 0
	}

	return &tcpSystemStack{
		r:         r,
		ln4:       ln4,
		ln6:       ln6,
		port4:     port4,
		port6:     port6,
		byTuple:   make(map[tcpTuple]*tcpNATEntry, 256),
		nextPort4: natPortMin,
		nextPort6: natPortMin,
	}, nil
}

func (s *tcpSystemStack) start() {
	s.r.wg.Add(1)
	go func() {
		defer s.r.wg.Done()
		s.acceptLoop(s.ln4, false)
	}()
	if s.ln6 != nil {
		s.r.wg.Add(1)
		go func() {
			defer s.r.wg.Done()
			s.acceptLoop(s.ln6, true)
		}()
	}
	s.r.wg.Add(1)
	go func() {
		defer s.r.wg.Done()
		s.gcLoop()
	}()
}

func (s *tcpSystemStack) close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if s.ln4 != nil {
		_ = s.ln4.Close()
	}
	if s.ln6 != nil {
		_ = s.ln6.Close()
	}
}

func (s *tcpSystemStack) gcLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.r.ctx.Done():
			return
		case <-ticker.C:
			s.gcNow(time.Now().UnixNano())
		}
	}
}

func (s *tcpSystemStack) natCount() uint64 {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	n := len(s.byTuple)
	s.mu.RUnlock()
	return uint64(n)
}

func (s *tcpSystemStack) gcNow(nowNano int64) {
	grace := natClosedGrace.Nanoseconds()
	unacc := natUnacceptIdle.Nanoseconds()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.byTuple {
		closedAt := e.closedAtNano.Load()
		expired := (closedAt > 0 && nowNano-closedAt >= grace) ||
			(!e.accepted.Load() && nowNano-e.createdNano >= unacc)
		if !expired {
			continue
		}
		delete(s.byTuple, k)
		if e.v6 {
			if s.byPort6[e.natPort] == e {
				s.byPort6[e.natPort] = nil
			}
		} else {
			if s.byPort4[e.natPort] == e {
				s.byPort4[e.natPort] = nil
			}
		}
	}
}

func (s *tcpSystemStack) allocPortLocked(v6 bool, nowNano int64) (uint16, bool) {
	table := &s.byPort4
	cursor := &s.nextPort4
	if v6 {
		table = &s.byPort6
		cursor = &s.nextPort6
	}
	grace := natClosedGrace.Nanoseconds()
	span := int(natPortMax - natPortMin)
	p := *cursor
	for i := 0; i < span; i++ {
		if p < natPortMin || p >= natPortMax {
			p = natPortMin
		}
		cur := table[p]
		if cur == nil {
			*cursor = p + 1
			if *cursor >= natPortMax {
				*cursor = natPortMin
			}
			return p, true
		}
		if closedAt := cur.closedAtNano.Load(); closedAt > 0 && nowNano-closedAt >= grace {
			// Reclaim expired port in-place.
			delete(s.byTuple, tcpTuple{src: cur.origSrc, dst: cur.origDst})
			table[p] = nil
			*cursor = p + 1
			if *cursor >= natPortMax {
				*cursor = natPortMin
			}
			return p, true
		}
		p++
	}
	return 0, false
}

// handleTCPInPlace rewrites a TUN TCP packet in-place (zero allocation on steady-state
// traffic) for either:
//   - Listener -> Application return traffic (srcPort == listenPort)
//   - Application -> Remote outbound traffic (rewritten to peerIP:natPort -> tunIP:listenPort)
//
// Returns (true, nil) when pkt.raw has been rewritten in-place and must be written
// back to the TUN device; (false, rst) when an explicit TCP RST should be sent back;
// or (false, nil) when the packet should be dropped silently.
func (s *tcpSystemStack) handleTCPInPlace(pkt ipPacket) (rewritten bool, rst []byte) {
	if len(pkt.payload) < 20 {
		return false, nil
	}
	srcPort := binary.BigEndian.Uint16(pkt.payload[0:2])
	dstPort := binary.BigEndian.Uint16(pkt.payload[2:4])
	if srcPort == 0 || dstPort == 0 {
		return false, nil
	}

	v6 := pkt.ver == 6
	listenPort := s.port4
	if v6 {
		if s.ln6 == nil {
			return false, nil
		}
		listenPort = s.port6
	}

	// Direction 1: Return packet from local TCP listener -> peerIP:natPort.
	if srcPort == listenPort {
		s.mu.RLock()
		var entry *tcpNATEntry
		if v6 {
			entry = s.byPort6[dstPort]
		} else {
			entry = s.byPort4[dstPort]
		}
		s.mu.RUnlock()
		if entry != nil && entry.peerIP == pkt.dst && entry.tunIP == pkt.src {
			rewriteIPTCPInPlace(pkt, entry.origDst.Addr(), entry.origDst.Port(), entry.origSrc.Addr(), entry.origSrc.Port())
			return true, nil
		}
		return false, nil
	}

	// Direction 2: Outbound packet from application -> remote.
	origSrc := netip.AddrPortFrom(pkt.src, srcPort)
	origDst := netip.AddrPortFrom(pkt.dst, dstPort)
	tuple := tcpTuple{src: origSrc, dst: origDst}
	flags := pkt.payload[13]
	isPureSYN := (flags & 0x12) == 0x02 // SYN=1, ACK=0

	// Fast path for established sessions: read-lock lookup only.
	if !isPureSYN {
		s.mu.RLock()
		entry := s.byTuple[tuple]
		s.mu.RUnlock()
		if entry == nil {
			return false, nil
		}
		rewriteIPTCPInPlace(pkt, entry.peerIP, entry.natPort, entry.tunIP, listenPort)
		return true, nil
	}

	// Pure SYN: check runtime admission gate BEFORE creating a NAT entry.
	s.r.mu.Lock()
	admitted := !s.r.stopping && !s.r.paused && s.r.ctx.Err() == nil && s.r.cfg.Admitting() && s.r.pending < maxHandlers
	var epoch uint64
	if admitted {
		epoch = s.r.cfg.Epoch()
		if epoch != s.r.cfg.Epoch() || !s.r.cfg.Admitting() {
			admitted = false
		}
	}
	s.r.mu.Unlock()
	if !admitted {
		s.r.dropped.Add(1)
		if r, ok := buildTCPRST(pkt, s.r.packetID.Add(1)); ok {
			return false, r
		}
		return false, nil
	}

	nowNano := time.Now().UnixNano()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false, nil
	}
	entry := s.byTuple[tuple]
	if entry != nil && entry.closedAtNano.Load() == 0 {
		// Retransmitted SYN for an active/pending tuple: reuse existing mapping.
		peerIP, natPort, tunIP := entry.peerIP, entry.natPort, entry.tunIP
		s.mu.Unlock()
		rewriteIPTCPInPlace(pkt, peerIP, natPort, tunIP, listenPort)
		return true, nil
	}
	if entry != nil {
		// Replace closed/TIME_WAIT mapping cleanly on fresh SYN.
		if v6 {
			if s.byPort6[entry.natPort] == entry {
				s.byPort6[entry.natPort] = nil
			}
		} else {
			if s.byPort4[entry.natPort] == entry {
				s.byPort4[entry.natPort] = nil
			}
		}
		delete(s.byTuple, tuple)
	}
	natPort, ok := s.allocPortLocked(v6, nowNano)
	if !ok {
		s.mu.Unlock()
		s.r.dropped.Add(1)
		if r, built := buildTCPRST(pkt, s.r.packetID.Add(1)); built {
			return false, r
		}
		return false, nil
	}
	tunIP := pkt.src
	peerIP := derivePeerIP(tunIP)
	entry = &tcpNATEntry{
		origSrc:     origSrc,
		origDst:     origDst,
		tunIP:       tunIP,
		peerIP:      peerIP,
		natPort:     natPort,
		v6:          v6,
		epoch:       epoch,
		createdNano: nowNano,
	}
	s.byTuple[tuple] = entry
	if v6 {
		s.byPort6[natPort] = entry
	} else {
		s.byPort4[natPort] = entry
	}
	s.mu.Unlock()

	rewriteIPTCPInPlace(pkt, peerIP, natPort, tunIP, listenPort)
	return true, nil
}

// rewriteIPTCPInPlace updates src/dst IP and TCP ports in-place and adjusts
// IPv4 header checksum and TCP checksum in O(1) time via RFC 1624.
func rewriteIPTCPInPlace(pkt ipPacket, newSrcIP netip.Addr, newSrcPort uint16, newDstIP netip.Addr, newDstPort uint16) {
	tcpHdr := pkt.payload
	oldSrcPort := binary.BigEndian.Uint16(tcpHdr[0:2])
	oldDstPort := binary.BigEndian.Uint16(tcpHdr[2:4])
	tcpCsum := binary.BigEndian.Uint16(tcpHdr[16:18])

	if pkt.ver == 4 {
		oldSrc := pkt.src.As4()
		oldDst := pkt.dst.As4()
		ns := newSrcIP.As4()
		nd := newDstIP.As4()
		oldIPSum := addr4Sum(oldSrc) + addr4Sum(oldDst)
		newIPSum := addr4Sum(ns) + addr4Sum(nd)

		copy(pkt.raw[12:16], ns[:])
		copy(pkt.raw[16:20], nd[:])
		ipCsum := binary.BigEndian.Uint16(pkt.raw[10:12])
		binary.BigEndian.PutUint16(pkt.raw[10:12], csumAddDelta(ipCsum, oldIPSum, newIPSum))

		binary.BigEndian.PutUint16(tcpHdr[0:2], newSrcPort)
		binary.BigEndian.PutUint16(tcpHdr[2:4], newDstPort)
		oldTCPSum := oldIPSum + uint32(oldSrcPort) + uint32(oldDstPort)
		newTCPSum := newIPSum + uint32(newSrcPort) + uint32(newDstPort)
		binary.BigEndian.PutUint16(tcpHdr[16:18], csumAddDelta(tcpCsum, oldTCPSum, newTCPSum))
		return
	}

	oldSrc := pkt.src.As16()
	oldDst := pkt.dst.As16()
	ns := newSrcIP.As16()
	nd := newDstIP.As16()
	oldIPSum := addr6Sum(oldSrc) + addr6Sum(oldDst)
	newIPSum := addr6Sum(ns) + addr6Sum(nd)

	copy(pkt.raw[8:24], ns[:])
	copy(pkt.raw[24:40], nd[:])

	binary.BigEndian.PutUint16(tcpHdr[0:2], newSrcPort)
	binary.BigEndian.PutUint16(tcpHdr[2:4], newDstPort)
	oldTCPSum := oldIPSum + uint32(oldSrcPort) + uint32(oldDstPort)
	newTCPSum := newIPSum + uint32(newSrcPort) + uint32(newDstPort)
	binary.BigEndian.PutUint16(tcpHdr[16:18], csumAddDelta(tcpCsum, oldTCPSum, newTCPSum))
}

func (s *tcpSystemStack) acceptLoop(ln *net.TCPListener, v6 bool) {
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			return
		}
		remoteAP := conn.RemoteAddr().(*net.TCPAddr).AddrPort()
		localAP := conn.LocalAddr().(*net.TCPAddr).AddrPort()
		remoteIP := remoteAP.Addr().Unmap()
		localIP := localAP.Addr().Unmap()
		natPort := remoteAP.Port()

		s.mu.RLock()
		var entry *tcpNATEntry
		if v6 {
			entry = s.byPort6[natPort]
		} else {
			entry = s.byPort4[natPort]
		}
		s.mu.RUnlock()

		// Strict validation: reject any non-NAT connection (including external probes).
		if entry == nil || entry.peerIP != remoteIP || entry.tunIP != localIP || !entry.accepted.CompareAndSwap(false, true) {
			_ = conn.Close()
			continue
		}

		if !s.r.reserve() {
			entry.closedAtNano.Store(time.Now().UnixNano())
			_ = conn.Close()
			continue
		}

		_ = conn.SetNoDelay(true)
		_ = conn.SetReadBuffer(natTCPBufSize)
		_ = conn.SetWriteBuffer(natTCPBufSize)

		f := Flow{
			Source:      entry.origSrc,
			Destination: entry.origDst,
			Protocol:    TCP,
		}
		if !s.r.enter(conn, &f) {
			entry.closedAtNano.Store(time.Now().UnixNano())
			s.r.release(conn)
			continue
		}

		go func(c *net.TCPConn, fl Flow, ent *tcpNATEntry) {
			defer func() {
				ent.closedAtNano.Store(time.Now().UnixNano())
				s.r.release(c)
			}()
			_ = s.r.cfg.Ingress.HandleTCP(s.r.ctx, fl, c)
		}(conn, f, entry)
	}
}
