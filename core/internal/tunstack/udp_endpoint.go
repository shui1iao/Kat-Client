// Kat-owned source-oriented UDP adapter (zero gVisor).
// Validated datagrams are queued by SOURCE+security epoch, never peer.
package tunstack

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

// DatagramConn preserves each real destination and permits EIF return sources.
// WriteFrom builds IP/UDP packets itself; it never relabels a connected endpoint.
type DatagramConn interface {
	net.Conn
	ReadDatagram([]byte) (int, netip.AddrPort, error)
	WriteFrom([]byte, netip.AddrPort) (int, error)
}

type sourceKey struct {
	source netip.AddrPort
	epoch  uint64
}

type udpMessage struct {
	target netip.AddrPort
	data   []byte
}

type sourceConn struct {
	r        *Runtime
	cancel   context.CancelFunc
	key      sourceKey
	first    netip.AddrPort
	mu       sync.Mutex
	queue    chan udpMessage
	closed   chan struct{}
	changed  chan struct{}
	deadline time.Time
	waiters  int
	once     sync.Once
}

const udpQueuedByteLimit = 8 << 20
const udpSourceQueueSize = 512

func (r *Runtime) handleUDP(pkt ipPacket) {
	if len(pkt.payload) < 8 || len(pkt.payload)-8 > 65527 {
		r.dropped.Add(1)
		return
	}
	srcPort := binary.BigEndian.Uint16(pkt.payload[0:2])
	dstPort := binary.BigEndian.Uint16(pkt.payload[2:4])
	if !pkt.src.IsValid() || !pkt.dst.IsValid() || srcPort == 0 || dstPort == 0 {
		r.dropped.Add(1)
		return
	}
	if !verifyUDPChecksum(pkt) {
		r.dropped.Add(1)
		return
	}
	f := Flow{
		Source:      netip.AddrPortFrom(pkt.src, srcPort),
		Destination: netip.AddrPortFrom(pkt.dst, dstPort),
		Protocol:    UDP,
	}
	body := pkt.payload[8:]
	n := len(body)

	// On jumbo virtual TUN interfaces (MTU > UDPMTU), advertise standard Path MTU
	// (UDPMTU=1420) via ICMPv4 Fragmentation Needed (when DF=1) or ICMPv6 Packet
	// Too Big so QUIC/UDP peers converge immediately without blackholing upstream.
	if pkt.totalLen > UDPMTU && pkt.hdrLen >= 20 {
		needPTB := (pkt.ver == 6) || (pkt.ver == 4 && pkt.df)
		if needPTB {
			r.mu.Lock()
			ok := !r.stopping && !r.paused && r.cfg.Admitting() && r.ctx.Err() == nil
			r.mu.Unlock()
			if ok {
				var origData []byte
				if pkt.ver == 6 {
					flat := body
					if len(flat) > 1200 {
						flat = flat[:1200]
					}
					origData = flat
				}
				if reply, built := ICMPPacketTooBig(pkt.raw[:pkt.hdrLen], pkt.payload[:8], origData, uint16(UDPMTU), r.packetID.Add(1)); built {
					r.writeRawPacket(reply)
				}
			}
			r.dropped.Add(1)
			return
		}
	}

	r.mu.Lock()
	if r.stopping || r.paused || !r.cfg.Admitting() || r.ctx.Err() != nil {
		r.dropped.Add(1)
		r.mu.Unlock()
		return
	}
	f.Epoch = r.cfg.Epoch()
	if f.Epoch != r.cfg.Epoch() || !r.cfg.Admitting() {
		r.dropped.Add(1)
		r.mu.Unlock()
		return
	}
	if r.udpQueuedBytes+int64(n) > udpQueuedByteLimit {
		r.dropped.Add(1)
		r.mu.Unlock()
		return
	}
	k := sourceKey{f.Source, f.Epoch}
	c := r.udpSources[k]
	if c == nil {
		if r.pending >= maxHandlers {
			r.dropped.Add(1)
			r.mu.Unlock()
			return
		}
		life, cancel := context.WithCancel(r.ctx)
		c = &sourceConn{
			r:       r,
			cancel:  cancel,
			key:     k,
			first:   f.Destination,
			queue:   make(chan udpMessage, udpSourceQueueSize),
			closed:  make(chan struct{}),
			changed: make(chan struct{}),
		}
		r.udpSources[k] = c
		r.active[c] = struct{}{}
		r.pending++
		r.wg.Add(1)
		if r.udpHandlers == 0 {
			r.udpDrained = make(chan struct{})
		}
		r.udpHandlers++
		go func() { defer r.release(c); _ = r.cfg.Ingress.HandleUDP(life, f, c) }()
	}
	data := append([]byte(nil), body...)
	select {
	case c.queue <- udpMessage{f.Destination, data}:
		r.udpQueuedBytes += int64(n)
	default:
		r.dropped.Add(1)
	}
	r.mu.Unlock()
}

// DatagramCurrent fences a second queue (the kernel sender) as well as DNS.
func (c *sourceConn) DatagramCurrent() bool {
	c.r.mu.Lock()
	defer c.r.mu.Unlock()
	return c.currentLocked()
}

func (c *sourceConn) currentLocked() bool {
	return !c.r.stopping && !c.r.paused && c.r.udpSources[c.key] == c && c.r.cfg.Admitting() && c.r.cfg.Epoch() == c.key.epoch
}

func (c *sourceConn) takeDatagram(b []byte, p udpMessage) (int, netip.AddrPort, error) {
	c.r.mu.Lock()
	c.r.udpQueuedBytes -= int64(len(p.data))
	valid := c.currentLocked()
	c.r.mu.Unlock()
	if !valid {
		c.r.dropped.Add(1)
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	return copy(b, p.data), p.target, nil
}

func (c *sourceConn) ReadDatagram(b []byte) (int, netip.AddrPort, error) {
	// Fast path: check closed/canceled/expired first, then pop any queued packet without allocating a timer.
	select {
	case <-c.closed:
		return 0, netip.AddrPort{}, net.ErrClosed
	case <-c.r.ctx.Done():
		return 0, netip.AddrPort{}, context.Canceled
	default:
	}
	c.mu.Lock()
	deadline := c.deadline
	c.mu.Unlock()
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
	}
	select {
	case p := <-c.queue:
		return c.takeDatagram(b, p)
	default:
	}

	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		c.mu.Lock()
		deadline, changed := c.deadline, c.changed
		c.waiters++
		c.mu.Unlock()

		var tc <-chan time.Time
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				c.mu.Lock()
				c.waiters--
				c.mu.Unlock()
				return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
			}
			if timer == nil {
				timer = time.NewTimer(d)
			} else {
				timer.Reset(d)
			}
			tc = timer.C
		}
		select {
		case <-c.closed:
			c.mu.Lock()
			c.waiters--
			c.mu.Unlock()
			return 0, netip.AddrPort{}, net.ErrClosed
		case <-c.r.ctx.Done():
			c.mu.Lock()
			c.waiters--
			c.mu.Unlock()
			return 0, netip.AddrPort{}, context.Canceled
		case <-changed:
			c.mu.Lock()
			c.waiters--
			c.mu.Unlock()
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-tc:
			c.mu.Lock()
			c.waiters--
			c.mu.Unlock()
			return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
		case p := <-c.queue:
			c.mu.Lock()
			c.waiters--
			c.mu.Unlock()
			return c.takeDatagram(b, p)
		}
	}
}

func (c *sourceConn) Read(b []byte) (int, error)  { n, _, e := c.ReadDatagram(b); return n, e }
func (c *sourceConn) Write(b []byte) (int, error) { return c.WriteFrom(b, c.first) }

func (c *sourceConn) WriteFrom(b []byte, peer netip.AddrPort) (int, error) {
	// Serialize BEFORE encoding: at most one large reply/fragment set is held
	// by the device writer, and admission is rechecked after the wait.
	c.r.writeMu.Lock()
	defer c.r.writeMu.Unlock()
	c.r.mu.Lock()
	valid := c.currentLocked()
	c.r.mu.Unlock()
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	if !valid {
		return 0, net.ErrClosed
	}
	packets, e := UDPReply(peer, c.key.source, b, c.r.packetID.Add(1))
	if e != nil {
		return 0, e
	}
	for _, p := range packets {
		if e = c.r.cfg.Device.WritePacket(p); e != nil {
			if isWintunRingFull(e) {
				c.r.dropped.Add(1)
				return 0, e
			}
			c.r.fatal("TUN_DEVICE_WRITE_FAILED", e)
			return 0, e
		}
	}
	return len(b), nil
}

func (c *sourceConn) Close() error {
	c.once.Do(func() {
		c.r.mu.Lock()
		if c.cancel != nil {
			c.cancel()
		}
		if c.r.udpSources[c.key] == c {
			delete(c.r.udpSources, c.key)
		}
		close(c.closed)
		for {
			select {
			case p := <-c.queue:
				c.r.udpQueuedBytes -= int64(len(p.data))
			default:
				c.r.mu.Unlock()
				return
			}
		}
	})
	return nil
}

func (c *sourceConn) LocalAddr() net.Addr  { return net.UDPAddrFromAddrPort(c.first) }
func (c *sourceConn) RemoteAddr() net.Addr { return net.UDPAddrFromAddrPort(c.key.source) }
func (c *sourceConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	if c.waiters > 0 {
		close(c.changed)
		c.changed = make(chan struct{})
	}
	c.mu.Unlock()
	return nil
}
func (c *sourceConn) SetWriteDeadline(time.Time) error { return nil }
func (c *sourceConn) SetDeadline(t time.Time) error    { return c.SetReadDeadline(t) }
