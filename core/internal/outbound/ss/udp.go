package ss

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/shui1iao/Kat/internal/outbound"
)

const (
	maxDatagram    = 65535
	udpWirePoolCap = 2048
)

var udpWirePool = sync.Pool{
	New: func() any {
		b := make([]byte, udpWirePoolCap)
		return &b
	},
}

func acquireUDPWire(n int) ([]byte, *[]byte) {
	if n <= udpWirePoolCap {
		bp := udpWirePool.Get().(*[]byte)
		return (*bp)[:n], bp
	}
	return make([]byte, n), nil
}

func releaseUDPWire(bp *[]byte) {
	if bp != nil {
		udpWirePool.Put(bp)
	}
}

func newXChaCha(key []byte) (cipher.AEAD, error)   { return chacha20poly1305.NewX(key) }
func newAESBlock(key []byte) (cipher.Block, error) { return aes.NewCipher(key) }

// ListenPacket opens a native Shadowsocks UDP association through
// under.ListenPacket. It requires UDP() (configured and supported by under).
func (s *Outbound) ListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	if !s.UDP() {
		return nil, outbound.ErrUDPUnsupported
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	p := &udpConn{s: s}
	if s.m.v2022 {
		var id [8]byte
		if _, e := rand.Read(id[:]); e != nil {
			return nil, e
		}
		p.session = binary.BigEndian.Uint64(id[:])
		if !s.m.chacha {
			a, e := sessionAEAD(s.m, s.key, id[:])
			if e != nil {
				return nil, e
			}
			p.sessionAEAD = a
		}
	}
	pc, e := s.under.ListenPacket(ctx)
	if e != nil {
		return nil, e
	}
	p.pc = pc
	return p, nil
}

type udpConn struct {
	s  *Outbound
	pc outbound.PacketConn

	// SS2022 client session (immutable after ListenPacket).
	session     uint64
	sessionAEAD cipher.AEAD

	wmu      sync.Mutex
	packetID uint64
	wdead    bool

	// Reader state (one concurrent reader).
	rbuf        []byte
	servers     [2]*serverSession // [0] current, [1] previous
	lastSrcIP4  [4]byte
	lastSrcStr  string
	lastSrcInit bool
}

// serverSession is one SIP022 server session observed on this association.
type serverSession struct {
	id     uint64
	aead   cipher.AEAD // AES variants only
	window window
}

func (p *udpConn) WriteTo(b []byte, dst outbound.Addr) (int, error) {
	var addrBuf [259]byte
	addr, e := appendAddr(addrBuf[:0], dst)
	if e != nil {
		return 0, e
	}
	var wire []byte
	var wireBP *[]byte
	if p.s.m.v2022 {
		wire, wireBP, e = p.encode2022Pooled(addr, b)
	} else {
		wire, e = p.encode2017(addr, b)
	}
	if e != nil {
		releaseUDPWire(wireBP)
		return 0, e
	}
	_, e = p.pc.WriteTo(wire, p.s.server)
	releaseUDPWire(wireBP)
	if e != nil {
		return 0, e
	}
	return len(b), nil
}

func (p *udpConn) encode2017(addr, payload []byte) ([]byte, error) {
	m := p.s.m
	if m.keySize+len(addr)+len(payload)+tagSize > maxDatagram {
		return nil, errTooLarge
	}
	wire := make([]byte, m.keySize, m.keySize+len(addr)+len(payload)+tagSize)
	if _, e := rand.Read(wire); e != nil {
		return nil, e
	}
	a, e := sessionAEAD(m, p.s.key, wire)
	if e != nil {
		return nil, e
	}
	body := append(append(make([]byte, 0, len(addr)+len(payload)), addr...), payload...)
	var zero [12]byte
	return a.Seal(wire, zero[:], body, nil), nil
}

func (p *udpConn) encode2022Pooled(addr, payload []byte) ([]byte, *[]byte, error) {
	m := p.s.m
	overhead := 16 + tagSize
	if m.chacha {
		overhead = 24 + 16 + tagSize
	}
	bodyLen := 11 + len(addr) + len(payload)
	totalLen := overhead + bodyLen
	if totalLen > maxDatagram {
		return nil, nil, errTooLarge
	}
	now := p.s.now().Unix()
	if now < 0 {
		return nil, nil, errTime
	}
	p.wmu.Lock()
	if p.wdead {
		p.wmu.Unlock()
		return nil, nil, errExhaust
	}
	id := p.packetID
	p.packetID++
	p.wdead = p.packetID == 0
	p.wmu.Unlock()

	var header [16]byte
	binary.BigEndian.PutUint64(header[:8], p.session)
	binary.BigEndian.PutUint64(header[8:], id)

	wire, bp := acquireUDPWire(totalLen)
	if m.chacha {
		if _, e := rand.Read(wire[:24]); e != nil {
			releaseUDPWire(bp)
			return nil, nil, e
		}
		plain := wire[24 : 24+16+bodyLen]
		copy(plain[:16], header[:])
		plain[16] = 0
		binary.BigEndian.PutUint64(plain[17:25], uint64(now))
		plain[25] = 0
		plain[26] = 0
		copy(plain[27:], addr)
		copy(plain[27+len(addr):], payload)
		return p.s.udpX.Seal(wire[:24], wire[:24], plain, nil), bp, nil
	}
	p.s.udpBlock.Encrypt(wire[:16], header[:])
	plain := wire[16 : 16+bodyLen]
	plain[0] = 0
	binary.BigEndian.PutUint64(plain[1:9], uint64(now))
	plain[9] = 0
	plain[10] = 0
	copy(plain[11:], addr)
	copy(plain[11+len(addr):], payload)
	return p.sessionAEAD.Seal(wire[:16], header[4:16], plain, nil), bp, nil
}

func (p *udpConn) ReadFrom(b []byte) (int, outbound.Addr, error) {
	if p.rbuf == nil {
		p.rbuf = make([]byte, maxDatagram)
	}
	for {
		n, _, e := p.pc.ReadFrom(p.rbuf)
		if e != nil {
			return 0, outbound.Addr{}, e
		}
		var src outbound.Addr
		var payload []byte
		if p.s.m.v2022 {
			src, payload, e = p.decode2022(p.rbuf[:n])
		} else {
			src, payload, e = p.decode2017(p.rbuf[:n])
		}
		if e != nil {
			continue // unauthenticated, replayed, stale or foreign: drop
		}
		return copy(b, payload), src, nil
	}
}

func (p *udpConn) decode2017(wire []byte) (outbound.Addr, []byte, error) {
	m := p.s.m
	if len(wire) < m.keySize+tagSize+7 {
		return outbound.Addr{}, nil, errFormat
	}
	a, e := sessionAEAD(m, p.s.key, wire[:m.keySize])
	if e != nil {
		return outbound.Addr{}, nil, e
	}
	var zero [12]byte
	plain, e := a.Open(wire[m.keySize:m.keySize], zero[:], wire[m.keySize:], nil)
	if e != nil {
		return outbound.Addr{}, nil, errAuth
	}
	src, k, e := parseAddr(plain)
	if e != nil {
		return outbound.Addr{}, nil, e
	}
	return src, plain[k:], nil
}

func (p *udpConn) decode2022(wire []byte) (outbound.Addr, []byte, error) {
	m := p.s.m
	var serverID, packetID uint64
	var plain []byte
	var sess *serverSession
	if m.chacha {
		if len(wire) < 24+16+19+7+tagSize {
			return outbound.Addr{}, nil, errFormat
		}
		var e error
		plain, e = p.s.udpX.Open(wire[24:24], wire[:24], wire[24:], nil)
		if e != nil {
			return outbound.Addr{}, nil, errAuth
		}
		serverID = binary.BigEndian.Uint64(plain[:8])
		packetID = binary.BigEndian.Uint64(plain[8:16])
		plain = plain[16:]
		sess = p.lookup(serverID)
		if sess == nil {
			sess = &serverSession{id: serverID}
		}
	} else {
		if len(wire) < 16+19+7+tagSize {
			return outbound.Addr{}, nil, errFormat
		}
		var header [16]byte
		p.s.udpBlock.Decrypt(header[:], wire[:16])
		serverID = binary.BigEndian.Uint64(header[:8])
		packetID = binary.BigEndian.Uint64(header[8:])
		sess = p.lookup(serverID)
		if sess == nil {
			a, e := sessionAEAD(m, p.s.key, header[:8])
			if e != nil {
				return outbound.Addr{}, nil, e
			}
			sess = &serverSession{id: serverID, aead: a}
		}
		var e error
		plain, e = sess.aead.Open(wire[16:16], header[4:16], wire[16:], nil)
		if e != nil {
			return outbound.Addr{}, nil, errAuth
		}
	}
	// type(1) timestamp(8) client session ID(8) padding length(2)
	if len(plain) < 19 || plain[0] != 1 {
		return outbound.Addr{}, nil, errFormat
	}
	if !checkTime(binary.BigEndian.Uint64(plain[1:9]), p.s.now()) {
		return outbound.Addr{}, nil, errTime
	}
	if binary.BigEndian.Uint64(plain[9:17]) != p.session {
		return outbound.Addr{}, nil, errFormat
	}
	start := 19 + int(binary.BigEndian.Uint16(plain[17:19]))
	if start > len(plain) {
		return outbound.Addr{}, nil, errFormat
	}
	var src outbound.Addr
	var k int
	var e error
	rem := plain[start:]
	if len(rem) >= 7 && rem[0] == 1 {
		var ip4 [4]byte
		copy(ip4[:], rem[1:5])
		if !p.lastSrcInit || ip4 != p.lastSrcIP4 {
			p.lastSrcIP4 = ip4
			p.lastSrcStr = netip.AddrFrom4(ip4).String()
			p.lastSrcInit = true
		}
		src = outbound.Addr{Host: p.lastSrcStr, Port: binary.BigEndian.Uint16(rem[5:7])}
		k = 7
	} else {
		src, k, e = parseAddr(rem)
		if e != nil {
			return outbound.Addr{}, nil, e
		}
	}
	if !sess.window.accept(packetID) {
		return outbound.Addr{}, nil, errFormat
	}
	p.remember(sess)
	return src, plain[start+k:], nil
}

func (p *udpConn) lookup(id uint64) *serverSession {
	for _, s := range p.servers {
		if s != nil && s.id == id {
			return s
		}
	}
	return nil
}

// remember makes an authenticated server session current; a different
// session (server restart/rotation) demotes the old current one.
func (p *udpConn) remember(s *serverSession) {
	if p.servers[0] == s {
		return
	}
	if p.servers[1] == s {
		p.servers[0], p.servers[1] = s, p.servers[0]
		return
	}
	p.servers[1], p.servers[0] = p.servers[0], s
}

func (p *udpConn) Close() error                       { return p.pc.Close() }
func (p *udpConn) SetReadDeadline(t time.Time) error  { return p.pc.SetReadDeadline(t) }
func (p *udpConn) SetWriteDeadline(t time.Time) error { return p.pc.SetWriteDeadline(t) }

// window is a 1024-packet sliding replay window. Bit d records max-d.
type window struct {
	seen bool
	max  uint64
	bits [16]uint64
}

func (w *window) has(d uint64) bool { return w.bits[d/64]&(1<<(d%64)) != 0 }
func (w *window) set(d uint64)      { w.bits[d/64] |= 1 << (d % 64) }

func (w *window) accept(id uint64) bool {
	const size = 1024
	if !w.seen {
		w.seen, w.max = true, id
		w.set(0)
		return true
	}
	if id > w.max {
		shift := id - w.max
		if shift >= size {
			w.bits = [16]uint64{}
		} else {
			var nb [16]uint64
			ws := int(shift / 64)
			bs := shift % 64
			if bs == 0 {
				for i := 0; i+ws < 16; i++ {
					nb[i+ws] = w.bits[i]
				}
			} else {
				rbs := 64 - bs
				for i := 0; i+ws < 16; i++ {
					v := w.bits[i]
					if v == 0 {
						continue
					}
					nb[i+ws] |= v << bs
					if i+ws+1 < 16 {
						nb[i+ws+1] |= v >> rbs
					}
				}
			}
			w.bits = nb
		}
		w.max = id
		w.set(0)
		return true
	}
	d := w.max - id
	if d >= size || w.has(d) {
		return false
	}
	w.set(d)
	return true
}

func (p *udpConn) WriteBatch(payloads [][]byte, dst outbound.Addr) (int, error) {
	if len(payloads) == 0 {
		return 0, nil
	}
	if len(payloads) == 1 {
		if _, err := p.WriteTo(payloads[0], dst); err != nil {
			return 0, err
		}
		return 1, nil
	}
	bw, ok := p.pc.(outbound.BatchPacketWriter)
	if !ok {
		for i, b := range payloads {
			if _, err := p.WriteTo(b, dst); err != nil {
				return i, err
			}
		}
		return len(payloads), nil
	}
	var addrBuf [259]byte
	addr, e := appendAddr(addrBuf[:0], dst)
	if e != nil {
		return 0, e
	}
	var (
		wires [32][]byte
		bps   [32]*[]byte
	)
	sentTotal := 0
	for sentTotal < len(payloads) {
		chunk := len(payloads) - sentTotal
		if chunk > len(wires) {
			chunk = len(wires)
		}
		encoded := 0
		var encErr error
		for i := 0; i < chunk; i++ {
			var w []byte
			var bp *[]byte
			if p.s.m.v2022 {
				w, bp, encErr = p.encode2022Pooled(addr, payloads[sentTotal+i])
			} else {
				w, encErr = p.encode2017(addr, payloads[sentTotal+i])
			}
			if encErr != nil {
				releaseUDPWire(bp)
				break
			}
			wires[encoded] = w
			bps[encoded] = bp
			encoded++
		}
		if encoded > 0 {
			n, we := bw.WriteBatch(wires[:encoded], p.s.server)
			for i := 0; i < encoded; i++ {
				releaseUDPWire(bps[i])
				bps[i] = nil
				wires[i] = nil
			}
			sentTotal += n
			if we != nil {
				return sentTotal, we
			}
		}
		if encErr != nil {
			return sentTotal, encErr
		}
	}
	return sentTotal, nil
}

func (p *udpConn) ReadBatch(bufs [][]byte, lens []int, srcs []outbound.Addr) (int, error) {
	if len(bufs) == 0 {
		return 0, nil
	}
	br, ok := p.pc.(outbound.BatchPacketReader)
	if !ok {
		n, src, err := p.ReadFrom(bufs[0])
		if err != nil {
			return 0, err
		}
		lens[0] = n
		srcs[0] = src
		return 1, nil
	}
	for {
		cnt, err := br.ReadBatch(bufs, lens, srcs)
		if err != nil {
			return 0, err
		}
		out := 0
		for i := 0; i < cnt; i++ {
			wire := bufs[i][:lens[i]]
			var src outbound.Addr
			var payload []byte
			var de error
			if p.s.m.v2022 {
				src, payload, de = p.decode2022(wire)
			} else {
				src, payload, de = p.decode2017(wire)
			}
			if de != nil {
				continue
			}
			n := copy(bufs[out], payload)
			lens[out] = n
			srcs[out] = src
			out++
		}
		if out > 0 {
			return out, nil
		}
	}
}
