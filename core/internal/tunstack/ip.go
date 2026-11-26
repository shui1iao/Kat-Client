// Package tunstack implements Kat's zero-gVisor System Stack for TUN devices:
// L3 IPv4/IPv6 parsing, bounded fragment reassembly, RFC 1624 O(1) incremental
// checksum updates, and native OS TCP NAT termination.
package tunstack

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

const (
	ipProtoICMPv4 = 1
	ipProtoTCP    = 6
	ipProtoUDP    = 17
	ipProtoICMPv6 = 58

	ipv6NextHopByHop = 0
	ipv6NextRouting  = 43
	ipv6NextFragment = 44
	ipv6NextDestOpts = 60

	maxReasmEntries = 256
	maxReasmBytes   = 4 << 20
	reasmTimeout    = 15 * time.Second
)

// ipPacket is a zero-allocation view over a raw L3 IPv4 or IPv6 packet.
type ipPacket struct {
	ver      uint8
	proto    uint8
	ttl      uint8
	tos      uint8
	df       bool
	hdrLen   int
	totalLen int
	src      netip.Addr
	dst      netip.Addr
	raw      []byte // full IP packet [:totalLen]
	payload  []byte // transport header + payload
}

// ipFragMeta describes an IPv4 or IPv6 fragment awaiting reassembly.
type ipFragMeta struct {
	v6      bool
	id      uint32
	proto   uint8
	offset  int
	more    bool
	ttl     uint8
	tos     uint8
	df      bool
	src     netip.Addr
	dst     netip.Addr
	hdr     []byte // unfragmentable IP header prefix (for IPv4: header[:ihl]; for IPv6: base 40B)
	payload []byte
}

func parseIPPacket(raw []byte) (pkt ipPacket, frag *ipFragMeta, ok bool) {
	if len(raw) < 20 {
		return pkt, nil, false
	}
	ver := raw[0] >> 4
	if ver == 4 {
		ihl := int(raw[0]&0x0f) * 4
		if ihl < 20 || len(raw) < ihl {
			return pkt, nil, false
		}
		totalLen := int(binary.BigEndian.Uint16(raw[2:4]))
		if totalLen < ihl || totalLen > len(raw) {
			return pkt, nil, false
		}
		if folded(sum16(raw[:ihl])) != 0 {
			return pkt, nil, false
		}
		flagsFrag := binary.BigEndian.Uint16(raw[6:8])
		more := (flagsFrag & 0x2000) != 0
		fragOff := int(flagsFrag&0x1fff) * 8
		src := netip.AddrFrom4([4]byte(raw[12:16]))
		dst := netip.AddrFrom4([4]byte(raw[16:20]))
		if more || fragOff > 0 {
			return pkt, &ipFragMeta{
				v6:      false,
				id:      uint32(binary.BigEndian.Uint16(raw[4:6])),
				proto:   raw[9],
				offset:  fragOff,
				more:    more,
				ttl:     raw[8],
				tos:     raw[1],
				df:      (flagsFrag & 0x4000) != 0,
				src:     src,
				dst:     dst,
				hdr:     raw[:ihl],
				payload: raw[ihl:totalLen],
			}, true
		}
		pkt = ipPacket{
			ver:      4,
			proto:    raw[9],
			ttl:      raw[8],
			tos:      raw[1],
			df:       (flagsFrag & 0x4000) != 0,
			hdrLen:   ihl,
			totalLen: totalLen,
			src:      src,
			dst:      dst,
			raw:      raw[:totalLen],
			payload:  raw[ihl:totalLen],
		}
		return pkt, nil, true
	}

	if ver == 6 {
		if len(raw) < 40 {
			return pkt, nil, false
		}
		payLen := int(binary.BigEndian.Uint16(raw[4:6]))
		totalLen := 40 + payLen
		if totalLen > len(raw) {
			return pkt, nil, false
		}
		next := raw[6]
		off := 40
		src := netip.AddrFrom16([16]byte(raw[8:24]))
		dst := netip.AddrFrom16([16]byte(raw[24:40]))
		for hops := 0; hops < 8; hops++ {
			switch next {
			case ipv6NextHopByHop, ipv6NextRouting, ipv6NextDestOpts:
				if off+2 > totalLen {
					return pkt, nil, false
				}
				extLen := (int(raw[off+1]) + 1) * 8
				if off+extLen > totalLen {
					return pkt, nil, false
				}
				next = raw[off]
				off += extLen
			case ipv6NextFragment:
				if off+8 > totalLen {
					return pkt, nil, false
				}
				fragNext := raw[off]
				offFlags := binary.BigEndian.Uint16(raw[off+2 : off+4])
				fragOff := int(offFlags & 0xfff8)
				more := (offFlags & 1) != 0
				fragID := binary.BigEndian.Uint32(raw[off+4 : off+8])
				off += 8
				if more || fragOff > 0 {
					return pkt, &ipFragMeta{
						v6:      true,
						id:      fragID,
						proto:   fragNext,
						offset:  fragOff,
						more:    more,
						ttl:     raw[7],
						src:     src,
						dst:     dst,
						hdr:     raw[:40],
						payload: raw[off:totalLen],
					}, true
				}
				// Atomic IPv6 fragment (offset=0, M=0): continue with inner protocol.
				next = fragNext
			default:
				pkt = ipPacket{
					ver:      6,
					proto:    next,
					ttl:      raw[7],
					tos:      uint8((uint16(raw[0]&0x0f) << 4) | uint16(raw[1]>>4)),
					hdrLen:   off,
					totalLen: totalLen,
					src:      src,
					dst:      dst,
					raw:      raw[:totalLen],
					payload:  raw[off:totalLen],
				}
				return pkt, nil, true
			}
		}
	}
	return pkt, nil, false
}

// RFC 1624 O(1) incremental checksum update (complement arithmetic).
// csum is the existing 16-bit one's complement checksum in host uint16 order
// (as read via binary.BigEndian.Uint16).
func csumAddDelta(csum uint16, oldSum, newSum uint32) uint16 {
	// RFC 1624 Eq. 3: HC' = ~(~HC + ~m + m')
	hc := uint32(^csum)
	// Fold oldSum and newSum into 16 bits.
	for oldSum>>16 != 0 {
		oldSum = (oldSum & 0xffff) + (oldSum >> 16)
	}
	for newSum>>16 != 0 {
		newSum = (newSum & 0xffff) + (newSum >> 16)
	}
	sum := hc + uint32(^uint16(oldSum)) + newSum
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func addr4Sum(a [4]byte) uint32 {
	return uint32(binary.BigEndian.Uint16(a[0:2])) + uint32(binary.BigEndian.Uint16(a[2:4]))
}

func addr6Sum(a [16]byte) uint32 {
	return sum16(a[:])
}

func verifyUDPChecksum(pkt ipPacket) bool {
	if len(pkt.payload) < 8 {
		return false
	}
	udpLen := int(binary.BigEndian.Uint16(pkt.payload[4:6]))
	if udpLen < 8 || udpLen != len(pkt.payload) {
		return false
	}
	csum := binary.BigEndian.Uint16(pkt.payload[6:8])
	if pkt.ver == 4 {
		if csum == 0 {
			// RFC 768: 0 means checksum disabled on IPv4.
			return true
		}
		a, b := pkt.src.As4(), pkt.dst.As4()
		pseudo := addr4Sum(a) + addr4Sum(b) + ipProtoUDP + uint32(udpLen)
		return folded(pseudo+sum16(pkt.payload)) == 0
	}
	// RFC 8200: IPv6 UDP checksum MUST NOT be zero.
	if csum == 0 {
		return false
	}
	a, b := pkt.src.As16(), pkt.dst.As16()
	pseudo := addr6Sum(a) + addr6Sum(b) + uint32(udpLen>>16) + uint32(udpLen&0xffff) + ipProtoUDP
	return folded(pseudo+sum16(pkt.payload)) == 0
}

func verifyICMP4Checksum(payload []byte) bool {
	return folded(sum16(payload)) == 0
}

func verifyICMP6Checksum(src, dst netip.Addr, payload []byte) bool {
	a, b := src.As16(), dst.As16()
	n := uint32(len(payload))
	pseudo := addr6Sum(a) + addr6Sum(b) + (n >> 16) + (n & 0xffff) + ipProtoICMPv6
	return folded(pseudo+sum16(payload)) == 0
}

// buildTCPRST synthesizes a standard IPv4 or IPv6 TCP RST packet in response
// to an unadmitted inbound TCP packet (typically SYN during Quiesce/pause).
func buildTCPRST(pkt ipPacket, pktID uint32) ([]byte, bool) {
	if len(pkt.payload) < 20 {
		return nil, false
	}
	flags := pkt.payload[13]
	if flags&0x04 != 0 {
		// Never send RST in response to RST.
		return nil, false
	}
	srcPort := binary.BigEndian.Uint16(pkt.payload[0:2])
	dstPort := binary.BigEndian.Uint16(pkt.payload[2:4])
	seq := binary.BigEndian.Uint32(pkt.payload[4:8])
	ack := binary.BigEndian.Uint32(pkt.payload[8:12])
	dataOff := int(pkt.payload[12]>>4) * 4
	if dataOff < 20 || dataOff > len(pkt.payload) {
		return nil, false
	}
	segLen := uint32(len(pkt.payload) - dataOff)
	if flags&0x02 != 0 {
		segLen++ // SYN consumes 1 seq
	}
	if flags&0x01 != 0 {
		segLen++ // FIN consumes 1 seq
	}

	var outSeq, outAck uint32
	var outFlags byte
	if flags&0x10 != 0 {
		// Incoming ACK set: RST with SEQ = incoming ACK.
		outSeq = ack
		outFlags = 0x04 // RST
	} else {
		// Incoming ACK not set (e.g. SYN): RST+ACK with ACK = incoming SEQ + segLen.
		outSeq = 0
		outAck = seq + segLen
		outFlags = 0x14 // RST|ACK
	}

	if pkt.ver == 4 {
		p := make([]byte, 40)
		p[0] = 0x45
		binary.BigEndian.PutUint16(p[2:4], 40)
		binary.BigEndian.PutUint16(p[4:6], uint16(pktID))
		p[6] = 0x40 // DF
		p[8] = 64
		p[9] = ipProtoTCP
		a, b := pkt.dst.As4(), pkt.src.As4()
		copy(p[12:16], a[:])
		copy(p[16:20], b[:])
		binary.BigEndian.PutUint16(p[10:12], folded(sum16(p[:20])))

		t := p[20:]
		binary.BigEndian.PutUint16(t[0:2], dstPort)
		binary.BigEndian.PutUint16(t[2:4], srcPort)
		binary.BigEndian.PutUint32(t[4:8], outSeq)
		binary.BigEndian.PutUint32(t[8:12], outAck)
		t[12] = 0x50 // 20B TCP header
		t[13] = outFlags
		pseudo := addr4Sum(a) + addr4Sum(b) + ipProtoTCP + 20
		binary.BigEndian.PutUint16(t[16:18], folded(pseudo+sum16(t)))
		return p, true
	}

	if pkt.ver == 6 {
		p := make([]byte, 60)
		p[0] = 0x60
		binary.BigEndian.PutUint16(p[4:6], 20)
		p[6] = ipProtoTCP
		p[7] = 64
		a, b := pkt.dst.As16(), pkt.src.As16()
		copy(p[8:24], a[:])
		copy(p[24:40], b[:])

		t := p[40:]
		binary.BigEndian.PutUint16(t[0:2], dstPort)
		binary.BigEndian.PutUint16(t[2:4], srcPort)
		binary.BigEndian.PutUint32(t[4:8], outSeq)
		binary.BigEndian.PutUint32(t[8:12], outAck)
		t[12] = 0x50
		t[13] = outFlags
		pseudo := addr6Sum(a) + addr6Sum(b) + 20 + ipProtoTCP
		binary.BigEndian.PutUint16(t[16:18], folded(pseudo+sum16(t)))
		return p, true
	}
	return nil, false
}

// Bounded IPv4/IPv6 fragment reassembler for inbound fragmented UDP/ICMP packets.
type reasmKey struct {
	src   netip.Addr
	dst   netip.Addr
	id    uint32
	proto uint8
	v6    bool
}

type reasmHole struct {
	start int
	end   int
}

type reasmEntry struct {
	created   time.Time
	v6        bool
	proto     uint8
	ttl       uint8
	tos       uint8
	df        bool
	src       netip.Addr
	dst       netip.Addr
	firstHdr  []byte
	buf       []byte
	gotLast   bool
	finalLen  int
	holes     []reasmHole
	storedLen int
}

type ipReassembler struct {
	mu         sync.Mutex
	entries    map[reasmKey]*reasmEntry
	totalBytes int
}

func newIPReassembler() *ipReassembler {
	return &ipReassembler{entries: make(map[reasmKey]*reasmEntry)}
}

func (ra *ipReassembler) gcLocked(now time.Time) {
	for k, e := range ra.entries {
		if now.Sub(e.created) > reasmTimeout {
			ra.totalBytes -= e.storedLen
			delete(ra.entries, k)
		}
	}
}

func (ra *ipReassembler) push(f *ipFragMeta) (ipPacket, bool) {
	if f == nil || len(f.payload) == 0 {
		return ipPacket{}, false
	}
	end := f.offset + len(f.payload)
	if f.offset < 0 || end > 65535 || (f.more && len(f.payload)%8 != 0) {
		return ipPacket{}, false
	}

	ra.mu.Lock()
	defer ra.mu.Unlock()
	now := time.Now()
	if len(ra.entries) >= maxReasmEntries || ra.totalBytes+len(f.payload) > maxReasmBytes {
		ra.gcLocked(now)
	}

	key := reasmKey{src: f.src, dst: f.dst, id: f.id, proto: f.proto, v6: f.v6}
	e := ra.entries[key]
	if e == nil {
		if len(ra.entries) >= maxReasmEntries || ra.totalBytes+end > maxReasmBytes {
			return ipPacket{}, false
		}
		e = &reasmEntry{
			created: now,
			v6:      f.v6,
			proto:   f.proto,
			ttl:     f.ttl,
			tos:     f.tos,
			df:      f.df,
			src:     f.src,
			dst:     f.dst,
			holes:   []reasmHole{{start: 0, end: 65535}},
		}
		ra.entries[key] = e
	}

	if f.offset == 0 && len(e.firstHdr) == 0 {
		e.firstHdr = append([]byte(nil), f.hdr...)
		e.ttl = f.ttl
		e.tos = f.tos
		e.df = f.df
	}
	if end > len(e.buf) {
		growth := end - len(e.buf)
		if ra.totalBytes+growth > maxReasmBytes {
			ra.totalBytes -= e.storedLen
			delete(ra.entries, key)
			return ipPacket{}, false
		}
		nb := make([]byte, end)
		copy(nb, e.buf)
		e.buf = nb
		e.storedLen = len(e.buf)
		ra.totalBytes += growth
	}
	copy(e.buf[f.offset:end], f.payload)

	if !f.more {
		if e.gotLast && e.finalLen != end {
			ra.totalBytes -= e.storedLen
			delete(ra.entries, key)
			return ipPacket{}, false
		}
		e.gotLast = true
		e.finalLen = end
		// Trim trailing hole to finalLen.
		var trimmed []reasmHole
		for _, h := range e.holes {
			if h.start >= end {
				continue
			}
			if h.end > end {
				h.end = end
			}
			trimmed = append(trimmed, h)
		}
		e.holes = trimmed
	}

	// Carve [f.offset, end) out of holes (RFC 815).
	var nextHoles []reasmHole
	for _, h := range e.holes {
		if f.offset >= h.end || end <= h.start {
			nextHoles = append(nextHoles, h)
			continue
		}
		if f.offset > h.start {
			nextHoles = append(nextHoles, reasmHole{start: h.start, end: f.offset})
		}
		if end < h.end {
			nextHoles = append(nextHoles, reasmHole{start: end, end: h.end})
		}
	}
	e.holes = nextHoles

	if !e.gotLast || len(e.holes) != 0 || len(e.firstHdr) == 0 {
		return ipPacket{}, false
	}

	// Complete! Remove entry and assemble contiguous logical IP packet.
	ra.totalBytes -= e.storedLen
	delete(ra.entries, key)

	payload := e.buf[:e.finalLen]
	hdrLen := len(e.firstHdr)
	if !e.v6 {
		if hdrLen+len(payload) > 65535 {
			return ipPacket{}, false
		}
		full := make([]byte, hdrLen+len(payload))
		copy(full, e.firstHdr)
		copy(full[hdrLen:], payload)
		binary.BigEndian.PutUint16(full[2:4], uint16(len(full)))
		flags := uint16(0)
		if e.df {
			flags = 0x4000
		}
		binary.BigEndian.PutUint16(full[6:8], flags)
		binary.BigEndian.PutUint16(full[10:12], 0)
		binary.BigEndian.PutUint16(full[10:12], folded(sum16(full[:hdrLen])))
		return ipPacket{
			ver:      4,
			proto:    e.proto,
			ttl:      e.ttl,
			tos:      e.tos,
			df:       e.df,
			hdrLen:   hdrLen,
			totalLen: len(full),
			src:      e.src,
			dst:      e.dst,
			raw:      full,
			payload:  full[hdrLen:],
		}, true
	}

	if len(payload) > 65535 {
		return ipPacket{}, false
	}
	full := make([]byte, 40+len(payload))
	copy(full[:40], e.firstHdr[:40])
	copy(full[40:], payload)
	binary.BigEndian.PutUint16(full[4:6], uint16(len(payload)))
	full[6] = e.proto
	return ipPacket{
		ver:      6,
		proto:    e.proto,
		ttl:      e.ttl,
		tos:      e.tos,
		hdrLen:   40,
		totalLen: len(full),
		src:      e.src,
		dst:      e.dst,
		raw:      full,
		payload:  full[40:],
	}, true
}
