// Kat UDP return packet encoder. Uses only IP/UDP public wire formats.
// Large datagrams are fragmented to the existing 1420 MTU (not truncated).
package tunstack

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

func sum16(b []byte) uint32 {
	var s uint32
	for len(b) >= 2 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		s += uint32(b[0]) << 8
	}
	return s
}
func folded(s uint32) uint16 {
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	return ^uint16(s)
}
func UDPReply(src, dst netip.AddrPort, payload []byte, id uint32) ([][]byte, error) {
	if !src.IsValid() || !dst.IsValid() || src.Port() == 0 || dst.Port() == 0 || src.Addr().Is4() != dst.Addr().Is4() || src.Addr().Zone() != "" || dst.Addr().Zone() != "" || src.Addr().IsUnspecified() || dst.Addr().IsUnspecified() {
		return nil, errors.New("TUN_UDP_INVALID_PEER")
	}
	max := 65527
	if src.Addr().Is4() {
		max = 65507
	}
	if len(payload) > max {
		return nil, errors.New("TUN_UDP_MESSAGE_TOO_LARGE")
	}
	udpLen := 8 + len(payload)
	if src.Addr().Is4() {
		a, b := src.Addr().As4(), dst.Addr().As4()
		pseudoSum := uint32(binary.BigEndian.Uint16(a[0:2])) +
			uint32(binary.BigEndian.Uint16(a[2:4])) +
			uint32(binary.BigEndian.Uint16(b[0:2])) +
			uint32(binary.BigEndian.Uint16(b[2:4])) +
			17 + uint32(udpLen)
		// Fast path: unfragmented IPv4 UDP packet built in a single allocation.
		if udpLen <= MTU-20 {
			p := make([]byte, 20+udpLen)
			p[0] = 0x45
			p[8] = 64
			p[9] = 17
			binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
			binary.BigEndian.PutUint16(p[4:6], uint16(id))
			copy(p[12:16], a[:])
			copy(p[16:20], b[:])
			binary.BigEndian.PutUint16(p[10:12], folded(sum16(p[:20])))

			u := p[20:]
			binary.BigEndian.PutUint16(u[0:2], src.Port())
			binary.BigEndian.PutUint16(u[2:4], dst.Port())
			binary.BigEndian.PutUint16(u[4:6], uint16(udpLen))
			copy(u[8:], payload)
			csum := folded(pseudoSum + sum16(u))
			if csum == 0 {
				csum = 65535
			}
			binary.BigEndian.PutUint16(u[6:8], csum)
			return [][]byte{p}, nil
		}
		udp := make([]byte, udpLen)
		binary.BigEndian.PutUint16(udp[0:2], src.Port())
		binary.BigEndian.PutUint16(udp[2:4], dst.Port())
		binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
		copy(udp[8:], payload)
		csum := folded(pseudoSum + sum16(udp))
		if csum == 0 {
			csum = 65535
		}
		binary.BigEndian.PutUint16(udp[6:8], csum)
		out := make([][]byte, 0, (udpLen+(MTU-20)-1)/(MTU-20))
		for off := 0; off < len(udp); {
			n := len(udp) - off
			if n > MTU-20 {
				n = (MTU - 20) &^ 7
			}
			p := make([]byte, 20+n)
			p[0] = 0x45
			p[8] = 64
			p[9] = 17
			binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
			binary.BigEndian.PutUint16(p[4:6], uint16(id))
			frag := uint16(off / 8)
			if off+n < len(udp) {
				frag |= 0x2000
			}
			binary.BigEndian.PutUint16(p[6:8], frag)
			copy(p[12:16], a[:])
			copy(p[16:20], b[:])
			binary.BigEndian.PutUint16(p[10:12], folded(sum16(p[:20])))
			copy(p[20:], udp[off:off+n])
			out = append(out, p)
			off += n
		}
		return out, nil
	}

	a, b := src.Addr().As16(), dst.Addr().As16()
	pseudoSum := sum16(a[:]) + sum16(b[:]) + uint32(udpLen>>16) + uint32(udpLen&0xffff) + 17
	if udpLen+40 <= MTU {
		p := make([]byte, 40+udpLen)
		p[0] = 0x60
		p[6] = 17
		p[7] = 64
		binary.BigEndian.PutUint16(p[4:6], uint16(udpLen))
		copy(p[8:24], a[:])
		copy(p[24:40], b[:])

		u := p[40:]
		binary.BigEndian.PutUint16(u[0:2], src.Port())
		binary.BigEndian.PutUint16(u[2:4], dst.Port())
		binary.BigEndian.PutUint16(u[4:6], uint16(udpLen))
		copy(u[8:], payload)
		csum := folded(pseudoSum + sum16(u))
		if csum == 0 {
			csum = 65535
		}
		binary.BigEndian.PutUint16(u[6:8], csum)
		return [][]byte{p}, nil
	}
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], src.Port())
	binary.BigEndian.PutUint16(udp[2:4], dst.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	csum := folded(pseudoSum + sum16(udp))
	if csum == 0 {
		csum = 65535
	}
	binary.BigEndian.PutUint16(udp[6:8], csum)
	var out [][]byte
	for off := 0; off < len(udp); {
		hdr := 48
		n := len(udp) - off
		if n > MTU-hdr {
			n = (MTU - hdr) &^ 7
		}
		p := make([]byte, hdr+n)
		p[0] = 0x60
		p[6] = 44
		p[7] = 64
		binary.BigEndian.PutUint16(p[4:6], uint16(len(p)-40))
		copy(p[8:24], a[:])
		copy(p[24:40], b[:])
		p[40] = 17
		bits := uint16(off) & 0xfff8
		if off+n < len(udp) {
			bits |= 1
		}
		binary.BigEndian.PutUint16(p[42:44], bits)
		binary.BigEndian.PutUint32(p[44:48], id)
		copy(p[hdr:], udp[off:off+n])
		out = append(out, p)
		off += n
	}
	return out, nil
}
