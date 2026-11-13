// Kat-owned ICMP/ICMPv6 Echo adapter and return packet encoder.
// Non-echo ICMP control messages remain owned by gVisor.
package tunstack

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const maxICMPInFlight = 64

func ICMPReply(src, dst netip.Addr, ident, seq uint16, ttl uint8, payload []byte, id uint32) ([][]byte, error) {
	if !src.IsValid() || !dst.IsValid() || src.Is4() != dst.Is4() || src.Zone() != "" || dst.Zone() != "" || src.IsUnspecified() || dst.IsUnspecified() {
		return nil, errors.New("TUN_ICMP_INVALID_PEER")
	}
	if ttl == 0 {
		ttl = 64
	}
	maxPayload := 65527
	if src.Is4() {
		maxPayload = 65507
	}
	if len(payload) > maxPayload {
		return nil, errors.New("TUN_ICMP_MESSAGE_TOO_LARGE")
	}
	icmpLen := 8 + len(payload)
	if src.Is4() {
		a, b := src.As4(), dst.As4()
		if icmpLen <= MTU-20 {
			p := make([]byte, 20+icmpLen)
			p[0] = 0x45
			p[8] = ttl
			p[9] = 1
			binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
			binary.BigEndian.PutUint16(p[4:6], uint16(id))
			copy(p[12:16], a[:])
			copy(p[16:20], b[:])
			binary.BigEndian.PutUint16(p[10:12], folded(sum16(p[:20])))

			ic := p[20:]
			ic[0] = 0 // Echo Reply
			ic[1] = 0
			binary.BigEndian.PutUint16(ic[4:6], ident)
			binary.BigEndian.PutUint16(ic[6:8], seq)
			copy(ic[8:], payload)
			binary.BigEndian.PutUint16(ic[2:4], folded(sum16(ic)))
			return [][]byte{p}, nil
		}
		ic := make([]byte, icmpLen)
		binary.BigEndian.PutUint16(ic[4:6], ident)
		binary.BigEndian.PutUint16(ic[6:8], seq)
		copy(ic[8:], payload)
		binary.BigEndian.PutUint16(ic[2:4], folded(sum16(ic)))
		out := make([][]byte, 0, (icmpLen+(MTU-20)-1)/(MTU-20))
		for off := 0; off < len(ic); {
			n := len(ic) - off
			if n > MTU-20 {
				n = (MTU - 20) &^ 7
			}
			p := make([]byte, 20+n)
			p[0] = 0x45
			p[8] = ttl
			p[9] = 1
			binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
			binary.BigEndian.PutUint16(p[4:6], uint16(id))
			frag := uint16(off / 8)
			if off+n < len(ic) {
				frag |= 0x2000
			}
			binary.BigEndian.PutUint16(p[6:8], frag)
			copy(p[12:16], a[:])
			copy(p[16:20], b[:])
			binary.BigEndian.PutUint16(p[10:12], folded(sum16(p[:20])))
			copy(p[20:], ic[off:off+n])
			out = append(out, p)
			off += n
		}
		return out, nil
	}

	a, b := src.As16(), dst.As16()
	pseudoSum := sum16(a[:]) + sum16(b[:]) + uint32(icmpLen>>16) + uint32(icmpLen&0xffff) + 58
	if icmpLen+40 <= MTU {
		p := make([]byte, 40+icmpLen)
		p[0] = 0x60
		p[6] = 58
		p[7] = ttl
		binary.BigEndian.PutUint16(p[4:6], uint16(icmpLen))
		copy(p[8:24], a[:])
		copy(p[24:40], b[:])

		ic := p[40:]
		ic[0] = 129 // ICMPv6 Echo Reply
		ic[1] = 0
		binary.BigEndian.PutUint16(ic[4:6], ident)
		binary.BigEndian.PutUint16(ic[6:8], seq)
		copy(ic[8:], payload)
		binary.BigEndian.PutUint16(ic[2:4], folded(pseudoSum+sum16(ic)))
		return [][]byte{p}, nil
	}
	ic := make([]byte, icmpLen)
	ic[0] = 129
	binary.BigEndian.PutUint16(ic[4:6], ident)
	binary.BigEndian.PutUint16(ic[6:8], seq)
	copy(ic[8:], payload)
	binary.BigEndian.PutUint16(ic[2:4], folded(pseudoSum+sum16(ic)))
	var out [][]byte
	for off := 0; off < len(ic); {
		hdr := 48
		n := len(ic) - off
		if n > MTU-hdr {
			n = (MTU - hdr) &^ 7
		}
		p := make([]byte, hdr+n)
		p[0] = 0x60
		p[6] = 44
		p[7] = ttl
		binary.BigEndian.PutUint16(p[4:6], uint16(len(p)-40))
		copy(p[8:24], a[:])
		copy(p[24:40], b[:])
		p[40] = 58
		bits := uint16(off) & 0xfff8
		if off+n < len(ic) {
			bits |= 1
		}
		binary.BigEndian.PutUint16(p[42:44], bits)
		binary.BigEndian.PutUint32(p[44:48], id)
		copy(p[hdr:], ic[off:off+n])
		out = append(out, p)
		off += n
	}
	return out, nil
}

func (r *Runtime) icmpPacket4(_ stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	hdrSlice := pkt.TransportHeader().Slice()
	if len(hdrSlice) < header.ICMPv4MinimumSize {
		return false
	}
	h := header.ICMPv4(hdrSlice)
	if h.Type() != header.ICMPv4Echo {
		return false
	}
	if h.Code() != 0 || folded(sum16(h)+uint32(pkt.Data().Checksum())) != 0 {
		r.dropped.Add(1)
		return true
	}
	n := pkt.Data().Size()
	if n > 65507 || len(pkt.NetworkHeader().Slice()) < header.IPv4MinimumSize {
		r.dropped.Add(1)
		return true
	}
	iph := header.IPv4(pkt.NetworkHeader().Slice())
	src := netip.AddrFrom4(iph.SourceAddress().As4())
	dst := netip.AddrFrom4(iph.DestinationAddress().As4())
	if !src.IsValid() || !dst.IsValid() || src.IsUnspecified() || dst.IsUnspecified() || src.IsMulticast() || dst.IsMulticast() || dst == netip.AddrFrom4([4]byte{255, 255, 255, 255}) || iph.TTL() == 0 {
		r.dropped.Add(1)
		return true
	}
	tos, _ := iph.TOS()
	req := ICMPEchoRequest{
		Source:      src,
		Destination: dst,
		Ident:       h.Ident(),
		Sequence:    h.Sequence(),
		TTL:         iph.TTL(),
		TOS:         tos,
		DF:          (iph.Flags() & header.IPv4FlagDontFragment) != 0,
	}
	r.admitICMP(req, pkt)
	return true
}

func (r *Runtime) icmpPacket6(_ stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	hdrSlice := pkt.TransportHeader().Slice()
	if len(hdrSlice) < header.ICMPv6EchoMinimumSize {
		return false
	}
	h := header.ICMPv6(hdrSlice)
	if h.Type() != header.ICMPv6EchoRequest {
		return false
	}
	nh := pkt.Network()
	n := pkt.Data().Size()
	if h.Code() != 0 || n > 65527 || len(pkt.NetworkHeader().Slice()) < header.IPv6MinimumSize {
		r.dropped.Add(1)
		return true
	}
	if header.ICMPv6Checksum(header.ICMPv6ChecksumParams{Header: h, Src: nh.SourceAddress(), Dst: nh.DestinationAddress(), PayloadCsum: pkt.Data().Checksum(), PayloadLen: n}) != h.Checksum() {
		r.dropped.Add(1)
		return true
	}
	iph := header.IPv6(pkt.NetworkHeader().Slice())
	src := netip.AddrFrom16(iph.SourceAddress().As16())
	dst := netip.AddrFrom16(iph.DestinationAddress().As16())
	if !src.IsValid() || !dst.IsValid() || src.IsUnspecified() || dst.IsUnspecified() || src.IsMulticast() || dst.IsMulticast() || iph.HopLimit() == 0 {
		r.dropped.Add(1)
		return true
	}
	req := ICMPEchoRequest{
		Source:      src,
		Destination: dst,
		Ident:       h.Ident(),
		Sequence:    h.Sequence(),
		TTL:         iph.HopLimit(),
	}
	r.admitICMP(req, pkt)
	return true
}

func (r *Runtime) admitICMP(req ICMPEchoRequest, pkt *stack.PacketBuffer) {
	hook, ok := r.cfg.Ingress.(ICMPIngress)
	if !ok {
		r.dropped.Add(1)
		return
	}
	r.mu.Lock()
	if r.stopping || r.paused || !r.cfg.Admitting() || r.ctx.Err() != nil {
		r.dropped.Add(1)
		r.mu.Unlock()
		return
	}
	req.Epoch = r.cfg.Epoch()
	if req.Epoch != r.cfg.Epoch() || !r.cfg.Admitting() {
		r.dropped.Add(1)
		r.mu.Unlock()
		return
	}
	if r.icmpInFlight >= maxICMPInFlight || r.pending >= maxHandlers {
		r.dropped.Add(1)
		r.mu.Unlock()
		return
	}
	buf := pkt.Data().ToBuffer()
	req.Payload = append([]byte(nil), buf.Flatten()...)
	buf.Release()
	r.icmpInFlight++
	r.pending++
	r.wg.Add(1)
	r.mu.Unlock()

	go func() {
		defer func() {
			r.mu.Lock()
			r.icmpInFlight--
			r.pending--
			r.mu.Unlock()
			r.wg.Done()
		}()
		rep, send := hook.HandleICMP(r.ctx, req)
		if !send {
			return
		}
		body := rep.Payload
		if body == nil {
			body = req.Payload
		}
		r.writeMu.Lock()
		defer r.writeMu.Unlock()
		r.mu.Lock()
		valid := !r.stopping && !r.paused && r.cfg.Admitting() && r.cfg.Epoch() == req.Epoch && r.ctx.Err() == nil
		r.mu.Unlock()
		if !valid {
			return
		}
		packets, err := ICMPReply(req.Destination, req.Source, req.Ident, req.Sequence, rep.TTL, body, r.packetID.Add(1))
		if err != nil {
			return
		}
		for _, p := range packets {
			if err = r.cfg.Device.WritePacket(p); err != nil {
				if isWintunRingFull(err) {
					r.dropped.Add(1)
					return
				}
				r.fatal("TUN_DEVICE_WRITE_FAILED", err)
				return
			}
		}
	}()
}
