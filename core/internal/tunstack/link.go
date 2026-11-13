// Derived from tun2socks v2.7.0 core/device/iobased/endpoint.go (MIT).
// Copyright (c) 2019 Jason Lyu. See LICENSE.tun2socks.
// Kat modifications: packet Device API, first-fault health, shared cancellation,
// close/join ownership and bounded validation. No upstream pump is run.
package tunstack

import (
	"errors"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type wintunRingFullError interface {
	error
	WintunRingFull() bool
}

func isWintunRingFull(err error) bool {
	var target wintunRingFullError
	return errors.As(err, &target) && target.WintunRingFull()
}

func (r *Runtime) readPackets() {
	scratch := make([]byte, 65535)
	for {
		n, e := r.cfg.Device.ReadPacket(scratch)
		if e != nil {
			r.fatal("TUN_DEVICE_READ_FAILED", e)
			return
		}
		if r.ctx.Err() != nil {
			return
		}
		if n <= 0 || n > len(scratch) {
			r.dropped.Add(1)
			continue
		}
		pkt := scratch[:n]
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
		switch header.IPVersion(pkt) {
		case header.IPv4Version:
			r.link.InjectInbound(header.IPv4ProtocolNumber, p)
		case header.IPv6Version:
			r.link.InjectInbound(header.IPv6ProtocolNumber, p)
		default:
			r.dropped.Add(1)
		}
		p.DecRef()
	}
}
func (r *Runtime) writePackets() {
	wbuf := make([]byte, 65535)
	for {
		p := r.link.ReadContext(r.ctx)
		if p == nil {
			if r.ctx.Err() == nil {
				r.fatal("TUN_STACK_STOPPED", errors.New("packet output queue stopped"))
			}
			return
		}
		n := copyPacket(wbuf, p)
		r.writeMu.Lock()
		e := r.cfg.Device.WritePacket(wbuf[:n])
		r.writeMu.Unlock()
		p.DecRef()
		if e != nil {
			if isWintunRingFull(e) {
				r.dropped.Add(1)
				continue
			}
			r.fatal("TUN_DEVICE_WRITE_FAILED", e)
			return
		}
	}
}
func copyPacket(dst []byte, p *stack.PacketBuffer) int {
	vl, off := p.AsViewList()
	rem := p.Size()
	n := 0
	for v := vl.Front(); v != nil && rem > 0 && n < len(dst); v = v.Next() {
		s := v.AsSlice()
		if off >= len(s) {
			off -= len(s)
			continue
		}
		if off > 0 {
			s = s[off:]
			off = 0
		}
		if len(s) > rem {
			s = s[:rem]
		}
		n += copy(dst[n:], s)
		rem -= len(s)
	}
	return n
}
