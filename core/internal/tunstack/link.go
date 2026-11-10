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
		b := make([]byte, n)
		copy(b, scratch[:n])
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b)})
		switch header.IPVersion(b) {
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
		n := 0
		for _, s := range p.AsSlices() {
			n += copy(wbuf[n:], s)
		}
		r.writeMu.Lock()
		e := r.cfg.Device.WritePacket(wbuf[:n])
		r.writeMu.Unlock()
		p.DecRef()
		if e != nil {
			r.fatal("TUN_DEVICE_WRITE_FAILED", e)
			return
		}
	}
}
