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
	for {
		b := make([]byte, 65535) // payload ownership never aliases the next device read
		n, e := r.cfg.Device.ReadPacket(b)
		if e != nil {
			r.fatal("TUN_DEVICE_READ_FAILED", e)
			return
		}
		if r.ctx.Err() != nil {
			return
		}
		if n <= 0 || n > len(b) {
			r.dropped.Add(1)
			continue
		}
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(b[:n])})
		switch header.IPVersion(b[:n]) {
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
	for {
		p := r.link.ReadContext(r.ctx)
		if p == nil {
			if r.ctx.Err() == nil {
				r.fatal("TUN_STACK_STOPPED", errors.New("packet output queue stopped"))
			}
			return
		}
		b := p.ToBuffer()
		r.writeMu.Lock()
		e := r.cfg.Device.WritePacket(b.Flatten())
		r.writeMu.Unlock()
		b.Release()
		p.DecRef()
		if e != nil {
			r.fatal("TUN_DEVICE_WRITE_FAILED", e)
			return
		}
	}
}
