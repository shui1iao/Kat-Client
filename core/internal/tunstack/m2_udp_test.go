package tunstack

import (
	"context"
	"encoding/binary"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"net"
	"net/netip"
	"testing"
)

func m2Input(t *testing.T, src, dst netip.AddrPort, mutate func([]byte), run func(*stack.PacketBuffer, stack.TransportEndpointID)) {
	t.Helper()
	frames, e := UDPReply(src, dst, []byte("test"), 1)
	if e != nil {
		t.Fatal(e)
	}
	wire := frames[0]
	mutate(wire)
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(wire)})
	defer p.DecRef()
	h := 20
	p.NetworkProtocolNumber = header.IPv4ProtocolNumber
	if src.Addr().Is6() {
		h = 40
		p.NetworkProtocolNumber = header.IPv6ProtocolNumber
	}
	p.NetworkHeader().Consume(h)
	p.TransportHeader().Consume(8)
	run(p, stack.TransportEndpointID{RemoteAddress: tcpip.AddrFromSlice(src.Addr().AsSlice()), LocalAddress: tcpip.AddrFromSlice(dst.Addr().AsSlice()), RemotePort: src.Port(), LocalPort: dst.Port()})
}
func TestM2UDPRejectsInvalidChecksumLengthAndTornEpoch(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		src, dst := netip.MustParseAddrPort("10.50.0.2:4000"), netip.MustParseAddrPort("203.0.113.1:4444")
		if v6 {
			src, dst = netip.MustParseAddrPort("[fd50::2]:4000"), netip.MustParseAddrPort("[2001:db8::1]:4444")
		}
		for _, bad := range []string{"checksum", "length", "epoch", "zero-v6"} {
			if bad == "zero-v6" && !v6 {
				continue
			}
			r := &Runtime{ctx: context.Background(), cfg: Config{Admitting: func() bool { return true }, Epoch: func() uint64 { return 1 }}, udpSources: map[sourceKey]*sourceConn{}, active: map[net.Conn]struct{}{}}
			if bad == "epoch" {
				var n uint64
				r.cfg.Epoch = func() uint64 { n++; return n }
			}
			m2Input(t, src, dst, func(w []byte) {
				h := 20
				if v6 {
					h = 40
				}
				switch bad {
				case "checksum":
					w[len(w)-1] ^= 1
				case "length":
					binary.BigEndian.PutUint16(w[h+4:], 7)
				case "zero-v6":
					binary.BigEndian.PutUint16(w[h+6:], 0)
				}
			}, func(p *stack.PacketBuffer, id stack.TransportEndpointID) { r.udpPacket(id, p) })
			if r.pending != 0 || len(r.udpSources) != 0 || r.dropped.Load() != 1 {
				t.Fatalf("invalid %s v6=%v admitted", bad, v6)
			}
		}
	}
}
func TestM2UDPGlobalQueueAndHandlerBudget(t *testing.T) {
	src, dst := netip.MustParseAddrPort("10.50.0.2:4000"), netip.MustParseAddrPort("203.0.113.1:4444")
	r := &Runtime{ctx: context.Background(), cfg: Config{Admitting: func() bool { return true }, Epoch: func() uint64 { return 1 }}, udpSources: map[sourceKey]*sourceConn{}, active: map[net.Conn]struct{}{}, pending: maxHandlers}
	deliver := func() {
		m2Input(t, src, dst, func([]byte) {}, func(p *stack.PacketBuffer, id stack.TransportEndpointID) { r.udpPacket(id, p) })
	}
	deliver()
	if len(r.udpSources) != 0 || r.pending != maxHandlers {
		t.Fatal("handler quota bypassed")
	}
	k := sourceKey{src, 1}
	c := &sourceConn{r: r, key: k, queue: make(chan udpMessage, 1), closed: make(chan struct{}), changed: make(chan struct{})}
	r.udpSources[k] = c
	r.udpQueuedBytes = udpQueuedByteLimit - 3
	deliver()
	if len(c.queue) != 0 || r.udpQueuedBytes != udpQueuedByteLimit-3 {
		t.Fatal("global bytes exceeded")
	}
	r.udpQueuedBytes = 0
	deliver()
	deliver()
	if len(c.queue) != 1 || r.udpQueuedBytes != 4 {
		t.Fatal("queue slot budget exceeded")
	}
	c.Close()
	if r.udpQueuedBytes != 0 {
		t.Fatal("close did not release queue bytes")
	}
}
