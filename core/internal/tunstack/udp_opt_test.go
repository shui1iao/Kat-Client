package tunstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func referenceUDPReply(src, dst netip.AddrPort, payload []byte, id uint32) [][]byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp, src.Port())
	binary.BigEndian.PutUint16(udp[2:], dst.Port())
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)
	var pseudo []byte
	if src.Addr().Is4() {
		a, b := src.Addr().As4(), dst.Addr().As4()
		pseudo = append(pseudo, a[:]...)
		pseudo = append(pseudo, b[:]...)
		pseudo = append(pseudo, 0, 17, byte(len(udp)>>8), byte(len(udp)))
	} else {
		a, b := src.Addr().As16(), dst.Addr().As16()
		pseudo = append(pseudo, a[:]...)
		pseudo = append(pseudo, b[:]...)
		pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(udp)))
		pseudo = append(pseudo, 0, 0, 0, 17)
	}
	csum := folded(sum16(pseudo) + sum16(udp))
	if csum == 0 {
		csum = 65535
	}
	binary.BigEndian.PutUint16(udp[6:], csum)
	var out [][]byte
	if src.Addr().Is4() {
		a, b := src.Addr().As4(), dst.Addr().As4()
		for off := 0; off < len(udp); {
			n := len(udp) - off
			if n > MTU-20 {
				n = (MTU - 20) &^ 7
			}
			p := make([]byte, 20+n)
			p[0] = 0x45
			p[8] = 64
			p[9] = 17
			binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
			binary.BigEndian.PutUint16(p[4:], uint16(id))
			frag := uint16(off / 8)
			if off+n < len(udp) {
				frag |= 0x2000
			}
			binary.BigEndian.PutUint16(p[6:], frag)
			copy(p[12:], a[:])
			copy(p[16:], b[:])
			binary.BigEndian.PutUint16(p[10:], folded(sum16(p[:20])))
			copy(p[20:], udp[off:off+n])
			out = append(out, p)
			off += n
		}
	} else {
		a, b := src.Addr().As16(), dst.Addr().As16()
		fragment := len(udp)+40 > MTU
		for off := 0; off < len(udp); {
			hdr := 40
			if fragment {
				hdr = 48
			}
			n := len(udp) - off
			if n > MTU-hdr {
				n = (MTU - hdr) &^ 7
			}
			p := make([]byte, hdr+n)
			p[0] = 0x60
			p[6] = 17
			p[7] = 64
			binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
			copy(p[8:], a[:])
			copy(p[24:], b[:])
			if fragment {
				p[6] = 44
				p[40] = 17
				bits := uint16(off) & 0xfff8
				if off+n < len(udp) {
					bits |= 1
				}
				binary.BigEndian.PutUint16(p[42:], bits)
				binary.BigEndian.PutUint32(p[44:], id)
			}
			copy(p[hdr:], udp[off:off+n])
			out = append(out, p)
			off += n
		}
	}
	return out
}

func TestUDPReplyByteEquivalenceIPv4IPv6AndFragments(t *testing.T) {
	pairs := [][2]netip.AddrPort{
		{netip.MustParseAddrPort("203.0.113.10:19412"), netip.MustParseAddrPort("198.18.0.1:51234")},
		{netip.MustParseAddrPort("[2001:db8::10]:19412"), netip.MustParseAddrPort("[fd00::1]:51234")},
	}
	sizes := []int{0, 1, 64, 1200, 1372, 1392, 1393, 4096}
	for _, pr := range pairs {
		for _, sz := range sizes {
			payload := make([]byte, sz)
			for i := range payload {
				payload[i] = byte((i*13 + 5) & 0xff)
			}
			got, err := UDPReply(pr[0], pr[1], payload, 0x12345678)
			if err != nil {
				t.Fatal(err)
			}
			want := referenceUDPReply(pr[0], pr[1], payload, 0x12345678)
			if len(got) != len(want) {
				t.Fatalf("frag count %d != %d for size %d", len(got), len(want), sz)
			}
			for i := range got {
				if !bytes.Equal(got[i], want[i]) {
					t.Fatalf("packet %d mismatch at size %d", i, sz)
				}
			}
		}
	}
}

func TestUDPBurst256NotDroppedAndDeadlineWakeupWorks(t *testing.T) {
	src := netip.MustParseAddrPort("198.18.0.1:42000")
	dst := netip.MustParseAddrPort("203.0.113.213:19412")
	var gotConn DatagramConn
	ready := make(chan struct{})
	r := &Runtime{
		ctx:        context.Background(),
		cancel:     func() {},
		cfg:        Config{Admitting: func() bool { return true }, Epoch: func() uint64 { return 1 }, Ingress: &captureUDPIngress{onUDP: func(c net.Conn) { gotConn = c.(DatagramConn); close(ready); <-c.(*sourceConn).closed }}},
		udpSources: map[sourceKey]*sourceConn{},
		active:     map[net.Conn]struct{}{},
		failed:     make(chan struct{}),
		done:       make(chan struct{}),
	}
	payload := make([]byte, 1200)
	frames, err := UDPReply(src, dst, payload, 1)
	if err != nil {
		t.Fatal(err)
	}
	id := stack.TransportEndpointID{RemoteAddress: tcpip.AddrFromSlice(src.Addr().AsSlice()), LocalAddress: tcpip.AddrFromSlice(dst.Addr().AsSlice()), RemotePort: src.Port(), LocalPort: dst.Port()}
	for i := 0; i < 200; i++ {
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frames[0])})
		p.NetworkProtocolNumber = header.IPv4ProtocolNumber
		p.NetworkHeader().Consume(20)
		p.TransportHeader().Consume(8)
		r.udpPacket(id, p)
		p.DecRef()
	}
	<-ready
	if r.dropped.Load() != 0 {
		t.Fatalf("expected 0 dropped packets for 200-packet burst, got %d", r.dropped.Load())
	}
	buf := make([]byte, 2048)
	for i := 0; i < 200; i++ {
		_ = gotConn.SetReadDeadline(time.Now().Add(time.Second))
		n, peer, err := gotConn.ReadDatagram(buf)
		if err != nil || n != 1200 || peer != dst {
			t.Fatalf("read %d: n=%d peer=%v err=%v", i, n, peer, err)
		}
	}
	// Verify dynamic deadline update wakes blocked ReadDatagram promptly
	_ = gotConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	errCh := make(chan error, 1)
	go func() {
		_, _, e := gotConn.ReadDatagram(buf)
		errCh <- e
	}()
	time.Sleep(20 * time.Millisecond)
	_ = gotConn.SetReadDeadline(time.Now().Add(15 * time.Millisecond))
	select {
	case e := <-errCh:
		if !os.IsTimeout(e) {
			t.Fatalf("expected timeout error, got %v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("SetReadDeadline did not wake blocked ReadDatagram")
	}
	_ = gotConn.Close()
}

type captureUDPIngress struct {
	onUDP func(net.Conn)
}

func (c *captureUDPIngress) HandleTCP(context.Context, Flow, TCPConn) error { return nil }
func (c *captureUDPIngress) HandleUDP(_ context.Context, _ Flow, conn net.Conn) error {
	c.onUDP(conn)
	return nil
}
