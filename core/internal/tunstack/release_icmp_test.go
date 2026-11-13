package tunstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

// Independent RFC1071 checksum: never use the production sum16/folded helpers.
func releaseChecksum(b []byte) uint16 {
	var n uint32
	for len(b) >= 2 {
		n += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		n += uint32(b[0]) << 8
	}
	for n>>16 != 0 {
		n = (n & 65535) + (n >> 16)
	}
	return ^uint16(n)
}
func releaseICMPSum(src, dst netip.Addr, icmp []byte) uint16 {
	if src.Is4() {
		return releaseChecksum(icmp)
	}
	p := append([]byte{}, src.AsSlice()...)
	p = append(p, dst.AsSlice()...)
	l := make([]byte, 8)
	binary.BigEndian.PutUint32(l, uint32(len(icmp)))
	l[7] = 58
	p = append(p, l...)
	p = append(p, icmp...)
	return releaseChecksum(p)
}
func releaseEchoWire(v6 bool, kind, code byte, body []byte) []byte {
	src, dst := netip.MustParseAddr("10.50.0.2"), netip.MustParseAddr("203.0.113.50")
	n := 20
	if v6 {
		src, dst = netip.MustParseAddr("fd50::2"), netip.MustParseAddr("2001:db8::50")
		n = 40
	}
	w := make([]byte, n+8+len(body))
	ic := w[n:]
	ic[0] = kind
	ic[1] = code
	binary.BigEndian.PutUint16(ic[4:], 0x1234)
	binary.BigEndian.PutUint16(ic[6:], 0x5678)
	copy(ic[8:], body)
	binary.BigEndian.PutUint16(ic[2:], releaseICMPSum(src, dst, ic))
	if v6 {
		w[0] = 0x60
		w[6] = 58
		w[7] = 37
		binary.BigEndian.PutUint16(w[4:], uint16(len(ic)))
		copy(w[8:24], src.AsSlice())
		copy(w[24:40], dst.AsSlice())
	} else {
		w[0] = 0x45
		w[8] = 37
		w[9] = 1
		binary.BigEndian.PutUint16(w[2:], uint16(len(w)))
		copy(w[12:16], src.AsSlice())
		copy(w[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(w[10:], releaseChecksum(w[:20]))
	}
	return w
}

type releaseICMPHook struct {
	call func(context.Context, ICMPEchoRequest) (ICMPEchoReply, bool)
}

func (*releaseICMPHook) HandleTCP(context.Context, Flow, TCPConn) error  { return nil }
func (*releaseICMPHook) HandleUDP(context.Context, Flow, net.Conn) error { return nil }
func (h *releaseICMPHook) HandleICMP(c context.Context, r ICMPEchoRequest) (ICMPEchoReply, bool) {
	return h.call(c, r)
}
func releaseInput(r *Runtime, v6 bool, w []byte) bool {
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(w)})
	defer p.DecRef()
	n := 20
	p.NetworkProtocolNumber = header.IPv4ProtocolNumber
	if v6 {
		n = 40
		p.NetworkProtocolNumber = header.IPv6ProtocolNumber
	}
	p.NetworkHeader().Consume(n)
	p.TransportHeader().Consume(8)
	if v6 {
		return r.icmpPacket6(stack.TransportEndpointID{}, p)
	}
	return r.icmpPacket4(stack.TransportEndpointID{}, p)
}
func releaseWait(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(2 * time.Second):
		t.Fatal("synchronized ICMP callback did not settle")
	}
}
func TestReleaseICMPEchoAdmissionAndChecksums(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		name := "v4"
		kind := byte(8)
		if v6 {
			name = "v6"
			kind = 128
		}
		t.Run(name, func(t *testing.T) {
			for _, bad := range []string{"valid", "non-echo", "checksum", "code"} {
				t.Run(bad, func(t *testing.T) {
					var calls atomic.Int32
					d := newScriptedDevice(4)
					defer d.Close()
					hook := &releaseICMPHook{call: func(_ context.Context, q ICMPEchoRequest) (ICMPEchoReply, bool) {
						calls.Add(1)
						if q.Ident != 0x1234 || q.Sequence != 0x5678 || q.TTL != 37 || !bytes.Equal(q.Payload, []byte("odd payload")) {
							t.Error("request identity changed", q)
						}
						return ICMPEchoReply{Payload: q.Payload, TTL: 51}, true
					}}
					r := &Runtime{ctx: context.Background(), cfg: Config{Device: d, Ingress: hook, Admitting: func() bool { return true }, Epoch: func() uint64 { return 7 }}}
					k, c := kind, byte(0)
					if bad == "non-echo" {
						k = 3
					}
					if bad == "code" {
						c = 1
					}
					wire := releaseEchoWire(v6, k, c, []byte("odd payload"))
					if bad == "checksum" {
						wire[len(wire)-1] ^= 1
					}
					handled := releaseInput(r, v6, wire)
					r.wg.Wait()
					if bad == "non-echo" {
						if handled {
							t.Fatal("non Echo stolen from gVisor")
						}
					} else if !handled {
						t.Fatal("Echo not consumed")
					}
					if bad != "valid" {
						if calls.Load() != 0 || len(d.writes) != 0 {
							t.Fatal("invalid/non Echo reached callback or output")
						}
						return
					}
					if calls.Load() != 1 || len(d.writes) != 1 {
						t.Fatal("valid Echo missing", calls.Load(), len(d.writes))
					}
					p := <-d.writes
					n := 20
					src, dst := netip.MustParseAddr("203.0.113.50"), netip.MustParseAddr("10.50.0.2")
					if v6 {
						n = 40
						src, dst = netip.MustParseAddr("2001:db8::50"), netip.MustParseAddr("fd50::2")
						if p[7] != 51 || p[40] != 129 || !bytes.Equal(p[8:24], src.AsSlice()) || !bytes.Equal(p[24:40], dst.AsSlice()) {
							t.Fatal("v6 reply header")
						}
					} else {
						if p[8] != 51 || p[20] != 0 || releaseChecksum(p[:20]) != 0 || !bytes.Equal(p[12:16], src.AsSlice()) || !bytes.Equal(p[16:20], dst.AsSlice()) {
							t.Fatal("v4 reply header")
						}
					}
					ic := p[n:]
					if releaseICMPSum(src, dst, ic) != 0 || binary.BigEndian.Uint16(ic[4:]) != 0x1234 || binary.BigEndian.Uint16(ic[6:]) != 0x5678 || !bytes.Equal(ic[8:], []byte("odd payload")) {
						t.Fatal("reply identity/checksum/payload")
					}
				})
			}
		})
	}
}
func TestReleaseICMPFragmentReassembly(t *testing.T) {
	body := bytes.Repeat([]byte{0x51, 0x62, 0x73}, 1301)
	for _, v6 := range []bool{false, true} {
		src, dst := netip.MustParseAddr("203.0.113.50"), netip.MustParseAddr("10.50.0.2")
		if v6 {
			src, dst = netip.MustParseAddr("2001:db8::50"), netip.MustParseAddr("fd50::2")
		}
		ps, e := ICMPReply(src, dst, 0x1234, 0x5678, 39, body, 0x12345678)
		if e != nil || len(ps) < 2 {
			t.Fatal("missing fragmentation", e)
		}
		rebuilt := []byte{}
		for i, p := range ps {
			if len(p) > MTU {
				t.Fatal("MTU exceeded")
			}
			n := 20
			off := int(binary.BigEndian.Uint16(p[6:8])&0x1fff) * 8
			more := binary.BigEndian.Uint16(p[6:8])&0x2000 != 0
			if v6 {
				n = 48
				off = int(binary.BigEndian.Uint16(p[42:44]) & 0xfff8)
				more = p[43]&1 != 0
				if p[6] != 44 || p[40] != 58 || p[7] != 39 || binary.BigEndian.Uint32(p[44:]) != 0x12345678 || int(binary.BigEndian.Uint16(p[4:])) != len(p)-40 {
					t.Fatal("v6 fragment metadata")
				}
			} else if releaseChecksum(p[:20]) != 0 || p[8] != 39 || binary.BigEndian.Uint16(p[4:]) != 0x5678 || int(binary.BigEndian.Uint16(p[2:])) != len(p) {
				t.Fatal("v4 fragment metadata")
			}
			if off != len(rebuilt) || more != (i < len(ps)-1) || more && (len(p)-n)%8 != 0 {
				t.Fatal("fragment offset/MF/alignment")
			}
			rebuilt = append(rebuilt, p[n:]...)
		}
		kind := byte(0)
		if v6 {
			kind = 129
		}
		if rebuilt[0] != kind || rebuilt[1] != 0 || binary.BigEndian.Uint16(rebuilt[4:]) != 0x1234 || binary.BigEndian.Uint16(rebuilt[6:]) != 0x5678 || !bytes.Equal(rebuilt[8:], body) || releaseICMPSum(src, dst, rebuilt) != 0 {
			t.Fatal("reassembled Echo invalid")
		}
	}
}
func TestReleaseICMPLateReplyFence(t *testing.T) {
	for _, fence := range []string{"none", "epoch", "quiesce", "context"} {
		t.Run(fence, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var epoch atomic.Uint64
			epoch.Store(1)
			d := newScriptedDevice(4)
			defer d.Close()
			hook := &releaseICMPHook{call: func(context.Context, ICMPEchoRequest) (ICMPEchoReply, bool) {
				close(entered)
				<-release
				return ICMPEchoReply{TTL: 40}, true
			}}
			r := &Runtime{ctx: ctx, cfg: Config{Device: d, Ingress: hook, Admitting: func() bool { return true }, Epoch: epoch.Load}}
			releaseInput(r, false, releaseEchoWire(false, 8, 0, []byte("held")))
			releaseWait(t, entered)
			switch fence {
			case "epoch":
				epoch.Store(2)
			case "quiesce":
				r.Quiesce()
			case "context":
				cancel()
			}
			close(release)
			go func() { r.wg.Wait(); close(finished) }()
			releaseWait(t, finished)
			want := 0
			if fence == "none" {
				want = 1
			}
			if len(d.writes) != want {
				t.Fatal("late output crossed fence", fence, len(d.writes))
			}
		})
	}
}
