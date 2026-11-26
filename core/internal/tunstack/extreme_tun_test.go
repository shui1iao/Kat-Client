package tunstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUDPPathMTUDiscoveryIPv4AndIPv6(t *testing.T) {
	if MTU < 16384 || UDPMTU != 1420 {
		t.Fatalf("unexpected MTU=%d UDPMTU=%d", MTU, UDPMTU)
	}
	var mu sync.Mutex
	var written [][]byte
	dev := &funcDevice{
		readFn: func([]byte) (int, error) {
			time.Sleep(50 * time.Millisecond)
			return 0, context.Canceled
		},
		writeFn: func(b []byte) error {
			mu.Lock()
			written = append(written, append([]byte(nil), b...))
			mu.Unlock()
			return nil
		},
	}

	handled := make(chan int, 4)
	ing := &funcIngress{
		udpFn: func(ctx context.Context, f Flow, c net.Conn) error {
			dc := c.(DatagramConn)
			buf := make([]byte, 4096)
			n, _, err := dc.ReadDatagram(buf)
			if err == nil {
				handled <- n
			}
			return nil
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &Runtime{
		cfg:        Config{Device: dev, Ingress: ing, Admitting: func() bool { return true }, Epoch: func() uint64 { return 1 }},
		ctx:        ctx,
		cancel:     cancel,
		reasm:      newIPReassembler(),
		active:     make(map[net.Conn]struct{}),
		udpSources: make(map[sourceKey]*sourceConn),
		failed:     make(chan struct{}),
		done:       make(chan struct{}),
	}

	buildV4UDP := func(payloadLen int, df bool) []byte {
		src := netip.MustParseAddr("198.18.0.1").As4()
		dst := netip.MustParseAddr("203.0.113.20").As4()
		udpLen := 8 + payloadLen
		ipLen := 20 + udpLen
		pkt := make([]byte, ipLen)
		pkt[0] = 0x45
		binary.BigEndian.PutUint16(pkt[2:4], uint16(ipLen))
		if df {
			binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
		}
		pkt[8] = 64
		pkt[9] = 17
		copy(pkt[12:16], src[:])
		copy(pkt[16:20], dst[:])
		binary.BigEndian.PutUint16(pkt[10:12], folded(sum16(pkt[:20])))
		u := pkt[20:]
		binary.BigEndian.PutUint16(u[0:2], 40001)
		binary.BigEndian.PutUint16(u[2:4], 443)
		binary.BigEndian.PutUint16(u[4:6], uint16(udpLen))
		pseudo := sum16(src[:]) + sum16(dst[:]) + 17 + uint32(udpLen)
		csum := folded(pseudo + sum16(u))
		if csum == 0 {
			csum = 0xffff
		}
		binary.BigEndian.PutUint16(u[6:8], csum)
		return pkt
	}

	// 1. Oversized IPv4 UDP with DF=1 -> ICMPv4 Frag-Needed (MTU=1420)
	r.dispatchPacket(buildV4UDP(1450, true))

	mu.Lock()
	if len(written) != 1 {
		mu.Unlock()
		t.Fatalf("expected 1 ICMPv4 PTB reply, got %d", len(written))
	}
	rep4 := written[0]
	mu.Unlock()
	if rep4[0]>>4 != 4 || rep4[9] != 1 || rep4[20] != 3 || rep4[21] != 4 {
		t.Fatalf("invalid ICMPv4 PTB header: %x", rep4[:28])
	}
	if gotMTU := binary.BigEndian.Uint16(rep4[26:28]); gotMTU != UDPMTU {
		t.Fatalf("ICMPv4 PTB MTU=%d want %d", gotMTU, UDPMTU)
	}
	if folded(sum16(rep4[:20])) != 0 || folded(sum16(rep4[20:])) != 0 {
		t.Fatalf("invalid ICMPv4 PTB checksums")
	}

	// 2. Oversized IPv4 UDP with DF=0 -> forwarded normally
	r.dispatchPacket(buildV4UDP(1450, false))
	select {
	case n := <-handled:
		if n != 1450 {
			t.Fatalf("expected DF=0 payload 1450, got %d", n)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for DF=0 UDP datagram")
	}

	// 3. Oversized IPv6 UDP -> ICMPv6 PTB (MTU=1420)
	src6 := netip.MustParseAddr("fd4b:6174::1").As16()
	dst6 := netip.MustParseAddr("2001:db8::20").As16()
	udpLen6 := 8 + 1400
	pkt6 := make([]byte, 40+udpLen6)
	pkt6[0] = 0x60
	binary.BigEndian.PutUint16(pkt6[4:6], uint16(udpLen6))
	pkt6[6] = 17
	pkt6[7] = 64
	copy(pkt6[8:24], src6[:])
	copy(pkt6[24:40], dst6[:])
	u6 := pkt6[40:]
	binary.BigEndian.PutUint16(u6[0:2], 40002)
	binary.BigEndian.PutUint16(u6[2:4], 443)
	binary.BigEndian.PutUint16(u6[4:6], uint16(udpLen6))
	p6Sum := sum16(src6[:]) + sum16(dst6[:]) + uint32(udpLen6) + 17
	cs6 := folded(p6Sum + sum16(u6))
	if cs6 == 0 {
		cs6 = 0xffff
	}
	binary.BigEndian.PutUint16(u6[6:8], cs6)
	r.dispatchPacket(pkt6)

	mu.Lock()
	if len(written) != 2 {
		mu.Unlock()
		t.Fatalf("expected 2 total PTB replies, got %d", len(written))
	}
	rep6 := written[1]
	mu.Unlock()
	if rep6[0]>>4 != 6 || rep6[6] != 58 || rep6[40] != 2 || rep6[41] != 0 || len(rep6) > 1280 {
		t.Fatalf("invalid ICMPv6 PTB header/len=%d", len(rep6))
	}
	if gotMTU := binary.BigEndian.Uint32(rep6[44:48]); gotMTU != UDPMTU {
		t.Fatalf("ICMPv6 PTB MTU=%d want %d", gotMTU, UDPMTU)
	}
	icmp6Len := uint32(len(rep6) - 40)
	p6Check := sum16(rep6[8:24]) + sum16(rep6[24:40]) + icmp6Len + 58 + sum16(rep6[40:])
	if folded(p6Check) != 0 {
		t.Fatalf("invalid ICMPv6 PTB checksum")
	}
	r.mu.Lock()
	for _, sc := range r.udpSources {
		go sc.Close()
	}
	r.mu.Unlock()
	cancel()
	r.wg.Wait()
}

func TestSystemStackNATRFC1624AndAdmissionRST(t *testing.T) {
	var admitting atomic.Bool
	admitting.Store(true)
	dev := newScriptedDevice(8)
	rt, err := StartReady(context.Background(), Config{
		Device:    dev,
		Ingress:   &funcIngress{},
		Admitting: admitting.Load,
		Epoch:     func() uint64 { return 7 },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close(context.Background())

	// Verify IPv4 & IPv6 NAT rewrite + RFC 1624 incremental checksum matches full recomputation.
	for _, tc := range []struct {
		src, dst netip.AddrPort
		v6       bool
	}{
		{netip.MustParseAddrPort("198.18.0.1:51234"), netip.MustParseAddrPort("203.0.113.20:443"), false},
		{netip.MustParseAddrPort("[fd4b:6174::1]:51235"), netip.MustParseAddrPort("[2001:db8::20]:443"), true},
	} {
		if tc.v6 && rt.TCPListenPort6() == 0 {
			continue
		}
		syn := buildTestSYNPacket(tc.src, tc.dst)
		out := rt.dispatchPacket(syn)
		if len(out) == 0 {
			t.Fatalf("v6=%v SYN was dropped", tc.v6)
		}
		p, _, ok := parseIPPacket(out)
		if !ok || p.proto != ipProtoTCP {
			t.Fatalf("v6=%v rewritten packet invalid", tc.v6)
		}
		wantPeer := derivePeerIP(tc.src.Addr())
		wantPort := rt.TCPListenPort4()
		if tc.v6 {
			wantPort = rt.TCPListenPort6()
		}
		gotSrcPort := binary.BigEndian.Uint16(p.payload[0:2])
		gotDstPort := binary.BigEndian.Uint16(p.payload[2:4])
		if p.src != wantPeer || p.dst != tc.src.Addr() || gotDstPort != wantPort {
			t.Fatalf("v6=%v NAT mismatch: %v:%d -> %v:%d", tc.v6, p.src, gotSrcPort, p.dst, gotDstPort)
		}
		// Verify full TCP checksum on rewritten packet!
		var pseudo uint32
		if tc.v6 {
			pseudo = addr6Sum(p.src.As16()) + addr6Sum(p.dst.As16()) + uint32(len(p.payload)) + ipProtoTCP
		} else {
			if folded(sum16(p.raw[:p.hdrLen])) != 0 {
				t.Fatal("v4 IP header incremental checksum mismatch")
			}
			pseudo = addr4Sum(p.src.As4()) + addr4Sum(p.dst.As4()) + ipProtoTCP + uint32(len(p.payload))
		}
		if folded(pseudo+sum16(p.payload)) != 0 {
			t.Fatalf("v6=%v TCP incremental checksum mismatch", tc.v6)
		}

		// Simulate return SYN-ACK from listener -> peerIP:natPort and verify reverse NAT + checksum.
		ret := buildTestSYNPacket(netip.AddrPortFrom(tc.src.Addr(), wantPort), netip.AddrPortFrom(wantPeer, gotSrcPort))
		ret[len(ret)-7] = 0x12 // SYN+ACK
		// Recompute TCP checksum for return test packet
		if tc.v6 {
			tHdr := ret[40:]
			binary.BigEndian.PutUint16(tHdr[16:18], 0)
			ps := addr6Sum(tc.src.Addr().As16()) + addr6Sum(wantPeer.As16()) + 20 + ipProtoTCP
			binary.BigEndian.PutUint16(tHdr[16:18], folded(ps+sum16(tHdr)))
		} else {
			tHdr := ret[20:]
			binary.BigEndian.PutUint16(tHdr[16:18], 0)
			ps := addr4Sum(tc.src.Addr().As4()) + addr4Sum(wantPeer.As4()) + ipProtoTCP + 20
			binary.BigEndian.PutUint16(tHdr[16:18], folded(ps+sum16(tHdr)))
		}
		rev := rt.dispatchPacket(ret)
		rp, _, ok := parseIPPacket(rev)
		if !ok || rp.src != tc.dst.Addr() || rp.dst != tc.src.Addr() || binary.BigEndian.Uint16(rp.payload[0:2]) != tc.dst.Port() || binary.BigEndian.Uint16(rp.payload[2:4]) != tc.src.Port() {
			t.Fatalf("v6=%v reverse NAT mismatch", tc.v6)
		}
		var revPseudo uint32
		if tc.v6 {
			revPseudo = addr6Sum(rp.src.As16()) + addr6Sum(rp.dst.As16()) + uint32(len(rp.payload)) + ipProtoTCP
		} else {
			if folded(sum16(rp.raw[:rp.hdrLen])) != 0 {
				t.Fatal("v4 reverse IP checksum mismatch")
			}
			revPseudo = addr4Sum(rp.src.As4()) + addr4Sum(rp.dst.As4()) + ipProtoTCP + uint32(len(rp.payload))
		}
		if folded(revPseudo+sum16(rp.payload)) != 0 {
			t.Fatalf("v6=%v reverse TCP checksum mismatch", tc.v6)
		}
	}

	// Verify unadmitted SYN receives a valid TCP RST (not silent drop).
	admitting.Store(false)
	synBlocked := buildTestSYNPacket(netip.MustParseAddrPort("198.18.0.1:52000"), netip.MustParseAddrPort("203.0.113.20:80"))
	rst := rt.dispatchPacket(synBlocked)
	rp, _, ok := parseIPPacket(rst)
	if !ok || rp.proto != ipProtoTCP || (rp.payload[13]&0x04) == 0 {
		t.Fatalf("expected TCP RST for unadmitted SYN, got %x", rst)
	}

	// Verify fragmented inbound UDP is reassembled cleanly without gVisor!
	admitting.Store(true)
	bigPayload := bytes.Repeat([]byte{0x42}, 3000)
	frags, err := UDPReply(netip.MustParseAddrPort("198.18.0.1:45000"), netip.MustParseAddrPort("203.0.113.99:5353"), bigPayload, 0x9988)
	if err != nil || len(frags) < 3 {
		t.Fatalf("expected fragmented UDP, got %d err=%v", len(frags), err)
	}
	gotUDP := make(chan []byte, 1)
	rt.cfg.Ingress = &funcIngress{udpFn: func(ctx context.Context, f Flow, c net.Conn) error {
		b := make([]byte, 4096)
		n, _, e := c.(DatagramConn).ReadDatagram(b)
		if e == nil {
			gotUDP <- append([]byte(nil), b[:n]...)
		}
		return nil
	}}
	// Feed fragments out of order (last first)!
	rt.dispatchPacket(frags[len(frags)-1])
	for i := 0; i < len(frags)-1; i++ {
		rt.dispatchPacket(frags[i])
	}
	select {
	case b := <-gotUDP:
		if !bytes.Equal(b, bigPayload) {
			t.Fatalf("reassembled UDP mismatch: len=%d", len(b))
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for out-of-order reassembled UDP")
	}

	// Verify stray non-NAT loopback connection to System Stack TCP listener is rejected immediately.
	c, err := net.DialTimeout("tcp4", netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), rt.TCPListenPort4()).String(), time.Second)
	if err == nil {
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 16)
		n, rerr := c.Read(buf)
		_ = c.Close()
		if rerr == nil || n != 0 {
			t.Fatalf("stray non-NAT connection was not closed immediately: n=%d err=%v", n, rerr)
		}
	}
}

type funcDevice struct {
	readFn  func([]byte) (int, error)
	writeFn func([]byte) error
}

func (f *funcDevice) ReadPacket(b []byte) (int, error) { return f.readFn(b) }
func (f *funcDevice) WritePacket(b []byte) error       { return f.writeFn(b) }
func (f *funcDevice) Close() error                     { return nil }

type funcIngress struct {
	udpFn func(context.Context, Flow, net.Conn) error
}

func (f *funcIngress) HandleTCP(context.Context, Flow, TCPConn) error { return nil }
func (f *funcIngress) HandleUDP(ctx context.Context, fl Flow, c net.Conn) error {
	if f.udpFn != nil {
		return f.udpFn(ctx, fl, c)
	}
	return nil
}
