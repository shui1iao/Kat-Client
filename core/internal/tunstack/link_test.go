package tunstack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/tunplatform"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func legacyCopyAsSlices(dst []byte, p *stack.PacketBuffer) int {
	n := 0
	for _, s := range p.AsSlices() {
		n += copy(dst[n:], s)
	}
	return n
}

func buildMultiViewPacket(reserve, netHdrLen, transHdrLen int, chunks ...[]byte) (*stack.PacketBuffer, *int) {
	var payload buffer.Buffer
	for _, c := range chunks {
		payload.Append(buffer.NewViewWithData(c))
	}
	released := new(int)
	p := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: reserve,
		Payload:            payload,
		OnRelease:          func() { *released++ },
	})
	if transHdrLen > 0 {
		th := p.TransportHeader().Push(transHdrLen)
		for i := range th {
			th[i] = byte(0xA0 + i)
		}
	}
	if netHdrLen > 0 {
		nh := p.NetworkHeader().Push(netHdrLen)
		for i := range nh {
			nh[i] = byte(0x40 + i)
		}
	}
	return p, released
}

func TestCopyPacketMatchesAsSlicesAndPreservesHeadersOffsetMTU(t *testing.T) {
	cases := []struct {
		name        string
		reserve     int
		netHdrLen   int
		transHdrLen int
		chunks      [][]byte
		capData     int
		dstCap      int
	}{
		{
			name:        "ipv4_tcp_partial_headroom_multiview_mtu",
			reserve:     60,
			netHdrLen:   20,
			transHdrLen: 20,
			chunks: [][]byte{
				bytes.Repeat([]byte{0x11}, 500),
				bytes.Repeat([]byte{0x22}, 480),
				bytes.Repeat([]byte{0x33}, 400),
			},
			capData: -1,
			dstCap:  65535,
		},
		{
			name:        "ipv6_udp_partial_headroom_multiview",
			reserve:     80,
			netHdrLen:   40,
			transHdrLen: 8,
			chunks: [][]byte{
				[]byte("header-adjacent"),
				bytes.Repeat([]byte{0x5A}, 700),
				[]byte("tail"),
			},
			capData: -1,
			dstCap:  65535,
		},
		{
			name:        "unpushed_reserved_headroom_skip_first_view",
			reserve:     48,
			netHdrLen:   0,
			transHdrLen: 0,
			chunks: [][]byte{
				bytes.Repeat([]byte{0x7E}, 256),
				bytes.Repeat([]byte{0x8F}, 512),
			},
			capData: -1,
			dstCap:  65535,
		},
		{
			name:        "capped_data_length",
			reserve:     40,
			netHdrLen:   20,
			transHdrLen: 8,
			chunks: [][]byte{
				bytes.Repeat([]byte{0xAB}, 300),
				bytes.Repeat([]byte{0xCD}, 300),
			},
			capData: 420,
			dstCap:  65535,
		},
		{
			name:        "short_destination_buffer",
			reserve:     40,
			netHdrLen:   20,
			transHdrLen: 20,
			chunks: [][]byte{
				bytes.Repeat([]byte{0xEF}, 600),
			},
			capData: -1,
			dstCap:  128,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, released := buildMultiViewPacket(tc.reserve, tc.netHdrLen, tc.transHdrLen, tc.chunks...)
			if tc.capData >= 0 {
				p.Data().CapLength(tc.capData)
			}
			gotBuf := make([]byte, tc.dstCap)
			wantBuf := make([]byte, tc.dstCap)

			gotN := copyPacket(gotBuf, p)
			wantN := legacyCopyAsSlices(wantBuf, p)
			if gotN != wantN {
				t.Fatalf("copyPacket len=%d, want %d", gotN, wantN)
			}
			if !bytes.Equal(gotBuf[:gotN], wantBuf[:wantN]) {
				t.Fatalf("copyPacket bytes mismatch")
			}
			if *released != 0 {
				t.Fatalf("packet released before DecRef: %d", *released)
			}
			p.DecRef()
			if *released != 1 {
				t.Fatalf("packet OnRelease count=%d after DecRef, want 1", *released)
			}
		})
	}

	p, released := buildMultiViewPacket(60, 20, 20, bytes.Repeat([]byte{0x42}, 700), bytes.Repeat([]byte{0x99}, 680))
	defer p.DecRef()
	wbuf := make([]byte, 65535)
	allocs := testing.AllocsPerRun(100, func() {
		n := copyPacket(wbuf, p)
		if n != 1420 {
			t.Fatalf("unexpected size %d", n)
		}
	})
	if allocs != 0 {
		t.Fatalf("copyPacket allocated %v allocs/op, want 0", allocs)
	}
	if *released != 0 {
		t.Fatalf("unexpected release during alloc check")
	}
}

type scriptedReadItem struct {
	data      []byte
	forceN    int
	useForceN bool
	fillByte  byte
}

type scriptedDevice struct {
	reads  chan scriptedReadItem
	writes chan []byte
	closed chan struct{}
	once   sync.Once
}

func newScriptedDevice(buf int) *scriptedDevice {
	return &scriptedDevice{
		reads:  make(chan scriptedReadItem, buf),
		writes: make(chan []byte, buf),
		closed: make(chan struct{}),
	}
}

func (d *scriptedDevice) ReadPacket(b []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, io.ErrClosedPipe
	case item := <-d.reads:
		if item.fillByte != 0 {
			for i := range b {
				b[i] = item.fillByte
			}
		}
		if len(item.data) > 0 {
			copy(b, item.data)
		}
		if item.useForceN {
			return item.forceN, nil
		}
		return len(item.data), nil
	}
}

func (d *scriptedDevice) WritePacket(b []byte) error {
	select {
	case <-d.closed:
		return io.ErrClosedPipe
	default:
	}
	cp := append([]byte(nil), b...)
	d.writes <- cp
	return nil
}

func (d *scriptedDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

type testIngress struct {
	udpCh chan struct {
		flow Flow
		conn DatagramConn
	}
}

func (in *testIngress) HandleTCP(_ context.Context, _ Flow, c TCPConn) error {
	_ = c.Close()
	return nil
}

func (in *testIngress) HandleUDP(ctx context.Context, f Flow, c net.Conn) error {
	dc, ok := c.(DatagramConn)
	if !ok {
		_ = c.Close()
		return nil
	}
	select {
	case in.udpCh <- struct {
		flow Flow
		conn DatagramConn
	}{flow: f, conn: dc}:
	case <-ctx.Done():
		return ctx.Err()
	}
	<-ctx.Done()
	return nil
}

func buildTCPSYN4(src, dst netip.AddrPort) []byte {
	total := header.IPv4MinimumSize + header.TCPMinimumSize
	pkt := make([]byte, total)
	ip := header.IPv4(pkt[:header.IPv4MinimumSize])
	srcAddr := tcpip.AddrFromSlice(src.Addr().AsSlice())
	dstAddr := tcpip.AddrFromSlice(dst.Addr().AsSlice())
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(total),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     srcAddr,
		DstAddr:     dstAddr,
	})
	ip.SetChecksum(^ip.CalculateChecksum())
	tcp := header.TCP(pkt[header.IPv4MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    src.Port(),
		DstPort:    dst.Port(),
		SeqNum:     1000,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcAddr, dstAddr, uint16(header.TCPMinimumSize))
	tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
	return pkt
}

func buildTCPSYN6(src, dst netip.AddrPort) []byte {
	total := header.IPv6MinimumSize + header.TCPMinimumSize
	pkt := make([]byte, total)
	ip := header.IPv6(pkt[:header.IPv6MinimumSize])
	srcAddr := tcpip.AddrFromSlice(src.Addr().AsSlice())
	dstAddr := tcpip.AddrFromSlice(dst.Addr().AsSlice())
	ip.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.TCPMinimumSize),
		TransportProtocol: header.TCPProtocolNumber,
		HopLimit:          64,
		SrcAddr:           srcAddr,
		DstAddr:           dstAddr,
	})
	tcp := header.TCP(pkt[header.IPv6MinimumSize:])
	tcp.Encode(&header.TCPFields{
		SrcPort:    src.Port(),
		DstPort:    dst.Port(),
		SeqNum:     2000,
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagSyn,
		WindowSize: 65535,
	})
	xsum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, srcAddr, dstAddr, uint16(header.TCPMinimumSize))
	tcp.SetChecksum(^tcp.CalculateChecksum(xsum))
	return pkt
}

func TestReadPacketsOwnershipScratchOverwriteIPv4IPv6AndInvalidDrop(t *testing.T) {
	dev := newScriptedDevice(16)
	ing := &testIngress{udpCh: make(chan struct {
		flow Flow
		conn DatagramConn
	}, 4)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rt, err := StartReady(ctx, Config{
		Device:    dev,
		Ingress:   ing,
		Admitting: func() bool { return true },
		Epoch:     func() uint64 { return 1 },
	})
	if err != nil {
		t.Fatalf("StartReady: %v", err)
	}
	defer rt.Close(context.Background())

	v4Src := netip.MustParseAddrPort("10.50.0.2:4000")
	v4Dst := netip.MustParseAddrPort("203.0.113.1:4444")
	v4Payload := []byte("alpha-v4-payload-ownership-check")
	v4Frames, err := UDPReply(v4Src, v4Dst, v4Payload, 101)
	if err != nil {
		t.Fatal(err)
	}

	v6Src := netip.MustParseAddrPort("[fd50::2]:4001")
	v6Dst := netip.MustParseAddrPort("[2001:db8::1]:4445")
	v6Payload := []byte("bravo-v6-payload-ownership-check")
	v6Frames, err := UDPReply(v6Src, v6Dst, v6Payload, 202)
	if err != nil {
		t.Fatal(err)
	}

	// 1) Invalid lengths (n=0, n=-1, n=65536) and invalid IP version nibble (0x00)
	dev.reads <- scriptedReadItem{useForceN: true, forceN: 0, fillByte: 0xEE}
	dev.reads <- scriptedReadItem{useForceN: true, forceN: -1, fillByte: 0xEE}
	dev.reads <- scriptedReadItem{useForceN: true, forceN: 65536, fillByte: 0xEE}
	dev.reads <- scriptedReadItem{data: []byte{0x00, 0x01, 0x02, 0x03}, fillByte: 0xEE}

	// 2) Valid IPv4 packet followed immediately by IPv6 packet (which overwrites scratch with 0xFF)
	// and another invalid length read that overwrites the entire 65535B scratch with 0xAA.
	dev.reads <- scriptedReadItem{data: v4Frames[0], fillByte: 0x55}
	dev.reads <- scriptedReadItem{data: v6Frames[0], fillByte: 0xFF}
	dev.reads <- scriptedReadItem{useForceN: true, forceN: 0, fillByte: 0xAA}

	deadline := time.Now().Add(3 * time.Second)
	for rt.dropped.Load() < 5 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := rt.dropped.Load(); got != 5 {
		t.Fatalf("dropped=%d, want 5", got)
	}

	// Read from both UDP connections AFTER scratch was overwritten by subsequent reads.
	seenV4, seenV6 := false, false
	for i := 0; i < 2; i++ {
		select {
		case item := <-ing.udpCh:
			buf := make([]byte, 128)
			_ = item.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, target, err := item.conn.ReadDatagram(buf)
			if err != nil {
				t.Fatalf("ReadDatagram(%v): %v", item.flow, err)
			}
			if item.flow.Source == v4Src {
				seenV4 = true
				if target != v4Dst || !bytes.Equal(buf[:n], v4Payload) {
					t.Fatalf("IPv4 payload/target corrupted after scratch overwrite: got %q -> %v", buf[:n], target)
				}
			} else if item.flow.Source == v6Src {
				seenV6 = true
				if target != v6Dst || !bytes.Equal(buf[:n], v6Payload) {
					t.Fatalf("IPv6 payload/target corrupted after scratch overwrite: got %q -> %v", buf[:n], target)
				}
			} else {
				t.Fatalf("unexpected flow source: %v", item.flow.Source)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for UDP flows")
		}
	}
	if !seenV4 || !seenV6 {
		t.Fatalf("missing flows: seenV4=%v seenV6=%v", seenV4, seenV6)
	}

	// 3) Verify outbound writePackets path via IPv4 and IPv6 TCP SYN -> gVisor SYN-ACK -> r.link -> copyPacket -> WritePacket.
	syn4 := buildTCPSYN4(netip.MustParseAddrPort("10.50.0.9:50000"), netip.MustParseAddrPort("203.0.113.9:443"))
	dev.reads <- scriptedReadItem{data: syn4, fillByte: 0xCC}
	select {
	case out := <-dev.writes:
		if header.IPVersion(out) != header.IPv4Version || len(out) < header.IPv4MinimumSize+header.TCPMinimumSize {
			t.Fatalf("unexpected IPv4 outbound packet len=%d ver=%d", len(out), header.IPVersion(out))
		}
		ipHdr := header.IPv4(out)
		if ipHdr.TransportProtocol() != header.TCPProtocolNumber {
			t.Fatalf("unexpected IPv4 outbound protocol: %v", ipHdr.TransportProtocol())
		}
		tcpHdr := header.TCP(out[ipHdr.HeaderLength():])
		if tcpHdr.Flags()&(header.TCPFlagSyn|header.TCPFlagAck) != (header.TCPFlagSyn | header.TCPFlagAck) {
			t.Fatalf("expected IPv4 SYN-ACK flags, got %v", tcpHdr.Flags())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for outbound IPv4 TCP SYN-ACK from writePackets")
	}

	syn6 := buildTCPSYN6(netip.MustParseAddrPort("[fd50::9]:50001"), netip.MustParseAddrPort("[2001:db8::9]:443"))
	dev.reads <- scriptedReadItem{data: syn6, fillByte: 0xDD}
	for {
		select {
		case out := <-dev.writes:
			if header.IPVersion(out) != header.IPv6Version {
				continue
			}
			if len(out) < header.IPv6MinimumSize+header.TCPMinimumSize {
				t.Fatalf("short IPv6 outbound packet len=%d", len(out))
			}
			ipHdr := header.IPv6(out)
			if ipHdr.TransportProtocol() != header.TCPProtocolNumber {
				t.Fatalf("unexpected IPv6 outbound protocol: %v", ipHdr.TransportProtocol())
			}
			tcpHdr := header.TCP(out[header.IPv6MinimumSize:])
			if tcpHdr.Flags()&(header.TCPFlagSyn|header.TCPFlagAck) != (header.TCPFlagSyn | header.TCPFlagAck) {
				t.Fatalf("expected IPv6 SYN-ACK flags, got %v", tcpHdr.Flags())
			}
			return
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for outbound IPv6 TCP SYN-ACK from writePackets")
		}
	}
}

func TestRuntimeCloseAndCancelBoundedExit(t *testing.T) {
	for _, mode := range []string{"close", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			dev := newScriptedDevice(4)
			ing := &testIngress{udpCh: make(chan struct {
				flow Flow
				conn DatagramConn
			}, 1)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			rt, err := StartReady(ctx, Config{
				Device:    dev,
				Ingress:   ing,
				Admitting: func() bool { return true },
				Epoch:     func() uint64 { return 1 },
			})
			if err != nil {
				t.Fatalf("StartReady: %v", err)
			}

			if mode == "cancel" {
				cancel()
				select {
				case <-rt.Done():
				case <-time.After(2 * time.Second):
					t.Fatal("runtime did not stop within 2s after context cancel")
				}
			}
			closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer closeCancel()
			if err := rt.Close(closeCtx); err != nil {
				t.Fatalf("Close: %v", err)
			}
		})
	}
}

var benchRuntimePacketLen = 1420

func BenchmarkCopyPacketAsViewList(b *testing.B) {
	p, _ := buildMultiViewPacket(60, 20, 20, bytes.Repeat([]byte{0x42}, 700), bytes.Repeat([]byte{0x99}, 680))
	defer p.DecRef()
	wbuf := make([]byte, 65535)
	b.ReportAllocs()
	b.SetBytes(1420)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n := copyPacket(wbuf, p); n != 1420 {
			b.Fatalf("size=%d", n)
		}
	}
}

func BenchmarkCopyPacketAsSlicesBaseline(b *testing.B) {
	p, _ := buildMultiViewPacket(60, 20, 20, bytes.Repeat([]byte{0x42}, 700), bytes.Repeat([]byte{0x99}, 680))
	defer p.DecRef()
	wbuf := make([]byte, 65535)
	b.ReportAllocs()
	b.SetBytes(1420)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if n := legacyCopyAsSlices(wbuf, p); n != 1420 {
			b.Fatalf("size=%d", n)
		}
	}
}

func BenchmarkInboundMakeWithDataScratch(b *testing.B) {
	scratch := make([]byte, 65535)
	n := benchRuntimePacketLen
	for i := 0; i < n; i++ {
		scratch[i] = byte(i)
	}
	b.ReportAllocs()
	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := scratch[:n]
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(pkt)})
		p.DecRef()
	}
}

func BenchmarkInboundScratchCopyBaseline(b *testing.B) {
	scratch := make([]byte, 65535)
	n := benchRuntimePacketLen
	for i := 0; i < n; i++ {
		scratch[i] = byte(i)
	}
	b.ReportAllocs()
	b.SetBytes(int64(n))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cp := make([]byte, n)
		copy(cp, scratch[:n])
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(cp)})
		p.DecRef()
	}
}

type scriptedWriteBehavior struct {
	mu          sync.Mutex
	errSeq      []error
	waitOnCall  map[int]chan struct{}
	enteredCall map[int]chan struct{}
	calls       int
}

type backpressureDevice struct {
	*scriptedDevice
	wb scriptedWriteBehavior
}

func (d *backpressureDevice) WritePacket(b []byte) error {
	d.wb.mu.Lock()
	d.wb.calls++
	idx := d.wb.calls - 1
	var stepErr error
	if idx < len(d.wb.errSeq) {
		stepErr = d.wb.errSeq[idx]
	}
	waitCh := d.wb.waitOnCall[idx]
	enteredCh := d.wb.enteredCall[idx]
	d.wb.mu.Unlock()

	if enteredCh != nil {
		close(enteredCh)
	}
	if waitCh != nil {
		select {
		case <-waitCh:
		case <-d.closed:
			return io.ErrClosedPipe
		}
	}
	if stepErr != nil {
		return stepErr
	}
	return d.scriptedDevice.WritePacket(b)
}

func injectOutboundPacketWithRelease(r *Runtime, payload []byte, released *atomic.Int32) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload:   buffer.MakeWithData(append([]byte(nil), payload...)),
		OnRelease: func() { released.Add(1) },
	})
	var pkts stack.PacketBufferList
	pkts.PushBack(pkt)
	_, _ = r.link.WritePackets(pkts)
	pkt.DecRef()
}

func TestWritePacketsWintunRingFullDropContinueFatalAndDecRefOnce(t *testing.T) {
	t.Run("transient_wait_and_ring_full_exhaustion_keep_runtime_alive_and_decref_once", func(t *testing.T) {
		transientReady := make(chan struct{})
		transientEntered := make(chan struct{})
		dev := &backpressureDevice{
			scriptedDevice: newScriptedDevice(16),
			wb: scriptedWriteBehavior{
				errSeq: []error{
					nil, // call 0: transient 111 wait in Device.WritePacket then succeeds
					&tunplatform.WintunRingFullError{Cause: 111},                            // call 1: direct ring-full exhaustion -> drop + continue
					fmt.Errorf("wrapped: %w", &tunplatform.WintunRingFullError{Cause: 111}), // call 2: wrapped ring-full exhaustion -> drop + continue
					nil, // call 3: normal write after ring-full drops
				},
				waitOnCall:  map[int]chan struct{}{0: transientReady},
				enteredCall: map[int]chan struct{}{0: transientEntered},
			},
		}
		ing := &testIngress{udpCh: make(chan struct {
			flow Flow
			conn DatagramConn
		}, 4)}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		rt, err := StartReady(ctx, Config{
			Device:    dev,
			Ingress:   ing,
			Admitting: func() bool { return true },
			Epoch:     func() uint64 { return 1 },
		})
		if err != nil {
			t.Fatalf("StartReady: %v", err)
		}
		defer rt.Close(context.Background())

		var rel [4]atomic.Int32
		p0 := bytes.Repeat([]byte{0x45, 0x10}, 710) // 1420B
		p1 := bytes.Repeat([]byte{0x45, 0x20}, 710)
		p2 := bytes.Repeat([]byte{0x45, 0x30}, 710)
		p3 := bytes.Repeat([]byte{0x45, 0x40}, 710)

		injectOutboundPacketWithRelease(rt, p0, &rel[0])
		injectOutboundPacketWithRelease(rt, p1, &rel[1])
		injectOutboundPacketWithRelease(rt, p2, &rel[2])
		injectOutboundPacketWithRelease(rt, p3, &rel[3])

		select {
		case <-transientEntered:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for first packet to enter WritePacket")
		}
		// Unblock transient retry wait on packet 0.
		close(transientReady)

		var got0, got3 []byte
		select {
		case got0 = <-dev.writes:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for packet 0 write")
		}
		select {
		case got3 = <-dev.writes:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for packet 3 write after ring-full drops")
		}

		if !bytes.Equal(got0, p0) {
			t.Fatal("packet 0 bytes corrupted or wbuf reused prematurely during transient wait")
		}
		if !bytes.Equal(got3, p3) {
			t.Fatal("packet 3 bytes mismatch after ring-full drops")
		}
		if got := rt.dropped.Load(); got != 2 {
			t.Fatalf("rt.dropped=%d, want 2", got)
		}
		select {
		case <-rt.Failed():
			t.Fatalf("runtime must not fail on WintunRingFullError, err=%v", rt.Err())
		default:
		}
		if rt.Err() != nil {
			t.Fatalf("unexpected runtime error: %v", rt.Err())
		}
		for i := range rel {
			if got := rel[i].Load(); got != 1 {
				t.Fatalf("packet %d OnRelease count=%d, want 1 (strictly once DecRef)", i, got)
			}
		}
	})

	t.Run("eof_38_and_bare_errno_111_remain_fatal_and_decref_once", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			err  error
			code syscall.Errno
		}{
			{
				name: "eof_38",
				err:  fmt.Errorf("WINTUN_ALLOCATE: %w", syscall.Errno(38)),
				code: 38,
			},
			{
				name: "bare_errno_111_without_ring_full_type",
				err:  fmt.Errorf("WINTUN_ALLOCATE: %w", syscall.Errno(111)),
				code: 111,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dev := &backpressureDevice{
					scriptedDevice: newScriptedDevice(4),
					wb:             scriptedWriteBehavior{errSeq: []error{tc.err}},
				}
				ing := &testIngress{udpCh: make(chan struct {
					flow Flow
					conn DatagramConn
				}, 1)}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				rt, err := StartReady(ctx, Config{
					Device:    dev,
					Ingress:   ing,
					Admitting: func() bool { return true },
					Epoch:     func() uint64 { return 1 },
				})
				if err != nil {
					t.Fatalf("StartReady: %v", err)
				}
				defer rt.Close(context.Background())

				var rel atomic.Int32
				injectOutboundPacketWithRelease(rt, bytes.Repeat([]byte{0x45, 0x01}, 100), &rel)

				select {
				case <-rt.Failed():
				case <-time.After(2 * time.Second):
					t.Fatalf("%s: expected runtime fatal on non-ring-full write error", tc.name)
				}
				if got := rt.dropped.Load(); got != 0 {
					t.Fatalf("%s: fatal write error must not increment dropped, got %d", tc.name, got)
				}
				var f *Failure
				if !errors.As(rt.Err(), &f) || f.Code != "TUN_DEVICE_WRITE_FAILED" || !errors.Is(f.Cause, tc.code) {
					t.Fatalf("%s: unexpected fatal error: %#v", tc.name, rt.Err())
				}
				if got := rel.Load(); got != 1 {
					t.Fatalf("%s: OnRelease count=%d, want 1", tc.name, got)
				}
			})
		}
	})

	t.Run("close_and_cancel_wake_inflight_write_wait_cleanly", func(t *testing.T) {
		for _, mode := range []string{"close", "cancel"} {
			t.Run(mode, func(t *testing.T) {
				neverReady := make(chan struct{})
				entered := make(chan struct{})
				dev := &backpressureDevice{
					scriptedDevice: newScriptedDevice(4),
					wb: scriptedWriteBehavior{
						waitOnCall:  map[int]chan struct{}{0: neverReady},
						enteredCall: map[int]chan struct{}{0: entered},
					},
				}
				ing := &testIngress{udpCh: make(chan struct {
					flow Flow
					conn DatagramConn
				}, 1)}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()

				rt, err := StartReady(ctx, Config{
					Device:    dev,
					Ingress:   ing,
					Admitting: func() bool { return true },
					Epoch:     func() uint64 { return 1 },
				})
				if err != nil {
					t.Fatalf("StartReady: %v", err)
				}

				var rel atomic.Int32
				injectOutboundPacketWithRelease(rt, bytes.Repeat([]byte{0x45, 0x99}, 100), &rel)

				select {
				case <-entered:
				case <-time.After(2 * time.Second):
					t.Fatal("timed out waiting for WritePacket to enter wait")
				}

				if mode == "cancel" {
					cancel()
					select {
					case <-rt.Done():
					case <-time.After(2 * time.Second):
						t.Fatal("runtime did not finish after cancel during WritePacket wait")
					}
				}
				closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer closeCancel()
				if err := rt.Close(closeCtx); err != nil {
					t.Fatalf("Close: %v", err)
				}
				if rt.Err() != nil {
					t.Fatalf("expected nil fatal error on %s, got %v", mode, rt.Err())
				}
				if got := rel.Load(); got != 1 {
					t.Fatalf("OnRelease count=%d, want 1", got)
				}
			})
		}
	})
}
