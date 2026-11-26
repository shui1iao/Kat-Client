package tunstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/shui1iao/Kat/internal/tunplatform"
)

func m2Input(t *testing.T, src, dst netip.AddrPort, mutate func([]byte), run func(ipPacket)) {
	t.Helper()
	frames, e := UDPReply(src, dst, []byte("test"), 1)
	if e != nil {
		t.Fatal(e)
	}
	wire := frames[0]
	mutate(wire)
	pkt, _, ok := parseIPPacket(wire)
	if !ok {
		t.Fatal("parseIPPacket rejected wire")
	}
	run(pkt)
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
			}, func(p ipPacket) { r.handleUDP(p) })
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
		m2Input(t, src, dst, func([]byte) {}, func(p ipPacket) { r.handleUDP(p) })
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
		t.Fatal("close leaked queued bytes")
	}
}

func TestM2UDPWriteFromRingFullDropsWithoutFatalAndPreservesFragmentSemantics(t *testing.T) {
	src := netip.MustParseAddrPort("198.18.0.1:41000")
	peer := netip.MustParseAddrPort("203.0.113.50:4444")

	t.Run("ring_full_single_and_fragmented_drop_then_recover", func(t *testing.T) {
		dev := &backpressureDevice{
			scriptedDevice: newScriptedDevice(8),
			wb: scriptedWriteBehavior{
				errSeq: []error{
					&tunplatform.WintunRingFullError{Cause: syscall.Errno(111)},
					nil,
					&tunplatform.WintunRingFullError{Cause: syscall.Errno(111)},
					nil,
				},
			},
		}
		r := &Runtime{
			ctx:        context.Background(),
			cfg:        Config{Device: dev, Admitting: func() bool { return true }, Epoch: func() uint64 { return 1 }},
			udpSources: map[sourceKey]*sourceConn{},
			active:     map[net.Conn]struct{}{},
			failed:     make(chan struct{}),
			done:       make(chan struct{}),
		}
		k := sourceKey{src, 1}
		c := &sourceConn{r: r, key: k, first: peer, queue: make(chan udpMessage, 4), closed: make(chan struct{}), changed: make(chan struct{})}
		r.udpSources[k] = c

		n, err := c.WriteFrom([]byte("small-udp"), peer)
		if n != 0 || err == nil || !errors.Is(err, tunplatform.ErrWintunRingFull) {
			t.Fatalf("expected (0, WintunRingFullError), got (%d, %v)", n, err)
		}
		if got := r.dropped.Load(); got != 1 {
			t.Fatalf("dropped=%d, want 1", got)
		}
		if r.stopping || r.Err() != nil {
			t.Fatalf("runtime must not stop/fatal on UDP ring full: stopping=%v err=%v", r.stopping, r.Err())
		}
		if len(dev.writes) != 0 {
			t.Fatalf("expected 0 written packets on first call, got %d", len(dev.writes))
		}

		large := bytes.Repeat([]byte{0x7A}, 2000)
		n, err = c.WriteFrom(large, peer)
		if n != 0 || err == nil || !errors.Is(err, tunplatform.ErrWintunRingFull) {
			t.Fatalf("expected (0, WintunRingFullError) on second fragment overflow, got (%d, %v)", n, err)
		}
		if got := r.dropped.Load(); got != 2 {
			t.Fatalf("dropped=%d, want 2", got)
		}
		if r.stopping || r.Err() != nil {
			t.Fatalf("runtime must not stop/fatal on fragmented UDP ring full: stopping=%v err=%v", r.stopping, r.Err())
		}
		if len(dev.writes) != 1 {
			t.Fatalf("expected fragment 0 (1 packet) already sent before fragment 1 failure, got %d", len(dev.writes))
		}
		<-dev.writes

		next := []byte("recovered-udp-reply")
		n, err = c.WriteFrom(next, peer)
		if err != nil || n != len(next) {
			t.Fatalf("expected (%d, nil) after recovery, got (%d, %v)", len(next), n, err)
		}
		if len(dev.writes) != 1 {
			t.Fatalf("expected 1 written packet for recovered datagram, got %d", len(dev.writes))
		}
	})

	t.Run("eof_38_on_udp_writefrom_remains_fatal", func(t *testing.T) {
		dev := &backpressureDevice{
			scriptedDevice: newScriptedDevice(4),
			wb:             scriptedWriteBehavior{errSeq: []error{fmt.Errorf("WINTUN_ALLOCATE: %w", syscall.Errno(38))}},
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

		k := sourceKey{src, 1}
		c := &sourceConn{r: rt, key: k, first: peer, queue: make(chan udpMessage, 4), closed: make(chan struct{}), changed: make(chan struct{})}
		rt.mu.Lock()
		rt.udpSources[k] = c
		rt.mu.Unlock()

		n, werr := c.WriteFrom([]byte("fatal-pkt"), peer)
		if n != 0 || !errors.Is(werr, syscall.Errno(38)) {
			t.Fatalf("expected (0, errno 38), got (%d, %v)", n, werr)
		}
		select {
		case <-rt.Failed():
		default:
			t.Fatal("expected runtime Failed() to be closed on EOF 38")
		}
		if got := rt.dropped.Load(); got != 0 {
			t.Fatalf("fatal UDP write must not increment dropped, got %d", got)
		}
	})
}
