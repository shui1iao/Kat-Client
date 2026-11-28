package tunstack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/tunplatform"
)

type scriptedReadItem struct {
	pkt []byte
	err error
}

type scriptedDevice struct {
	reads   chan scriptedReadItem
	writes  chan []byte
	closed  chan struct{}
	once    sync.Once
	closeFn func() error
}

func newScriptedDevice(buf int) *scriptedDevice {
	return &scriptedDevice{
		reads:  make(chan scriptedReadItem, buf),
		writes: make(chan []byte, buf),
		closed: make(chan struct{}),
	}
}

func (d *scriptedDevice) ReadPacket(dst []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, net.ErrClosed
	case item := <-d.reads:
		if item.err != nil {
			return 0, item.err
		}
		return copy(dst, item.pkt), nil
	}
}

func (d *scriptedDevice) WritePacket(src []byte) error {
	select {
	case <-d.closed:
		return net.ErrClosed
	default:
	}
	cp := append([]byte(nil), src...)
	select {
	case <-d.closed:
		return net.ErrClosed
	case d.writes <- cp:
		return nil
	}
}

func (d *scriptedDevice) Close() error {
	var err error
	d.once.Do(func() {
		close(d.closed)
		if d.closeFn != nil {
			err = d.closeFn()
		}
	})
	return err
}

type testIngress struct {
	udpCh chan struct {
		flow Flow
		conn DatagramConn
	}
}

func (i *testIngress) HandleTCP(context.Context, Flow, TCPConn) error { return nil }
func (i *testIngress) HandleUDP(ctx context.Context, f Flow, c net.Conn) error {
	dc, _ := c.(DatagramConn)
	select {
	case i.udpCh <- struct {
		flow Flow
		conn DatagramConn
	}{f, dc}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

type scriptedWriteBehavior struct {
	mu     sync.Mutex
	errSeq []error
	idx    int
}

func (b *scriptedWriteBehavior) nextErr() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.idx >= len(b.errSeq) {
		return nil
	}
	e := b.errSeq[b.idx]
	b.idx++
	return e
}

type backpressureDevice struct {
	*scriptedDevice
	wb scriptedWriteBehavior
}

func (d *backpressureDevice) WritePacket(src []byte) error {
	if err := d.wb.nextErr(); err != nil {
		return err
	}
	return d.scriptedDevice.WritePacket(src)
}

func TestReadPacketsOwnershipScratchOverwriteIPv4IPv6AndInvalidDrop(t *testing.T) {
	dev := newScriptedDevice(16)
	ing := &testIngress{udpCh: make(chan struct {
		flow Flow
		conn DatagramConn
	}, 4)}
	rt, err := StartReady(context.Background(), Config{
		Device:    dev,
		Ingress:   ing,
		Admitting: func() bool { return true },
		Epoch:     func() uint64 { return 1 },
	})
	if err != nil {
		t.Fatalf("StartReady: %v", err)
	}
	defer rt.Close(context.Background())

	// 1) Invalid packet is dropped without stopping the pump.
	dev.reads <- scriptedReadItem{pkt: []byte{0x00, 0x01, 0x02}}

	// 2) Valid IPv4 and IPv6 UDP packets survive scratch buffer reuse.
	src4 := netip.MustParseAddrPort("198.18.0.1:41001")
	dst4 := netip.MustParseAddrPort("203.0.113.10:53")
	p4, err := UDPReply(src4, dst4, []byte("v4-body"), 1)
	if err != nil {
		t.Fatal(err)
	}
	src6 := netip.MustParseAddrPort("[fd4b:6174::1]:41002")
	dst6 := netip.MustParseAddrPort("[2001:db8::10]:53")
	p6, err := UDPReply(src6, dst6, []byte("v6-body"), 2)
	if err != nil {
		t.Fatal(err)
	}
	dev.reads <- scriptedReadItem{pkt: p4[0]}
	dev.reads <- scriptedReadItem{pkt: p6[0]}

	seen := map[string]bool{}
	for len(seen) < 2 {
		select {
		case got := <-ing.udpCh:
			buf := make([]byte, 128)
			_ = got.conn.SetReadDeadline(time.Now().Add(time.Second))
			n, peer, err := got.conn.ReadDatagram(buf)
			if err != nil {
				t.Fatalf("ReadDatagram: %v", err)
			}
			if peer == dst4 && bytes.Equal(buf[:n], []byte("v4-body")) {
				seen["v4"] = true
			} else if peer == dst6 && bytes.Equal(buf[:n], []byte("v6-body")) {
				seen["v6"] = true
			} else {
				t.Fatalf("unexpected datagram peer=%v body=%q", peer, buf[:n])
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for IPv4/IPv6 UDP delivery, seen=%v", seen)
		}
	}
	if rt.dropped.Load() < 1 {
		t.Fatalf("expected invalid packet drop >= 1, got %d", rt.dropped.Load())
	}
}

func TestRuntimeCloseAndCancelBoundedExit(t *testing.T) {
	for _, mode := range []string{"close", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			dev := newScriptedDevice(4)
			var closes atomic.Int32
			dev.closeFn = func() error { closes.Add(1); return nil }
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
			} else {
				cctx, ccancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer ccancel()
				if err := rt.Close(cctx); err != nil {
					t.Fatalf("Close: %v", err)
				}
			}
			select {
			case <-rt.Done():
			case <-time.After(2 * time.Second):
				t.Fatal("runtime Done did not close within budget")
			}
			if closes.Load() != 1 {
				t.Fatalf("device close count = %d, want 1", closes.Load())
			}
		})
	}
}

func TestWritePacketsWintunRingFullDropContinueAndFatal(t *testing.T) {
	t.Run("ring_full_drops_without_fatal", func(t *testing.T) {
		dev := &backpressureDevice{
			scriptedDevice: newScriptedDevice(8),
			wb: scriptedWriteBehavior{
				errSeq: []error{&tunplatform.WintunRingFullError{Cause: syscall.Errno(111)}, nil},
			},
		}
		rt, err := StartReady(context.Background(), Config{
			Device: dev,
			Ingress: &testIngress{udpCh: make(chan struct {
				flow Flow
				conn DatagramConn
			}, 1)},
			Admitting: func() bool { return true },
			Epoch:     func() uint64 { return 1 },
		})
		if err != nil {
			t.Fatal(err)
		}
		defer rt.Close(context.Background())

		rt.writeRawPacket([]byte{0x45, 0x00})
		rt.writeRawPacket([]byte{0x45, 0x01})
		if rt.dropped.Load() != 1 {
			t.Fatalf("dropped=%d want 1", rt.dropped.Load())
		}
		if rt.Err() != nil {
			t.Fatalf("unexpected fatal on ring full: %v", rt.Err())
		}
		if len(dev.writes) != 1 {
			t.Fatalf("expected 1 successful write, got %d", len(dev.writes))
		}
	})

	t.Run("non_overflow_write_error_is_fatal", func(t *testing.T) {
		dev := &backpressureDevice{
			scriptedDevice: newScriptedDevice(8),
			wb: scriptedWriteBehavior{
				errSeq: []error{fmt.Errorf("WINTUN_ALLOCATE: %w", syscall.Errno(38))},
			},
		}
		rt, err := StartReady(context.Background(), Config{
			Device: dev,
			Ingress: &testIngress{udpCh: make(chan struct {
				flow Flow
				conn DatagramConn
			}, 1)},
			Admitting: func() bool { return true },
			Epoch:     func() uint64 { return 1 },
		})
		if err != nil {
			t.Fatal(err)
		}
		defer rt.Close(context.Background())

		rt.writeRawPacket([]byte{0x45, 0x00})
		select {
		case <-rt.Failed():
		case <-time.After(time.Second):
			t.Fatal("expected Failed() closed on fatal write error")
		}
		var f *Failure
		if !errors.As(rt.Err(), &f) || f.Code != "TUN_DEVICE_WRITE_FAILED" {
			t.Fatalf("unexpected error: %v", rt.Err())
		}
	})
}
