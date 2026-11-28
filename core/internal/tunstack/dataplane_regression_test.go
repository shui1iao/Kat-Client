package tunstack

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func buildTestIPv4UDP(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte, df bool) []byte {
	s4, d4 := srcIP.As4(), dstIP.As4()
	udpLen := 8 + len(payload)
	ipLen := 20 + udpLen
	pkt := make([]byte, ipLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipLen))
	if df {
		binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	}
	pkt[8] = 64
	pkt[9] = ipProtoUDP
	copy(pkt[12:16], s4[:])
	copy(pkt[16:20], d4[:])
	binary.BigEndian.PutUint16(pkt[10:12], folded(sum16(pkt[:20])))
	u := pkt[20:]
	binary.BigEndian.PutUint16(u[0:2], srcPort)
	binary.BigEndian.PutUint16(u[2:4], dstPort)
	binary.BigEndian.PutUint16(u[4:6], uint16(udpLen))
	copy(u[8:], payload)
	pseudo := addr4Sum(s4) + addr4Sum(d4) + ipProtoUDP + uint32(udpLen)
	csum := folded(pseudo + sum16(u))
	if csum == 0 {
		csum = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:8], csum)
	return pkt
}

func fragmentTestIPv4(fullPkt []byte, id uint16, maxFragPayload int) [][]byte {
	ihl := int(fullPkt[0]&0x0f) * 4
	body := fullPkt[ihl:]
	var frags [][]byte
	for off := 0; off < len(body); {
		chunk := maxFragPayload &^ 7
		rem := len(body) - off
		more := true
		if rem <= maxFragPayload {
			chunk = rem
			more = false
		}
		f := make([]byte, ihl+chunk)
		copy(f[:ihl], fullPkt[:ihl])
		binary.BigEndian.PutUint16(f[2:4], uint16(ihl+chunk))
		binary.BigEndian.PutUint16(f[4:6], id)
		flagsOff := uint16(off / 8)
		if more {
			flagsOff |= 0x2000
		}
		binary.BigEndian.PutUint16(f[6:8], flagsOff)
		f[10], f[11] = 0, 0
		binary.BigEndian.PutUint16(f[10:12], folded(sum16(f[:ihl])))
		copy(f[ihl:], body[off:off+chunk])
		frags = append(frags, f)
		off += chunk
	}
	return frags
}

func TestRegressionUDPPooledDispatchFragReassemblyAndIdleEviction(t *testing.T) {
	dev := &funcDevice{
		readFn: func([]byte) (int, error) {
			time.Sleep(50 * time.Millisecond)
			return 0, context.Canceled
		},
		writeFn: func([]byte) error { return nil },
	}

	unblock := make(chan struct{})
	gotNewActive := make(chan []byte, 4)
	var admitted atomic.Int64

	ing := &funcIngress{
		udpFn: func(ctx context.Context, f Flow, c net.Conn) error {
			admitted.Add(1)
			dc := c.(DatagramConn)
			buf := make([]byte, 65535)
			n, _, err := dc.ReadDatagram(buf)
			if err != nil {
				return nil
			}
			if f.Source.Port() == 61000 {
				gotNewActive <- append([]byte(nil), buf[:n]...)
			}
			select {
			case <-unblock:
			case <-ctx.Done():
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

	src4 := netip.MustParseAddr("198.18.0.1")
	dst4 := netip.MustParseAddr("203.0.113.99")

	// Fill up to maxHandlers (1024) sessions, marking port 20000 as idle > 3s ago.
	for i := 0; i < maxHandlers; i++ {
		sp := uint16(20000 + i)
		pkt := buildTestIPv4UDP(src4, dst4, sp, 53, []byte("seed"), false)
		r.dispatchPacket(pkt)
	}
	r.mu.Lock()
	idleKey := sourceKey{netip.AddrPortFrom(src4, 20000), 1}
	if victim := r.udpSources[idleKey]; victim != nil {
		victim.lastActive.Store(time.Now().Add(-5 * time.Second).UnixNano())
	} else {
		r.mu.Unlock()
		t.Fatal("missing seeded session 20000")
	}
	r.mu.Unlock()

	// Send a fragmented 12KiB UDP packet from new active port 61000 (out-of-order: tail first!)
	wantPay := bytes.Repeat([]byte("ACTIVE-FRAG-"), 1024) // 12288 B
	bigPkt := buildTestIPv4UDP(src4, dst4, 61000, 443, wantPay, false)
	frags := fragmentTestIPv4(bigPkt, 999, 1380)
	for i := len(frags) - 1; i >= 0; i-- {
		r.dispatchPacket(frags[i])
	}

	select {
	case got := <-gotNewActive:
		if !bytes.Equal(got, wantPay) {
			t.Fatalf("reassembled payload mismatch: len=%d want=%d", len(got), len(wantPay))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected idle UDP session to be evicted and new active flow 61000 admitted")
	}

	close(unblock)
	cancel()
	r.wg.Wait()
}

func BenchmarkTUNIPFragReassembly60K(b *testing.B) {
	src4 := netip.MustParseAddr("198.18.0.1")
	dst4 := netip.MustParseAddr("203.0.113.99")
	big := buildTestIPv4UDP(src4, dst4, 41000, 5000, make([]byte, 60*1024), false)
	frags := fragmentTestIPv4(big, 777, 1400)
	ra := newIPReassembler()
	b.ReportAllocs()
	b.SetBytes(int64(len(big)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var done bool
		// Tail-first delivery exercises upfront exact allocation; alternate with in-order every odd iteration.
		if i%2 == 0 {
			for j := len(frags) - 1; j >= 0; j-- {
				_, fm, ok := parseIPPacket(frags[j])
				if !ok || fm == nil {
					b.Fatal("expected fragment")
				}
				_, done = ra.push(fm)
			}
		} else {
			for _, raw := range frags {
				_, fm, ok := parseIPPacket(raw)
				if !ok || fm == nil {
					b.Fatal("expected fragment")
				}
				_, done = ra.push(fm)
			}
		}
		if !done {
			b.Fatal("reassembly incomplete")
		}
	}
}
