package anytls

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	A "github.com/shui1iao/Kat/internal/anytls"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/internal/tlsclient"
)

func TestStreamQueueReusesBackingCapacityAndClearsReferences(t *testing.T) {
	s := &session{
		o:       &Outbound{},
		streams: make(map[uint32]*stream),
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	st := newStream(s, 1)

	for round := 0; round < 5; round++ {
		for j := 0; j < 8; j++ {
			st.push([]byte{byte(round), byte(j), 1, 2})
		}
		if round == 0 {
			if cap(st.in) < 8 {
				t.Fatalf("expected cap >= 8, got %d", cap(st.in))
			}
		}
		buf := make([]byte, 4)
		for j := 0; j < 8; j++ {
			n, err := st.Read(buf)
			if err != nil || n != 4 {
				t.Fatalf("round %d frame %d: Read = (%d, %v)", round, j, n, err)
			}
		}
		if len(st.in) != 0 || st.inHead != 0 {
			t.Fatalf("round %d: expected drained queue (len=%d, head=%d)", round, len(st.in), st.inHead)
		}
		if cap(st.in) < 8 {
			t.Fatalf("round %d: backing capacity lost after drain: cap=%d", round, cap(st.in))
		}
		backing := st.in[:cap(st.in)]
		for idx, slot := range backing {
			if slot != nil {
				t.Fatalf("round %d slot %d still references payload", round, idx)
			}
		}
	}

	st.push([]byte("tail"))
	st.remoteClose(io.EOF)
	buf := make([]byte, 8)
	n, err := st.Read(buf)
	if err != nil || string(buf[:n]) != "tail" {
		t.Fatalf("Read tail = (%q, %v)", buf[:n], err)
	}
	if st.in != nil || st.inHead != 0 {
		t.Fatalf("expected st.in == nil after reading final frame post-EOF, got cap=%d", cap(st.in))
	}
}

func BenchmarkStreamPushRead(b *testing.B) {
	s := &session{done: make(chan struct{})}
	st := newStream(s, 1)
	chunk := make([]byte, 1024)
	buf := make([]byte, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 4; j++ {
			st.push(chunk)
		}
		for j := 0; j < 4; j++ {
			if _, err := st.Read(buf); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkPacketConnWriteToIPv4(b *testing.B) {
	s := &session{
		wake: make(chan struct{}, 1),
		done: make(chan struct{}),
	}
	go func() {
		for {
			select {
			case <-s.wake:
				s.mu.Lock()
				q := s.queue
				s.queue = s.queue[:0]
				s.mu.Unlock()
				for _, req := range q {
					req.done <- nil
				}
			case <-s.done:
				return
			}
		}
	}()
	defer close(s.done)

	st := newStream(s, 1)
	pc := &packetConn{st: st, headerSent: true}
	payload := make([]byte, 512)
	dst := outbound.Addr{Host: "1.1.1.1", Port: 53}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pc.WriteTo(payload, dst); err != nil {
			b.Fatal(err)
		}
	}
}

func resetRecvPoolForTest() {
	recvPool.mu.Lock()
	for i := range recvPool.classes {
		recvPool.classes[i] = nil
		recvPool.lastUsed[i] = 0
	}
	recvPool.seq = 0
	recvPool.bytes = 0
	recvPool.mu.Unlock()
}

func recvPoolCountForClass(idx int) (slots, totalBytes int) {
	recvPool.mu.Lock()
	defer recvPool.mu.Unlock()
	return len(recvPool.classes[idx]), recvPool.bytes
}

func TestRecvBufPoolReleaseBoundaries(t *testing.T) {
	resetRecvPoolForTest()
	t.Cleanup(resetRecvPoolForTest)

	// 1. Head-offset slice guard: an offset slice must never enter the pool.
	raw := acquireRecvBuf(4096)
	idx4k := recvClassIndex(4096)
	if idx4k < 0 || cap(raw) != recvClassCaps[idx4k] {
		t.Fatalf("unexpected class=%d cap=%d", idx4k, cap(raw))
	}
	releaseRecvBuf(raw[7:])
	if slots, _ := recvPoolCountForClass(idx4k); slots != 0 {
		t.Fatalf("head-offset slice was erroneously accepted into pool: slots=%d", slots)
	}
	releaseRecvBuf(raw)
	if slots, _ := recvPoolCountForClass(idx4k); slots != 1 {
		t.Fatalf("original slice was not accepted into pool: slots=%d", slots)
	}

	// 2. Partial Read keeps ownership in st.in; full Read releases to pool.
	s := &session{
		o:       &Outbound{},
		streams: make(map[uint32]*stream),
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	st := newStream(s, 1)
	b := acquireRecvBuf(4096)
	for i := range b {
		b[i] = byte(i)
	}
	if slots, _ := recvPoolCountForClass(idx4k); slots != 0 {
		t.Fatalf("expected pool empty after acquire, got %d", slots)
	}
	st.pushPooled(b)
	part := make([]byte, 1500)
	n, err := st.Read(part)
	if err != nil || n != 1500 {
		t.Fatalf("partial Read = (%d, %v)", n, err)
	}
	if slots, _ := recvPoolCountForClass(idx4k); slots != 0 {
		t.Fatalf("partially read buffer released prematurely: slots=%d", slots)
	}
	rest := make([]byte, 4096)
	n, err = st.Read(rest)
	if err != nil || n != 4096-1500 {
		t.Fatalf("rest Read = (%d, %v)", n, err)
	}
	if slots, _ := recvPoolCountForClass(idx4k); slots != 1 {
		t.Fatalf("fully read buffer not returned to pool: slots=%d", slots)
	}

	// 3. Close() releases both partially-read head frame and unread queued frames.
	st2 := newStream(s, 2)
	b1 := acquireRecvBuf(4096)
	b2 := acquireRecvBuf(4096)
	st2.pushPooled(b1)
	st2.pushPooled(b2)
	if _, err := st2.Read(make([]byte, 500)); err != nil {
		t.Fatal(err)
	}
	if slots, _ := recvPoolCountForClass(idx4k); slots != 0 {
		t.Fatalf("expected 0 pooled before Close, got %d", slots)
	}
	_ = st2.Close()
	if slots, _ := recvPoolCountForClass(idx4k); slots != 2 {
		t.Fatalf("Close did not release queued/partial buffers: got %d, want 2", slots)
	}
	// Push after Close immediately releases buffer to pool.
	bAfterClose := acquireRecvBuf(4096)
	st2.pushPooled(bAfterClose)
	if slots, _ := recvPoolCountForClass(idx4k); slots != 2 {
		t.Fatalf("pushPooled on closed stream leaked buffer: got %d, want 2", slots)
	}

	// 4. remoteClose (FIN) retains unread frames until Read, and rejects post-FIN pushPooled.
	resetRecvPoolForTest()
	st3 := newStream(s, 3)
	bfin := acquireRecvBuf(4096)
	copy(bfin, bytes.Repeat([]byte{0xab}, 4096))
	st3.pushPooled(bfin)
	st3.remoteClose(io.EOF)
	if slots, _ := recvPoolCountForClass(idx4k); slots != 0 {
		t.Fatalf("remoteClose released unread buffer before application Read: slots=%d", slots)
	}
	bPostFIN := acquireRecvBuf(4096)
	st3.pushPooled(bPostFIN)
	if slots, _ := recvPoolCountForClass(idx4k); slots != 1 {
		t.Fatalf("pushPooled after FIN did not release buffer: slots=%d", slots)
	}
	out := make([]byte, 4096)
	if n, err := st3.Read(out); err != nil || n != 4096 {
		t.Fatalf("Read after FIN = (%d, %v)", n, err)
	}
	if slots, _ := recvPoolCountForClass(idx4k); slots != 2 {
		t.Fatalf("Read draining FIN frame did not release buffer: slots=%d", slots)
	}
	if _, err := st3.Read(out); err != io.EOF {
		t.Fatalf("expected EOF after draining FIN stream, got %v", err)
	}

	// 5. Backpressure overflow wait aborted by session failure releases in-flight buffer.
	resetRecvPoolForTest()
	sFail := &session{
		o:       &Outbound{},
		streams: make(map[uint32]*stream),
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	st4 := newStream(sFail, 4)
	idxMax := recvClassIndex(maxFrame)
	var held [][]byte
	for st4.inBytes+maxFrame <= maxStreamBuffer {
		f := acquireRecvBuf(maxFrame)
		held = append(held, f)
		st4.pushPooled(f)
	}
	blockedDone := make(chan struct{})
	go func() {
		defer close(blockedDone)
		extra := acquireRecvBuf(maxFrame)
		st4.pushPooled(extra)
	}()
	time.Sleep(20 * time.Millisecond)
	close(sFail.done)
	<-blockedDone
	if slots, _ := recvPoolCountForClass(idxMax); slots != 1 {
		t.Fatalf("aborted backpressure pushPooled did not release buffer: got %d, want 1", slots)
	}
	_ = st4.Close()

	// 6. readFrames io.ReadFull failure mid-frame releases buffer back to pool.
	resetRecvPoolForTest()
	c1, c2 := net.Pipe()
	sRead := &session{
		o:       &Outbound{},
		conn:    c1,
		streams: make(map[uint32]*stream),
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	st5 := newStream(sRead, 5)
	sRead.streams[5] = st5
	go func() {
		var hdr [headerSize]byte
		hdr[0] = cmdPSH
		binary.BigEndian.PutUint32(hdr[1:5], 5)
		binary.BigEndian.PutUint16(hdr[5:7], 4096)
		_, _ = c2.Write(hdr[:])
		_, _ = c2.Write(make([]byte, 1000)) // truncated frame
		_ = c2.Close()
	}()
	err = sRead.readFrames()
	_ = c1.Close()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("readFrames truncated error = %v, want ErrUnexpectedEOF", err)
	}
	if slots, _ := recvPoolCountForClass(idx4k); slots != 1 {
		t.Fatalf("readFrames ReadFull error did not release buffer: got %d, want 1", slots)
	}

	// 7. Hard pool bounds (maxRecvPoolBytes and maxRecvClassSlot).
	resetRecvPoolForTest()
	allocs := make([][]byte, 64)
	for i := range allocs {
		allocs[i] = acquireRecvBuf(maxFrame)
	}
	for _, a := range allocs {
		releaseRecvBuf(a)
	}
	slots, totalBytes := recvPoolCountForClass(idxMax)
	if totalBytes > maxRecvPoolBytes || slots > maxRecvClassSlot {
		t.Fatalf("pool exceeded bounds: slots=%d (max %d) bytes=%d (max %d)", slots, maxRecvClassSlot, totalBytes, maxRecvPoolBytes)
	}
}

func TestStreamReadCoalescesReadyFramesWithoutWaiting(t *testing.T) {
	resetRecvPoolForTest()
	t.Cleanup(resetRecvPoolForTest)

	s := &session{
		o:       &Outbound{},
		streams: make(map[uint32]*stream),
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	st := newStream(s, 1)

	// Push 4 ready frames of 4096B each; a single Read(32KiB) must coalesce all 4
	// (16384B) and return immediately without blocking for the remaining 16KiB.
	var want []byte
	for i := 0; i < 4; i++ {
		f := acquireRecvBuf(4096)
		fill := pattern(i+1, 4096)
		copy(f, fill)
		want = append(want, fill...)
		st.pushPooled(f)
	}
	buf := make([]byte, 32<<10)
	n, err := st.Read(buf)
	if err != nil || n != 16384 {
		t.Fatalf("coalesced Read = (%d, %v), want (16384, nil)", n, err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatal("coalesced Read payload mismatch")
	}

	// Partial head frame (off > 0) + subsequent whole frames that fit into caller buffer.
	want = want[:0]
	for i := 0; i < 3; i++ {
		f := acquireRecvBuf(4096)
		fill := pattern(i+10, 4096)
		copy(f, fill)
		want = append(want, fill...)
		st.pushPooled(f)
	}
	// Short read on first frame leaves an already-partial head frame (st.off == 1500, remaining 2596B).
	first := make([]byte, 1500)
	n1, err := st.Read(first)
	if err != nil || n1 != 1500 {
		t.Fatalf("first partial Read = (%d, %v), want (1500, nil)", n1, err)
	}
	// Next Read(8192) drains the remaining 2596B of frame 0 plus all 4096B of frame 1 (total 6692B),
	// and stops at the boundary of frame 2 (4096B > remaining 1500B in caller buffer) without splitting frame 2.
	second := make([]byte, 8192)
	n2, err := st.Read(second)
	if err != nil || n2 != (4096-1500)+4096 {
		t.Fatalf("second Read = (%d, %v), want (%d, nil)", n2, err, (4096-1500)+4096)
	}
	third := make([]byte, 8192)
	n3, err := st.Read(third)
	if err != nil || n3 != 4096 {
		t.Fatalf("third Read = (%d, %v), want (4096, nil)", n3, err)
	}
	got := append(append(first[:n1], second[:n2]...), third[:n3]...)
	if !bytes.Equal(got, want) {
		t.Fatal("partial + frame-boundary coalesced Read payload mismatch")
	}
}

func TestStreamReadFrameBoundaryNo1ByteSpillAndSemantics(t *testing.T) {
	resetRecvPoolForTest()
	t.Cleanup(resetRecvPoolForTest)

	idxMax := recvClassIndex(maxFrame)
	idx8k := recvClassIndex(8192)
	idx2k := recvClassIndex(2048)

	// 1. 65536B caller buffer vs two ready 65535B (maxFrame) frames:
	// First Read(65536) must return 65535, release frame 0 immediately to pool,
	// and leave frame 1 untouched at off==0 (no 1-byte split, no simultaneous 2-frame hold across downstream Write).
	t.Run("65536_vs_two_65535_frames_no_1byte_split", func(t *testing.T) {
		resetRecvPoolForTest()
		s := &session{
			o:       &Outbound{},
			streams: make(map[uint32]*stream),
			wake:    make(chan struct{}, 1),
			done:    make(chan struct{}),
		}
		st := newStream(s, 1)

		var want []byte
		const rounds = 4
		for r := 0; r < rounds; r++ {
			f1 := acquireRecvBuf(maxFrame)
			f2 := acquireRecvBuf(maxFrame)
			p1 := pattern(r*2+1, maxFrame)
			p2 := pattern(r*2+2, maxFrame)
			copy(f1, p1)
			copy(f2, p2)
			want = append(want, p1...)
			want = append(want, p2...)
			st.pushPooled(f1)
			st.pushPooled(f2)

			if slots, _ := recvPoolCountForClass(idxMax); slots != 0 {
				t.Fatalf("round %d: expected 0 idle pooled maxFrame buffers while 2 are queued, got %d", r, slots)
			}

			callerBuf := make([]byte, 64<<10) // 65536B relay buffer
			n1, err := st.Read(callerBuf)
			if err != nil || n1 != maxFrame {
				t.Fatalf("round %d first Read(65536) = (%d, %v), want (%d, nil)", r, n1, err, maxFrame)
			}
			if !bytes.Equal(callerBuf[:n1], p1) {
				t.Fatalf("round %d first frame payload mismatch", r)
			}

			st.mu.Lock()
			offAfterFirst := st.off
			inBytesAfterFirst := st.inBytes
			queuedFramesAfterFirst := len(st.in) - st.inHead
			headNil := st.in[0] == nil
			st.mu.Unlock()

			if offAfterFirst != 0 {
				t.Fatalf("round %d: second 65535B frame was partially consumed: st.off=%d, want 0", r, offAfterFirst)
			}
			if inBytesAfterFirst != maxFrame || queuedFramesAfterFirst != 1 || !headNil {
				t.Fatalf("round %d: unexpected queue state after first Read: inBytes=%d (want %d), queued=%d (want 1), headNil=%v",
					r, inBytesAfterFirst, maxFrame, queuedFramesAfterFirst, headNil)
			}
			// Frame 0 must already be back in the pool before caller finishes downstream Write / second Read.
			if slots, _ := recvPoolCountForClass(idxMax); slots != 1 {
				t.Fatalf("round %d: first 65535B frame was not returned to pool immediately after first Read: slots=%d, want 1", r, slots)
			}

			n2, err := st.Read(callerBuf)
			if err != nil || n2 != maxFrame {
				t.Fatalf("round %d second Read(65536) = (%d, %v), want (%d, nil)", r, n2, err, maxFrame)
			}
			if !bytes.Equal(callerBuf[:n2], p2) {
				t.Fatalf("round %d second frame payload mismatch", r)
			}

			st.mu.Lock()
			empty := st.inHead == 0 && len(st.in) == 0 && st.off == 0 && st.inBytes == 0
			st.mu.Unlock()
			if !empty {
				t.Fatalf("round %d: stream queue not completely drained after second Read", r)
			}
			if slots, _ := recvPoolCountForClass(idxMax); slots != 2 {
				t.Fatalf("round %d: expected 2 pooled maxFrame buffers after draining both frames (peak 2 buffers reused across rounds), got %d", r, slots)
			}
		}
	})

	// 2. First frame larger than caller buffer p still performs normal short Read,
	// and an already-partial head frame (st.off > 0) remains readable across multiple small/medium Reads.
	t.Run("small_dest_p_and_existing_partial_frame", func(t *testing.T) {
		resetRecvPoolForTest()
		s := &session{
			o:       &Outbound{},
			streams: make(map[uint32]*stream),
			wake:    make(chan struct{}, 1),
			done:    make(chan struct{}),
		}
		st := newStream(s, 2)

		f1 := acquireRecvBuf(8192)
		f2 := acquireRecvBuf(2048)
		p1 := pattern(31, 8192)
		p2 := pattern(32, 2048)
		copy(f1, p1)
		copy(f2, p2)
		st.pushPooled(f1)
		st.pushPooled(f2)

		// First frame (8192B) > len(p) (1000B): must short-read 1000B.
		small := make([]byte, 1000)
		n1, err := st.Read(small)
		if err != nil || n1 != 1000 {
			t.Fatalf("first small Read(1000) = (%d, %v), want (1000, nil)", n1, err)
		}
		if st.off != 1000 || st.inBytes != 8192+2048 {
			t.Fatalf("after first small Read: off=%d inBytes=%d", st.off, st.inBytes)
		}

		// Second small Read(2000) on already-partial head frame (st.off == 1000): must read 2000B.
		med := make([]byte, 2000)
		n2, err := st.Read(med)
		if err != nil || n2 != 2000 {
			t.Fatalf("second partial Read(2000) = (%d, %v), want (2000, nil)", n2, err)
		}
		if st.off != 3000 {
			t.Fatalf("after second partial Read: off=%d, want 3000", st.off)
		}

		// Third Read(6000): finishes remaining 5192B of f1 (releasing f1 to 8KiB pool class),
		// then sees f2 at off==0 with len(f2)==2048 > remaining len(p)==808, so stops at frame boundary!
		bridge := make([]byte, 6000)
		n3, err := st.Read(bridge)
		if err != nil || n3 != 8192-3000 {
			t.Fatalf("third Read(6000) = (%d, %v), want (%d, nil)", n3, err, 8192-3000)
		}
		if slots8k, _ := recvPoolCountForClass(idx8k); slots8k != 1 {
			t.Fatalf("f1 (8KiB) not released after completion: slots8k=%d", slots8k)
		}
		if slots2k, _ := recvPoolCountForClass(idx2k); slots2k != 0 {
			t.Fatalf("f2 (2KiB) released prematurely: slots2k=%d", slots2k)
		}
		if st.off != 0 || st.inBytes != 2048 {
			t.Fatalf("f2 should remain untouched at off=0: off=%d inBytes=%d", st.off, st.inBytes)
		}

		// Fourth Read(2048): reads f2 in full and releases it to the 2KiB pool class.
		tail := make([]byte, 2048)
		n4, err := st.Read(tail)
		if err != nil || n4 != 2048 {
			t.Fatalf("fourth Read(2048) = (%d, %v), want (2048, nil)", n4, err)
		}
		if slots2k, _ := recvPoolCountForClass(idx2k); slots2k != 1 {
			t.Fatalf("f2 (2KiB) not released after completion: slots2k=%d", slots2k)
		}

		var got []byte
		got = append(got, small[:n1]...)
		got = append(got, med[:n2]...)
		got = append(got, bridge[:n3]...)
		got = append(got, tail[:n4]...)
		if !bytes.Equal(got, append(p1, p2...)) {
			t.Fatal("reconstructed byte stream mismatch across small/partial/boundary reads")
		}
	})

	// 3. 4x8KiB ready frames coalesce into a single 32KiB or 64KiB Read without waiting for network,
	// and if a 5th 8KiB frame is queued when caller passes 35KiB, Read coalesces 4x8KiB (32768B) and leaves the 5th intact.
	t.Run("coalesce_4x8k_ready_frames_without_splitting_5th", func(t *testing.T) {
		resetRecvPoolForTest()
		s := &session{
			o:       &Outbound{},
			streams: make(map[uint32]*stream),
			wake:    make(chan struct{}, 1),
			done:    make(chan struct{}),
		}
		st := newStream(s, 3)

		var want4 []byte
		for i := 0; i < 4; i++ {
			f := acquireRecvBuf(8192)
			p := pattern(40+i, 8192)
			copy(f, p)
			want4 = append(want4, p...)
			st.pushPooled(f)
		}
		f5 := acquireRecvBuf(8192)
		p5 := pattern(49, 8192)
		copy(f5, p5)
		st.pushPooled(f5)

		buf35k := make([]byte, 35<<10)
		n, err := st.Read(buf35k)
		if err != nil || n != 32<<10 {
			t.Fatalf("Read(35KiB) over 5x8KiB frames = (%d, %v), want (%d, nil)", n, err, 32<<10)
		}
		if !bytes.Equal(buf35k[:n], want4) {
			t.Fatal("4x8KiB coalesced payload mismatch")
		}
		if st.off != 0 || st.inBytes != 8192 {
			t.Fatalf("5th 8KiB frame was not left intact: off=%d inBytes=%d", st.off, st.inBytes)
		}
		if slots8k, _ := recvPoolCountForClass(idx8k); slots8k != 4 {
			t.Fatalf("expected 4 released 8KiB buffers in pool, got %d", slots8k)
		}

		n5, err := st.Read(buf35k)
		if err != nil || n5 != 8192 || !bytes.Equal(buf35k[:n5], p5) {
			t.Fatalf("Read 5th frame = (%d, %v)", n5, err)
		}
	})

	// 4. Queued data before EOF (remoteClose) or session error (abort) is delivered in full
	// respecting frame boundaries before returning io.EOF or the abort error, and st.in is nilled afterward.
	t.Run("queued_data_before_eof_and_abort_error", func(t *testing.T) {
		resetRecvPoolForTest()
		s := &session{
			o:       &Outbound{},
			streams: make(map[uint32]*stream),
			wake:    make(chan struct{}, 1),
			done:    make(chan struct{}),
		}
		// 4a: EOF after two 65535B frames read with 65536B buffer
		stEOF := newStream(s, 4)
		f1 := acquireRecvBuf(maxFrame)
		f2 := acquireRecvBuf(maxFrame)
		p1 := pattern(51, maxFrame)
		p2 := pattern(52, maxFrame)
		copy(f1, p1)
		copy(f2, p2)
		stEOF.pushPooled(f1)
		stEOF.pushPooled(f2)
		stEOF.remoteClose(io.EOF)

		buf := make([]byte, 64<<10)
		n1, err := stEOF.Read(buf)
		if err != nil || n1 != maxFrame || !bytes.Equal(buf[:n1], p1) {
			t.Fatalf("EOF stream first Read = (%d, %v)", n1, err)
		}
		n2, err := stEOF.Read(buf)
		if err != nil || n2 != maxFrame || !bytes.Equal(buf[:n2], p2) {
			t.Fatalf("EOF stream second Read = (%d, %v)", n2, err)
		}
		if stEOF.in != nil {
			t.Fatal("expected stEOF.in == nil after draining final frame post-EOF")
		}
		n3, err := stEOF.Read(buf)
		if n3 != 0 || err != io.EOF {
			t.Fatalf("EOF stream third Read = (%d, %v), want (0, io.EOF)", n3, err)
		}

		// 4b: Abort error after queued frames
		stErr := newStream(s, 5)
		fe1 := acquireRecvBuf(4096)
		fe2 := acquireRecvBuf(4096)
		pe1 := pattern(61, 4096)
		pe2 := pattern(62, 4096)
		copy(fe1, pe1)
		copy(fe2, pe2)
		stErr.pushPooled(fe1)
		stErr.pushPooled(fe2)
		boom := errors.New("simulated session failure")
		stErr.abort(boom)

		smallBuf := make([]byte, 6000)
		ne1, err := stErr.Read(smallBuf)
		if err != nil || ne1 != 4096 || !bytes.Equal(smallBuf[:ne1], pe1) {
			t.Fatalf("abort stream first Read(6000) = (%d, %v), want (4096, nil)", ne1, err)
		}
		ne2, err := stErr.Read(smallBuf)
		if err != nil || ne2 != 4096 || !bytes.Equal(smallBuf[:ne2], pe2) {
			t.Fatalf("abort stream second Read(6000) = (%d, %v), want (4096, nil)", ne2, err)
		}
		if stErr.in != nil {
			t.Fatal("expected stErr.in == nil after draining final frame post-abort")
		}
		ne3, err := stErr.Read(smallBuf)
		if ne3 != 0 || !errors.Is(err, boom) {
			t.Fatalf("abort stream third Read = (%d, %v), want (0, %v)", ne3, err, boom)
		}
	})

	// 5. Backpressure wakeup: when enqueueIn blocks because st.inBytes + len(b) > maxStreamBuffer,
	// a boundary-stopped Read(65536) that drains the first 65535B frame decrements st.inBytes
	// and signals st.space so the blocked producer wakes up and enqueues the waiting frame.
	t.Run("backpressure_space_wakeup_on_boundary_read", func(t *testing.T) {
		resetRecvPoolForTest()
		s := &session{
			o:       &Outbound{},
			streams: make(map[uint32]*stream),
			wake:    make(chan struct{}, 1),
			done:    make(chan struct{}),
		}
		st := newStream(s, 6)

		// maxStreamBuffer is 1048576 (16 * 65536). 16 * 65535 = 1048560 <= maxStreamBuffer.
		// The 17th 65535B frame will block in enqueueIn until at least one frame is drained.
		for i := 0; i < 16; i++ {
			f := acquireRecvBuf(maxFrame)
			copy(f, pattern(70+i, maxFrame))
			st.pushPooled(f)
		}
		pushed17 := make(chan struct{})
		go func() {
			f17 := acquireRecvBuf(maxFrame)
			copy(f17, pattern(99, maxFrame))
			st.pushPooled(f17)
			close(pushed17)
		}()

		select {
		case <-pushed17:
			t.Fatal("17th maxFrame push should block on maxStreamBuffer backpressure")
		case <-time.After(20 * time.Millisecond):
		}

		// A single Read(65536) drains frame 0 (65535B), stops at frame 1 boundary, and signals st.space.
		callerBuf := make([]byte, 64<<10)
		n, err := st.Read(callerBuf)
		if err != nil || n != maxFrame {
			t.Fatalf("Read(65536) under backpressure = (%d, %v), want (%d, nil)", n, err, maxFrame)
		}

		select {
		case <-pushed17:
		case <-time.After(time.Second):
			t.Fatal("blocked pushPooled was not woken after boundary Read drained first frame")
		}
		_ = st.Close()
	})

	// 6. Close, deadline, and single pool release: a pooled buffer is returned to the pool
	// at most once even if Close() runs after boundary Read or while unread frames remain,
	// and SetReadDeadline works cleanly after draining boundary-aligned frames.
	t.Run("close_deadline_and_single_pool_release", func(t *testing.T) {
		resetRecvPoolForTest()
		s := &session{
			o:       &Outbound{},
			streams: make(map[uint32]*stream),
			wake:    make(chan struct{}, 1),
			done:    make(chan struct{}),
		}
		st := newStream(s, 7)

		f1 := acquireRecvBuf(maxFrame)
		f2 := acquireRecvBuf(maxFrame)
		st.pushPooled(f1)
		st.pushPooled(f2)

		callerBuf := make([]byte, 64<<10)
		n, err := st.Read(callerBuf)
		if err != nil || n != maxFrame {
			t.Fatalf("Read(65536) = (%d, %v), want (%d, nil)", n, err, maxFrame)
		}
		if slots, _ := recvPoolCountForClass(idxMax); slots != 1 {
			t.Fatalf("after first Read: slots=%d, want 1", slots)
		}

		// Drain f2 so queue is empty, then verify read deadline expiry on empty queue.
		n2, err := st.Read(callerBuf)
		if err != nil || n2 != maxFrame {
			t.Fatalf("second Read(65536) = (%d, %v), want (%d, nil)", n2, err, maxFrame)
		}
		if slots, _ := recvPoolCountForClass(idxMax); slots != 2 {
			t.Fatalf("after second Read: slots=%d, want 2", slots)
		}
		_ = st.SetReadDeadline(time.Now().Add(-time.Millisecond))
		if _, derr := st.Read(callerBuf); !errors.Is(derr, os.ErrDeadlineExceeded) {
			t.Fatalf("expired deadline Read = %v, want os.ErrDeadlineExceeded", derr)
		}
		_ = st.SetReadDeadline(time.Time{})

		// Enqueue one more frame and Close() immediately: f1 & f2 were already released once (2 in pool);
		// f3 (acquired from those 2) must be released once on Close(), bringing pool back to 2 (never 3).
		f3 := acquireRecvBuf(maxFrame)
		st.pushPooled(f3)
		if slots, _ := recvPoolCountForClass(idxMax); slots != 1 {
			t.Fatalf("after acquiring f3: slots=%d, want 1", slots)
		}
		_ = st.Close()
		if slots, _ := recvPoolCountForClass(idxMax); slots != 2 {
			t.Fatalf("after Close(): slots=%d, want 2 (each buffer released exactly once)", slots)
		}
		if _, cerr := st.Read(callerBuf); !errors.Is(cerr, net.ErrClosed) {
			t.Fatalf("Read after Close() = %v, want net.ErrClosed", cerr)
		}
	})
}

func BenchmarkStreamReadCoalesce4x8K(b *testing.B) {
	resetRecvPoolForTest()
	s := &session{done: make(chan struct{})}
	st := newStream(s, 1)
	buf := make([]byte, 32<<10)
	b.ReportAllocs()
	b.SetBytes(32 << 10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 4; j++ {
			f := acquireRecvBuf(8 << 10)
			st.pushPooled(f)
		}
		n, err := st.Read(buf)
		if err != nil || n != 32<<10 {
			b.Fatalf("Read = (%d, %v)", n, err)
		}
	}
}

func BenchmarkSessionRecv32KFrame(b *testing.B) {
	resetRecvPoolForTest()
	const frameSize = 32 << 10
	s := &session{done: make(chan struct{})}
	st := newStream(s, 1)
	src := bytes.NewReader(make([]byte, frameSize))
	readBuf := make([]byte, frameSize)
	b.ReportAllocs()
	b.SetBytes(frameSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src.Reset(readBuf)
		data := acquireRecvBuf(frameSize)
		if _, err := io.ReadFull(src, data); err != nil {
			b.Fatal(err)
		}
		st.pushPooled(data)
		n, err := st.Read(readBuf)
		if err != nil || n != frameSize {
			b.Fatalf("Read = (%d, %v)", n, err)
		}
	}
}

func BenchmarkSessionRecvMaxFrame(b *testing.B) {
	resetRecvPoolForTest()
	const frameSize = maxFrame
	s := &session{done: make(chan struct{})}
	st := newStream(s, 1)
	src := bytes.NewReader(make([]byte, frameSize))
	readBuf := make([]byte, 64<<10)
	b.ReportAllocs()
	b.SetBytes(frameSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src.Reset(readBuf[:frameSize])
		data := acquireRecvBuf(frameSize)
		if _, err := io.ReadFull(src, data); err != nil {
			b.Fatal(err)
		}
		st.pushPooled(data)
		n, err := st.Read(readBuf)
		if err != nil || n != frameSize {
			b.Fatalf("Read = (%d, %v)", n, err)
		}
	}
}

func TestSessionReadFramesPooledSteadyState(t *testing.T) {
	resetRecvPoolForTest()
	t.Cleanup(resetRecvPoolForTest)

	// Verify 0 steady-state heap allocations per frame across 32KiB and maxFrame (65535B).
	for _, frameSize := range []int{32 << 10, maxFrame} {
		s := &session{done: make(chan struct{})}
		st := newStream(s, 1)
		src := bytes.NewReader(make([]byte, frameSize))
		readBuf := make([]byte, 64<<10)
		allocs := testing.AllocsPerRun(100, func() {
			src.Reset(readBuf[:frameSize])
			data := acquireRecvBuf(frameSize)
			if _, err := io.ReadFull(src, data); err != nil {
				t.Fatal(err)
			}
			st.pushPooled(data)
			n, err := st.Read(readBuf)
			if err != nil || n != frameSize {
				t.Fatalf("Read(%d) = (%d, %v)", frameSize, n, err)
			}
		})
		if allocs != 0 {
			t.Fatalf("frameSize=%d: steady-state allocs=%v, want 0", frameSize, allocs)
		}
	}

	// Verify end-to-end session.readFrames() + stream.Read() over net.Pipe with mixed frame sizes.
	c1, c2 := net.Pipe()
	s := &session{
		o:       &Outbound{},
		conn:    c1,
		streams: make(map[uint32]*stream),
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	st := newStream(s, 7)
	s.streams[7] = st

	sizes := []int{64, 512, 1500, 8192, 16384, 32768, maxFrame, 4096, 2048}
	var want []byte
	writerDone := make(chan error, 1)
	go func() {
		defer c2.Close()
		for i, sz := range sizes {
			p := pattern(i+1, sz)
			want = append(want, p...)
			wire := appendFrame(nil, cmdPSH, 7, p)
			if err := writeAll(c2, wire); err != nil {
				writerDone <- err
				return
			}
		}
		if err := writeAll(c2, appendFrame(nil, cmdFIN, 7, nil)); err != nil {
			writerDone <- err
			return
		}
		writerDone <- nil
	}()
	recvDone := make(chan error, 1)
	go func() {
		recvDone <- s.readFrames()
	}()

	got, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if werr := <-writerDone; werr != nil {
		t.Fatalf("writer: %v", werr)
	}
	_ = c1.Close()
	<-recvDone
	if !bytes.Equal(got, want) {
		t.Fatalf("ReadAll len=%d want=%d mismatch", len(got), len(want))
	}
	_ = st.Close()
	recvPool.mu.Lock()
	poolBytes := recvPool.bytes
	recvPool.mu.Unlock()
	if poolBytes > maxRecvPoolBytes {
		t.Fatalf("poolBytes=%d exceeds maxRecvPoolBytes=%d", poolBytes, maxRecvPoolBytes)
	}
}

type sendWriteRecordConn struct {
	net.Conn
	mu          sync.Mutex
	writes      int
	sizes       []int
	shortLimit  int
	failAfter   int
	wroteBytes  int
	closeWrites atomic.Int32
}

func (c *sendWriteRecordConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.failAfter > 0 && c.wroteBytes >= c.failAfter {
		c.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	limit := len(p)
	if c.shortLimit > 0 && limit > c.shortLimit {
		limit = c.shortLimit
	}
	if c.failAfter > 0 && c.wroteBytes+limit > c.failAfter {
		limit = c.failAfter - c.wroteBytes
	}
	c.writes++
	c.sizes = append(c.sizes, limit)
	c.wroteBytes += limit
	c.mu.Unlock()
	n, err := c.Conn.Write(p[:limit])
	if err != nil {
		return n, err
	}
	if c.failAfter > 0 && c.wroteBytes >= c.failAfter && limit < len(p) {
		return n, io.ErrClosedPipe
	}
	return n, nil
}

func (c *sendWriteRecordConn) CloseWrite() error {
	c.closeWrites.Add(1)
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *sendWriteRecordConn) resetCounts() {
	c.mu.Lock()
	c.writes = 0
	c.sizes = c.sizes[:0]
	c.wroteBytes = 0
	c.mu.Unlock()
}

func (c *sendWriteRecordConn) snapshot() (writes int, sizes []int, total int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes, append([]int(nil), c.sizes...), c.wroteBytes
}

// countTLSRecords parses raw TLS 1.2/1.3 record headers (5 bytes: typ(1) | ver(2) | len(2))
// from a captured ciphertext byte stream and returns each record total wire size (5 + length).
func countTLSRecords(t testing.TB, raw []byte) []int {
	t.Helper()
	var records []int
	for len(raw) > 0 {
		if len(raw) < 5 {
			t.Fatalf("truncated TLS record header: remaining=%d", len(raw))
		}
		typ := raw[0]
		if typ < 20 || typ > 24 {
			t.Fatalf("unexpected TLS content type %d", typ)
		}
		n := int(binary.BigEndian.Uint16(raw[3:5]))
		if len(raw) < 5+n {
			t.Fatalf("truncated TLS record body: need %d, have %d", 5+n, len(raw))
		}
		records = append(records, 5+n)
		raw = raw[5+n:]
	}
	return records
}

type tapConn struct {
	net.Conn
	mu      sync.Mutex
	written bytes.Buffer
}

func (c *tapConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.mu.Lock()
		_, _ = c.written.Write(p[:n])
		c.mu.Unlock()
	}
	return n, err
}

func (c *tapConn) takeWritten() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := append([]byte(nil), c.written.Bytes()...)
	c.written.Reset()
	return b
}

// TestSendPathIdealConnWriteAndTLSRecordCounts verifies on an ideal in-memory
// connection (not claimed as Windows WSASend) how many TLS records and underlying
// raw conn.Write calls occur for 1B, 32KiB (cold-start dynamic sizing vs steady-state
// 16KiB maxPlaintext), 64KiB, and 256KiB stream writes before vs after the
// send-path optimization.
func TestSendPathIdealConnWriteAndTLSRecordCounts(t *testing.T) {
	cert := newTestCert(t)
	stop1, err := parsePaddingScheme("stop=1\n0=30-30")
	if err != nil {
		t.Fatal(err)
	}

	runCase := func(buffered, warmTLS bool, writeSize int) (rawWrites int, rawSizes []int, tlsRecordSizes []int) {
		cClient, cServer := net.Pipe()
		defer cClient.Close()
		defer cServer.Close()

		// Drain server pipe asynchronously so large buffered writes (>64KiB) never
		// deadlock on synchronous net.Pipe while TLS handshake / application data flows.
		srvIn, srvOut := io.Pipe()
		defer srvIn.Close()
		defer srvOut.Close()
		go func() {
			_, _ = io.Copy(srvOut, cServer)
		}()

		tap := &tapConn{Conn: cClient}
		rec := &sendWriteRecordConn{Conn: tap}

		warmBytes := 0
		if warmTLS {
			warmBytes = 128 << 10 // exceed crypto/tls maxDynamicSizingThreshold (128KiB)
		}
		totalExpected := warmBytes + writeSize

		srvDone := make(chan error, 1)
		var srvGot []byte
		go func() {
			// Server reads from srvIn and writes handshake replies to cServer.
			srvConn := &duplexRWConn{Conn: cServer, r: srvIn, w: cServer}
			srvTLS := tls.Server(srvConn, &tls.Config{Certificates: []tls.Certificate{cert.pair}, MinVersion: tls.VersionTLS13})
			if err := srvTLS.Handshake(); err != nil {
				srvDone <- err
				return
			}
			var hdr [headerSize]byte
			readTotal := 0
			for readTotal < totalExpected {
				if _, err := io.ReadFull(srvTLS, hdr[:]); err != nil {
					srvDone <- err
					return
				}
				if hdr[0] != cmdPSH {
					srvDone <- fmt.Errorf("unexpected cmd %d", hdr[0])
					return
				}
				n := int(binary.BigEndian.Uint16(hdr[5:7]))
				body := make([]byte, n)
				if _, err := io.ReadFull(srvTLS, body); err != nil {
					srvDone <- err
					return
				}
				readTotal += n
				if readTotal > warmBytes {
					keep := body
					if readTotal-n < warmBytes {
						keep = body[warmBytes-(readTotal-n):]
					}
					srvGot = append(srvGot, keep...)
				}
			}
			srvDone <- nil
		}()

		var under net.Conn = rec
		var bw *bufferedWriteConn
		if buffered {
			bw = wrapBufferedWriteConn(rec)
			under = bw.asNetConn()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		tlsCfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}
		tc, err := tlsclient.Handshake(ctx, under, tlsCfg, "")
		if err != nil {
			t.Fatal(err)
		}
		defer tc.Close()

		s := &session{
			o:        &Outbound{},
			conn:     tc,
			rawWrite: bw,
			scheme:   stop1,
			packet:   8, // past padding stop
			streams:  make(map[uint32]*stream),
			wake:     make(chan struct{}, 1),
			done:     make(chan struct{}),
			ver:      make(chan struct{}),
		}
		s.wg.Add(1)
		go s.writeLoop()
		defer func() {
			s.fail(net.ErrClosed)
			s.wg.Wait()
		}()

		st := newStream(s, 1)
		s.streams[1] = st

		if warmBytes > 0 {
			if _, err := st.Write(make([]byte, warmBytes)); err != nil {
				t.Fatal(err)
			}
		}

		// Reset counters after handshake (and optional TLS record-size warm-up)
		// so only the target write is measured.
		rec.resetCounts()
		_ = tap.takeWritten()

		payload := pattern(17, writeSize)

		if !buffered {
			// Simulate legacy pre-optimization behavior: writeChunk=65535 (maxFrame)
			// and every request goes through s.enqueue without inline token or rawWrite batching.
			rem := payload
			for len(rem) > 0 {
				n := min(len(rem), maxFrame)
				wire := appendFrame(nil, cmdPSH, st.id, rem[:n])
				req := &writeReq{wire: wire, done: make(chan error, 1)}
				if err := s.enqueue(req); err != nil {
					t.Fatal(err)
				}
				if err := <-req.done; err != nil {
					t.Fatal(err)
				}
				rem = rem[n:]
			}
		} else {
			n, err := st.Write(payload)
			if err != nil || n != len(payload) {
				t.Fatalf("st.Write(%d) = (%d, %v)", len(payload), n, err)
			}
		}

		if err := <-srvDone; err != nil {
			t.Fatalf("server error: %v", err)
		}
		if !bytes.Equal(srvGot, payload) {
			t.Fatalf("payload mismatch for size=%d", writeSize)
		}
		rawWrites, rawSizes, _ = rec.snapshot()
		tlsRecordSizes = countTLSRecords(t, tap.takeWritten())
		return
	}

	// 1. Cold-start 32KiB write (crypto/tls dynamic record sizing produces 7 TLS records on first write):
	coldLegW, coldLegSz, coldLegRecs := runCase(false, false, 32<<10)
	coldOptW, coldOptSz, coldOptRecs := runCase(true, false, 32<<10)
	t.Logf("cold-start 32768B: legacy idealConn.Write=%d (sizes=%v, TLSrecords=%d) -> optimized idealConn.Write=%d (sizes=%v, TLSrecords=%d)",
		coldLegW, coldLegSz, len(coldLegRecs), coldOptW, coldOptSz, len(coldOptRecs))
	if coldLegW != 7 || coldOptW != 1 {
		t.Fatalf("cold-start 32KiB write: legacy=%d (want 7) opt=%d (want 1)", coldLegW, coldOptW)
	}

	// 2. Steady-state (warm TLS after 128KiB) across 1B, 32KiB, 64KiB, and 256KiB:
	for _, sz := range []int{1, 32 << 10, 64 << 10, 256 << 10} {
		legWrites, legSizes, legRecs := runCase(false, true, sz)
		optWrites, optSizes, optRecs := runCase(true, true, sz)
		t.Logf("steady-state size=%dB: legacy idealConn.Write=%d (sizes=%v, TLSrecords=%d %v) -> optimized idealConn.Write=%d (sizes=%v, TLSrecords=%d %v)",
			sz, legWrites, legSizes, len(legRecs), legRecs, optWrites, optSizes, len(optRecs), optRecs)

		switch sz {
		case 1:
			if legWrites != 1 || optWrites != 1 || len(legRecs) != 1 || len(optRecs) != 1 {
				t.Fatalf("1B write: legacy=%d/%d opt=%d/%d, want 1", legWrites, len(legRecs), optWrites, len(optRecs))
			}
		case 32 << 10:
			// Steady-state 32KiB + 7B header = 32775B plaintext -> 3 TLS records (16384 + 16384 + 7B).
			// Legacy issues 3 underlying conn.Write calls; optimized coalesces into 1 conn.Write.
			if legWrites != 3 || len(legRecs) != 3 || optWrites != 1 || len(optRecs) != 3 {
				t.Fatalf("steady 32KiB write: legacy=%d (recs=%d) opt=%d (recs=%d), want 3->1 writes and 3 TLS records",
					legWrites, len(legRecs), optWrites, len(optRecs))
			}
		case 64 << 10:
			// Legacy splits 65536B into 65535B (5 TLS records) + 1B (1 TLS record) = 6 conn.Write calls across 2 writeData requests.
			// Optimized frames 2x32KiB (65550B wire = 5 TLS records) in 1 writeData request and flushes in 1 conn.Write call.
			if legWrites != 6 || len(legRecs) != 6 || optWrites != 1 || len(optRecs) != 5 {
				t.Fatalf("steady 64KiB write: legacy=%d (recs=%d, want 6/6) opt=%d (recs=%d, want 1/5)",
					legWrites, len(legRecs), optWrites, len(optRecs))
			}
		case 256 << 10:
			// 256KiB = 4 * 64KiB chunks: optimized performs 4 underlying conn.Write calls vs legacy 21.
			if optWrites != 4 || legWrites != 21 {
				t.Fatalf("steady 256KiB write: legacy=%d (want 21) opt=%d (want 4)", legWrites, optWrites)
			}
		}
	}
}

type duplexRWConn struct {
	net.Conn
	r io.Reader
	w io.Writer
}

func (c *duplexRWConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *duplexRWConn) Write(p []byte) (int, error) { return c.w.Write(p) }

// TestSendPathMatrixAndSafetyBoundaries verifies 1B, short streams, 64KiB exact
// framing (no 65535+1 micro-tail), large multi-chunk writes, concurrent streams +
// control frames (heartbeat/settings), FIN/Close ordering, stream-scoped deadlines,
// partial write / mid-write failure reporting, queue cancel without early wbuf reuse,
// CloseWrite preservation, and 0-RTT / padding scheme invariants.
func TestSendPathMatrixAndSafetyBoundaries(t *testing.T) {
	// 1. Exact 64KiB framing: verify 65536B emits two 32768B PSH frames in one request (never 65535 + 1),
	// and maxFrame (65535B) limit is never exceeded for any input size.
	t.Run("framing_64k_and_maxframe_invariants", func(t *testing.T) {
		for _, sz := range []int{1, 7, 512, 16384, 32768, 65535, 65536, 65537, 100000, 256 << 10} {
			c1, c2 := net.Pipe()
			stop1, _ := parsePaddingScheme("stop=1\n0=30-30")
			s := &session{
				o:       &Outbound{},
				conn:    c1,
				scheme:  stop1,
				packet:  8,
				streams: make(map[uint32]*stream),
				wake:    make(chan struct{}, 1),
				done:    make(chan struct{}),
			}
			s.wg.Add(1)
			go s.writeLoop()
			st := newStream(s, 9)
			s.streams[9] = st

			src := pattern(sz, sz)
			var frameLengths []int
			var got []byte
			readDone := make(chan error, 1)
			go func() {
				var hdr [headerSize]byte
				for len(got) < sz {
					if _, err := io.ReadFull(c2, hdr[:]); err != nil {
						readDone <- err
						return
					}
					if hdr[0] != cmdPSH {
						readDone <- fmt.Errorf("unexpected cmd %d", hdr[0])
						return
					}
					if id := binary.BigEndian.Uint32(hdr[1:5]); id != 9 {
						readDone <- fmt.Errorf("unexpected stream id %d", id)
						return
					}
					n := int(binary.BigEndian.Uint16(hdr[5:7]))
					if n == 0 || n > maxFrame {
						readDone <- fmt.Errorf("invalid frame length %d", n)
						return
					}
					frameLengths = append(frameLengths, n)
					body := make([]byte, n)
					if _, err := io.ReadFull(c2, body); err != nil {
						readDone <- err
						return
					}
					got = append(got, body...)
				}
				readDone <- nil
			}()

			n, err := st.Write(src)
			if err != nil || n != sz {
				t.Fatalf("size=%d: Write=(%d, %v)", sz, n, err)
			}
			if err := <-readDone; err != nil {
				t.Fatalf("size=%d: reader err=%v", sz, err)
			}
			if !bytes.Equal(got, src) {
				t.Fatalf("size=%d: payload mismatch", sz)
			}
			if sz == 65536 {
				if len(frameLengths) != 2 || frameLengths[0] != 32768 || frameLengths[1] != 32768 {
					t.Fatalf("64KiB frame lengths = %v, want [32768 32768]", frameLengths)
				}
			}
			s.fail(net.ErrClosed)
			s.wg.Wait()
			_ = c1.Close()
			_ = c2.Close()
		}
	})

	// 2. Concurrent multi-stream + control frames (heartbeat response) + FIN ordering:
	// verifies inline token and writeLoop strictly serialize writes, never starve
	// queued requests or heartbeats, and never allow data to cross after Close/FIN.
	t.Run("concurrent_multistream_control_and_fin_ordering", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		stop1, _ := parsePaddingScheme("stop=1\n0=30-30")
		bw := wrapBufferedWriteConn(c1)
		s := &session{
			o:        &Outbound{},
			conn:     bw.asNetConn(),
			rawWrite: bw,
			scheme:   stop1,
			packet:   8,
			streams:  make(map[uint32]*stream),
			wake:     make(chan struct{}, 1),
			done:     make(chan struct{}),
		}
		s.wg.Add(1)
		go s.writeLoop()
		defer func() {
			s.fail(net.ErrClosed)
			s.wg.Wait()
		}()

		const numStreams = 6
		const writesPerStream = 20
		streams := make([]*stream, numStreams)
		for i := 0; i < numStreams; i++ {
			id := uint32(i + 1)
			streams[i] = newStream(s, id)
			s.streams[id] = streams[i]
		}

		var (
			recvMu     sync.Mutex
			perStream  = make(map[uint32][]byte)
			finSeen    = make(map[uint32]bool)
			heartbeats int
			orderErr   error
		)
		readerDone := make(chan struct{})
		go func() {
			defer close(readerDone)
			var hdr [headerSize]byte
			for {
				if _, err := io.ReadFull(c2, hdr[:]); err != nil {
					return
				}
				cmd := hdr[0]
				id := binary.BigEndian.Uint32(hdr[1:5])
				n := int(binary.BigEndian.Uint16(hdr[5:7]))
				body := make([]byte, n)
				if _, err := io.ReadFull(c2, body); err != nil {
					return
				}
				recvMu.Lock()
				switch cmd {
				case cmdPSH:
					if finSeen[id] && orderErr == nil {
						orderErr = fmt.Errorf("stream %d emitted PSH after FIN", id)
					}
					perStream[id] = append(perStream[id], body...)
				case cmdFIN:
					finSeen[id] = true
				case cmdHeartResponse:
					heartbeats++
				}
				recvMu.Unlock()
			}
		}()

		var wg sync.WaitGroup
		for i, st := range streams {
			wg.Add(1)
			go func(idx int, st *stream) {
				defer wg.Done()
				for j := 0; j < writesPerStream; j++ {
					chunk := pattern(idx*100+j, 1024+j*17)
					if _, err := st.Write(chunk); err != nil {
						t.Errorf("stream %d write %d: %v", st.id, j, err)
						return
					}
					if j%5 == 0 {
						_ = s.enqueue(&writeReq{wire: appendFrame(nil, cmdHeartResponse, st.id, nil), done: make(chan error, 1)})
					}
				}
				_ = st.Close()
				if _, err := st.Write([]byte("after-close")); !errors.Is(err, net.ErrClosed) {
					t.Errorf("stream %d Write after Close = %v, want net.ErrClosed", st.id, err)
				}
			}(i, st)
		}
		wg.Wait()

		// Wait until all FIN frames and heartbeats are drained by writeLoop.
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			recvMu.Lock()
			doneFINs := len(finSeen)
			hb := heartbeats
			recvMu.Unlock()
			if doneFINs == numStreams && hb == numStreams*(writesPerStream/5) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		_ = c1.Close()
		<-readerDone

		recvMu.Lock()
		defer recvMu.Unlock()
		if orderErr != nil {
			t.Fatal(orderErr)
		}
		if len(finSeen) != numStreams {
			t.Fatalf("FINs seen = %d, want %d", len(finSeen), numStreams)
		}
		if heartbeats != numStreams*(writesPerStream/5) {
			t.Fatalf("heartbeats = %d, want %d", heartbeats, numStreams*(writesPerStream/5))
		}
		for i := 0; i < numStreams; i++ {
			id := uint32(i + 1)
			var want []byte
			for j := 0; j < writesPerStream; j++ {
				want = append(want, pattern(i*100+j, 1024+j*17)...)
			}
			if !bytes.Equal(perStream[id], want) {
				t.Fatalf("stream %d data mismatch: got %dB, want %dB", id, len(perStream[id]), len(want))
			}
		}
	})

	// 3. Queue cancel & wbuf ownership safety: when a stream write is queued behind
	// an active writer and times out (or closes), if it was not taken it is cleanly
	// withdrawn and never reaches the wire; if it WAS already taken, writeData waits
	// for the real wire outcome before returning so a subsequent Write can never
	// overwrite st.wbuf while writeLoop is still reading it.
	t.Run("queue_cancel_and_no_premature_wbuf_reuse", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		stop1, _ := parsePaddingScheme("stop=1\n0=30-30")
		s := &session{
			o:       &Outbound{},
			conn:    c1,
			scheme:  stop1,
			packet:  8,
			streams: make(map[uint32]*stream),
			wake:    make(chan struct{}, 1),
			done:    make(chan struct{}),
		}
		s.wg.Add(1)
		go s.writeLoop()
		defer func() {
			s.fail(net.ErrClosed)
			s.wg.Wait()
		}()

		st1 := newStream(s, 1)
		st2 := newStream(s, 2)
		s.streams[1] = st1
		s.streams[2] = st2

		// st1 starts an inline write that blocks because c2 is not reading yet.
		st1Done := make(chan error, 1)
		go func() {
			_, err := st1.Write(bytes.Repeat([]byte{'A'}, 1024))
			st1Done <- err
		}()
		// Wait until st1 holds s.writing.
		for {
			s.mu.Lock()
			w := s.writing
			s.mu.Unlock()
			if w {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}

		// st2 queues a write with a short write deadline while st1 is blocking the transport.
		// Because st1 holds s.writing, st2's request stays untaken in s.queue and must be
		// withdrawn on deadline expiry without ever reaching the wire.
		_ = st2.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
		n, err := st2.Write(bytes.Repeat([]byte{'B'}, 512))
		if !errors.Is(err, os.ErrDeadlineExceeded) || n != 0 {
			t.Fatalf("st2 timed out queued write = (%d, %v), want (0, ErrDeadlineExceeded)", n, err)
		}
		_ = st2.SetWriteDeadline(time.Time{})

		// Now drain st1 from c2 and then write 'C' on st2; 'B' must never appear on c2.
		var gotStream2 []byte
		readDone := make(chan error, 1)
		go func() {
			var hdr [headerSize]byte
			for i := 0; i < 2; i++ {
				if _, err := io.ReadFull(c2, hdr[:]); err != nil {
					readDone <- err
					return
				}
				id := binary.BigEndian.Uint32(hdr[1:5])
				n := int(binary.BigEndian.Uint16(hdr[5:7]))
				body := make([]byte, n)
				if _, err := io.ReadFull(c2, body); err != nil {
					readDone <- err
					return
				}
				if id == 2 {
					gotStream2 = append(gotStream2, body...)
				}
			}
			readDone <- nil
		}()

		if err := <-st1Done; err != nil {
			t.Fatalf("st1 write failed: %v", err)
		}
		if _, err := st2.Write(bytes.Repeat([]byte{'C'}, 512)); err != nil {
			t.Fatalf("st2 follow-up write failed: %v", err)
		}
		if err := <-readDone; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(gotStream2, bytes.Repeat([]byte{'C'}, 512)) {
			t.Fatalf("cancelled st2 payload leaked onto wire or corrupted by wbuf reuse")
		}
	})

	// 4. Partial multi-chunk Write failure & short underlying writes:
	// Verify that if a multi-chunk Write(128KiB) fails on the second 64KiB chunk,
	// only the first 65536 bytes are reported written, and uncommitted bytes are
	// never reported as succeeded. Also verify short underlying writes are handled.
	t.Run("partial_write_failure_and_short_under_writes", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		go func() {
			_, _ = io.Copy(io.Discard, c2)
		}()

		// Allow exactly the first 64KiB write (2 * (32768 + 7) = 65550 wire bytes) to succeed,
		// then fail partway through the second 64KiB write.
		const firstChunkWire = (64 << 10) + 2*headerSize
		rec := &sendWriteRecordConn{
			Conn:       c1,
			shortLimit: 4096,
			failAfter:  firstChunkWire + 1000,
		}
		bw := wrapBufferedWriteConn(rec)
		stop1, _ := parsePaddingScheme("stop=1\n0=30-30")
		s := &session{
			o:        &Outbound{},
			conn:     bw.asNetConn(),
			rawWrite: bw,
			scheme:   stop1,
			packet:   8,
			streams:  make(map[uint32]*stream),
			wake:     make(chan struct{}, 1),
			done:     make(chan struct{}),
		}
		s.wg.Add(1)
		go s.writeLoop()
		defer s.wg.Wait()

		st := newStream(s, 1)
		s.streams[1] = st
		n, err := st.Write(make([]byte, 128<<10))
		if err == nil {
			t.Fatal("expected error on second chunk failure, got nil")
		}
		if n != 64<<10 {
			t.Fatalf("partial Write returned n=%d, want %d (exact first committed chunk)", n, 64<<10)
		}
	})

	// 5. CloseWrite capability preservation on bufferedWriteConn.
	t.Run("closewrite_capability_preserved", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		go func() { _, _ = io.Copy(io.Discard, c2) }()

		recCW := &sendWriteRecordConn{Conn: c1}
		bwCW := wrapBufferedWriteConn(recCW)
		connCW := bwCW.asNetConn()
		cw, ok := connCW.(interface{ CloseWrite() error })
		if !ok {
			t.Fatal("bufferedWriteConn.asNetConn lost CloseWrite capability")
		}
		bwCW.beginBatchWrite()
		_, _ = connCW.Write([]byte("pending-before-closewrite"))
		if err := cw.CloseWrite(); err != nil {
			t.Fatalf("CloseWrite err: %v", err)
		}
		if recCW.closeWrites.Load() != 1 {
			t.Fatalf("underlying CloseWrite count = %d, want 1", recCW.closeWrites.Load())
		}
		if writes, _, total := recCW.snapshot(); writes != 1 || total != len("pending-before-closewrite") {
			t.Fatalf("CloseWrite did not flush pending batch: writes=%d total=%d", writes, total)
		}

		// A plain net.Conn without CloseWrite must not grow CloseWrite.
		bwPlain := wrapBufferedWriteConn(c1)
		if _, ok := bwPlain.asNetConn().(interface{ CloseWrite() error }); ok {
			t.Fatal("asNetConn invented CloseWrite for plain net.Conn")
		}
	})

	// 6. Small stream immediacy (1B & short writes over real AnyTLS server):
	// Verify no cross-call timer buffering delays 1B writes.
	t.Run("small_stream_immediacy_and_0rtt", func(t *testing.T) {
		cert, ks := katFixture(t, A.Config{})
		echo := tcpEchoServer(t)
		o := newTestOutbound(t, baseOptions(ks.addr, testPassword, &outbound.TLSOptions{PinSHA256: cert.pin}), &countingDialer{})
		c, e := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()

		for _, sz := range []int{1, 13, 512, 32 << 10, 64 << 10, 200 << 10} {
			start := time.Now()
			if err := echoRoundTrip(c, pattern(sz, sz)); err != nil {
				t.Fatalf("echo size=%d: %v", sz, err)
			}
			if sz <= 512 && time.Since(start) > 250*time.Millisecond {
				t.Fatalf("small write size=%d delayed: %v", sz, time.Since(start))
			}
		}
	})
}

func TestSessionWriteSteadyStateZeroAlloc(t *testing.T) {
	stop1, err := parsePaddingScheme("stop=1\n0=30-30")
	if err != nil {
		t.Fatal(err)
	}
	bw := wrapBufferedWriteConn(discardConn{})
	s := &session{
		o:        &Outbound{},
		conn:     bw.asNetConn(),
		rawWrite: bw,
		scheme:   stop1,
		packet:   8,
		streams:  make(map[uint32]*stream),
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	s.wg.Add(1)
	go s.writeLoop()
	defer func() {
		s.fail(net.ErrClosed)
		s.wg.Wait()
	}()

	st := newStream(s, 1)
	s.streams[1] = st

	for _, sz := range []int{32 << 10, 64 << 10} {
		payload := make([]byte, sz)
		// Warm up st.wbuf and bw.buf capacities once.
		if _, err := st.Write(payload); err != nil {
			t.Fatal(err)
		}
		allocs := testing.AllocsPerRun(100, func() {
			n, err := st.Write(payload)
			if err != nil || n != sz {
				t.Fatalf("Write(%d) = (%d, %v)", sz, n, err)
			}
		})
		if allocs != 0 {
			t.Fatalf("steady-state stream.Write(%d) allocs = %v, want 0", sz, allocs)
		}
	}
}

type discardConn struct{ net.Conn }

func (discardConn) Write(p []byte) (int, error)      { return len(p), nil }
func (discardConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (discardConn) Close() error                     { return nil }
func (discardConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (discardConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (discardConn) SetDeadline(time.Time) error      { return nil }
func (discardConn) SetReadDeadline(time.Time) error  { return nil }
func (discardConn) SetWriteDeadline(time.Time) error { return nil }

func BenchmarkStreamWrite32K(b *testing.B) {
	stop1, _ := parsePaddingScheme("stop=1\n0=30-30")
	bw := wrapBufferedWriteConn(discardConn{})
	s := &session{
		o:        &Outbound{},
		conn:     bw.asNetConn(),
		rawWrite: bw,
		scheme:   stop1,
		packet:   8,
		streams:  make(map[uint32]*stream),
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	s.wg.Add(1)
	go s.writeLoop()
	defer func() {
		s.fail(net.ErrClosed)
		s.wg.Wait()
	}()
	st := newStream(s, 1)
	s.streams[1] = st
	payload := make([]byte, 32<<10)
	_, _ = st.Write(payload)

	b.ReportAllocs()
	b.SetBytes(32 << 10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamWrite64K(b *testing.B) {
	stop1, _ := parsePaddingScheme("stop=1\n0=30-30")
	bw := wrapBufferedWriteConn(discardConn{})
	s := &session{
		o:        &Outbound{},
		conn:     bw.asNetConn(),
		rawWrite: bw,
		scheme:   stop1,
		packet:   8,
		streams:  make(map[uint32]*stream),
		wake:     make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	s.wg.Add(1)
	go s.writeLoop()
	defer func() {
		s.fail(net.ErrClosed)
		s.wg.Wait()
	}()
	st := newStream(s, 1)
	s.streams[1] = st
	payload := make([]byte, 64<<10)
	_, _ = st.Write(payload)

	b.ReportAllocs()
	b.SetBytes(64 << 10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamWrite32KLegacyQueueCopy(b *testing.B) {
	stop1, _ := parsePaddingScheme("stop=1\n0=30-30")
	s := &session{
		o:       &Outbound{},
		conn:    discardConn{},
		scheme:  stop1,
		packet:  8,
		streams: make(map[uint32]*stream),
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	s.wg.Add(1)
	// Legacy writeLoop: always copies batch[0].wire into buf and signals req.done.
	go func() {
		defer s.wg.Done()
		var buf []byte
		for {
			s.mu.Lock()
			for len(s.queue) == 0 && s.err == nil {
				s.mu.Unlock()
				select {
				case <-s.wake:
				case <-s.done:
				}
				s.mu.Lock()
			}
			if s.err != nil {
				s.mu.Unlock()
				return
			}
			batch := append([]*writeReq(nil), s.queue[:1]...)
			s.queue = s.queue[:0]
			s.mu.Unlock()
			buf = buf[:0]
			for _, r := range batch {
				buf = append(buf, r.wire...)
			}
			e := s.writePadded(buf)
			for _, r := range batch {
				r.done <- e
			}
		}
	}()
	defer func() {
		s.fail(net.ErrClosed)
		s.wg.Wait()
	}()
	st := newStream(s, 1)
	payload := make([]byte, 32<<10)
	need := (32 << 10) + headerSize
	st.wbuf = make([]byte, 0, need)

	b.ReportAllocs()
	b.SetBytes(32 << 10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wire := appendFrame(st.wbuf[:0], cmdPSH, st.id, payload)
		req := &writeReq{wire: wire, done: make(chan error, 1)}
		if err := s.enqueue(req); err != nil {
			b.Fatal(err)
		}
		if err := <-req.done; err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamWrite64KLegacyQueueCopy(b *testing.B) {
	stop1, _ := parsePaddingScheme("stop=1\n0=30-30")
	s := &session{
		o:       &Outbound{},
		conn:    discardConn{},
		scheme:  stop1,
		packet:  8,
		streams: make(map[uint32]*stream),
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		var buf []byte
		for {
			s.mu.Lock()
			for len(s.queue) == 0 && s.err == nil {
				s.mu.Unlock()
				select {
				case <-s.wake:
				case <-s.done:
				}
				s.mu.Lock()
			}
			if s.err != nil {
				s.mu.Unlock()
				return
			}
			batch := append([]*writeReq(nil), s.queue[:1]...)
			s.queue = s.queue[:0]
			s.mu.Unlock()
			buf = buf[:0]
			for _, r := range batch {
				buf = append(buf, r.wire...)
			}
			e := s.writePadded(buf)
			for _, r := range batch {
				r.done <- e
			}
		}
	}()
	defer func() {
		s.fail(net.ErrClosed)
		s.wg.Wait()
	}()
	st := newStream(s, 1)
	payload := make([]byte, 64<<10)
	need := maxFrame + headerSize
	st.wbuf = make([]byte, 0, need)

	b.ReportAllocs()
	b.SetBytes(64 << 10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Legacy writeChunk = maxFrame (65535), so 65536 splits into 65535 + 1 across two lockstep requests.
		rem := payload
		for len(rem) > 0 {
			n := min(len(rem), maxFrame)
			wire := appendFrame(st.wbuf[:0], cmdPSH, st.id, rem[:n])
			req := &writeReq{wire: wire, done: make(chan error, 1)}
			if err := s.enqueue(req); err != nil {
				b.Fatal(err)
			}
			if err := <-req.done; err != nil {
				b.Fatal(err)
			}
			rem = rem[n:]
		}
	}
}

// blockingFailConn pauses inside Write on the first call after failing, allowing
// the test to deterministically assert that even BEFORE s.fail(e) completes,
// no concurrent caller can acquire the inline token because s.writing is still true,
// and at the exact instant s.writing becomes false, s.err is already non-nil.
type blockingFailConn struct {
	net.Conn
	calls atomic.Int32
}

func (c *blockingFailConn) Write(p []byte) (int, error) {
	if c.calls.Add(1) == 1 {
		return min(len(p), 4), io.ErrClosedPipe
	}
	return len(p), nil
}

func (c *blockingFailConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *blockingFailConn) Close() error                     { return nil }
func (c *blockingFailConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *blockingFailConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *blockingFailConn) SetDeadline(time.Time) error      { return nil }
func (c *blockingFailConn) SetReadDeadline(time.Time) error  { return nil }
func (c *blockingFailConn) SetWriteDeadline(time.Time) error { return nil }

type hookAfterFirstWriteFailConn struct {
	net.Conn
	calls      atomic.Int32
	onFirstErr func()
}

func (c *hookAfterFirstWriteFailConn) Write(p []byte) (int, error) {
	n := c.calls.Add(1)
	if n == 1 {
		if c.onFirstErr != nil {
			defer c.onFirstErr()
		}
		return min(len(p), 4), io.ErrClosedPipe
	}
	return len(p), nil
}

func (c *hookAfterFirstWriteFailConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *hookAfterFirstWriteFailConn) Close() error                     { return nil }
func (c *hookAfterFirstWriteFailConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *hookAfterFirstWriteFailConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *hookAfterFirstWriteFailConn) SetDeadline(time.Time) error      { return nil }
func (c *hookAfterFirstWriteFailConn) SetReadDeadline(time.Time) error  { return nil }
func (c *hookAfterFirstWriteFailConn) SetWriteDeadline(time.Time) error { return nil }

// TestWriteFailureVisibilityBeforeTokenRelease deterministically verifies that
// after writeInline or writeLoop encounters a writePadded error, s.err is made
// visible and the session fails BEFORE s.writing is cleared:
//  1. At no point is (s.writing == false && s.err == nil) observable after a write failure;
//  2. No sibling stream or queued request can acquire the inline token or emit a
//     second underlying Write after the first failure;
//  3. Both the failing batch and any concurrently queued requests complete
//     exactly once with the sessionError.
func TestWriteFailureVisibilityBeforeTokenRelease(t *testing.T) {
	stop1, err := parsePaddingScheme("stop=1\n0=30-30")
	if err != nil {
		t.Fatal(err)
	}

	// Case A: writeInline fails; a tight observer polling tryAcquireInlineWrite
	// starting from the moment Write fails must NEVER observe (ok == true) nor
	// observe (s.writing == false && s.err == nil).
	t.Run("inline_write_failure_blocks_next_writer", func(t *testing.T) {
		conn := &hookAfterFirstWriteFailConn{}
		s := newSession(&Outbound{}, conn, nil, stop1, nil)
		s.packet = 8
		st1 := newStream(s, 1)
		st2 := newStream(s, 2)
		s.streams[1] = st1
		s.streams[2] = st2

		queuedReq := &writeReq{wire: appendFrame(nil, cmdHeartResponse, 1, nil), done: make(chan error, 2)}
		observerDone := make(chan error, 1)
		siblingTried := make(chan error, 1)

		conn.onFirstErr = func() {
			_ = s.enqueue(queuedReq)
			ready := make(chan struct{})
			go func() {
				close(ready)
				for {
					s.mu.Lock()
					writing, serr := s.writing, s.err
					s.mu.Unlock()
					if !writing && serr == nil {
						observerDone <- errors.New("window detected: s.writing == false while s.err == nil after write failure")
						return
					}
					ok, terr := s.tryAcquireInlineWrite()
					if ok {
						observerDone <- errors.New("window detected: tryAcquireInlineWrite succeeded after write failure")
						return
					}
					if !writing && terr != nil {
						observerDone <- nil
						return
					}
				}
			}()
			<-ready
			go func() {
				_, e := st2.Write([]byte("sibling-must-not-write"))
				siblingTried <- e
			}()
		}

		s.wg.Add(1)
		go s.writeLoop()
		defer s.wg.Wait()

		if _, err1 := st1.Write([]byte("first-inline-fails")); err1 == nil {
			t.Fatal("st1.Write succeeded on failing conn")
		}
		if obsErr := <-observerDone; obsErr != nil {
			t.Fatal(obsErr)
		}
		if ok, terr := s.tryAcquireInlineWrite(); ok || terr == nil {
			t.Fatalf("tryAcquireInlineWrite after inline failure = (%v, %v), want (false, non-nil)", ok, terr)
		}
		if _, err2 := st2.Write([]byte("post-inline-fail")); err2 == nil {
			t.Fatal("st2.Write after inline failure succeeded")
		}
		if sibErr := <-siblingTried; sibErr == nil {
			t.Fatal("racing sibling Write succeeded after first write failure")
		}
		select {
		case qerr := <-queuedReq.done:
			if qerr == nil {
				t.Fatal("queued request completed with nil error after inline failure")
			}
		case <-time.After(time.Second):
			t.Fatal("queued request was not completed on inline failure")
		}
		select {
		case extra := <-queuedReq.done:
			t.Fatalf("queued request completed more than once: %v", extra)
		default:
		}
		if gotCalls := conn.calls.Load(); gotCalls != 1 {
			t.Fatalf("underlying conn.Write calls = %d, want 1 (no frame may be written after error)", gotCalls)
		}
	})

	// Case B: writeLoop batch fails; before s.writing becomes false or any new
	// inline writer can acquire the token, s.err is set and no second conn.Write occurs.
	t.Run("writeloop_failure_blocks_inline_and_queued_writers", func(t *testing.T) {
		conn := &hookAfterFirstWriteFailConn{}
		s := newSession(&Outbound{}, conn, nil, stop1, nil)
		s.packet = 8
		st1 := newStream(s, 1)
		st2 := newStream(s, 2)
		s.streams[1] = st1
		s.streams[2] = st2

		_ = st1.SetWriteDeadline(time.Now().Add(time.Hour))
		lateQueued := &writeReq{wire: appendFrame(nil, cmdFIN, 1, nil), done: make(chan error, 2)}
		observerDone := make(chan error, 1)

		conn.onFirstErr = func() {
			_ = s.enqueue(lateQueued)
			ready := make(chan struct{})
			go func() {
				close(ready)
				for {
					s.mu.Lock()
					writing, serr := s.writing, s.err
					s.mu.Unlock()
					if !writing && serr == nil {
						observerDone <- errors.New("window detected in writeLoop: s.writing == false while s.err == nil")
						return
					}
					ok, terr := s.tryAcquireInlineWrite()
					if ok {
						observerDone <- errors.New("window detected in writeLoop: tryAcquireInlineWrite succeeded after failure")
						return
					}
					if !writing && terr != nil {
						observerDone <- nil
						return
					}
				}
			}()
			<-ready
		}

		s.wg.Add(1)
		go s.writeLoop()
		defer s.wg.Wait()

		if _, err1 := st1.Write([]byte("queued-batch-fails")); err1 == nil {
			t.Fatal("st1 queued Write succeeded on failing conn")
		}
		if obsErr := <-observerDone; obsErr != nil {
			t.Fatal(obsErr)
		}
		if ok, terr := s.tryAcquireInlineWrite(); ok || terr == nil {
			t.Fatalf("tryAcquireInlineWrite after writeLoop failure = (%v, %v), want (false, non-nil)", ok, terr)
		}
		if _, err2 := st2.Write([]byte("after-writeloop-fail")); err2 == nil {
			t.Fatal("st2 inline Write succeeded after writeLoop failure")
		}
		select {
		case lerr := <-lateQueued.done:
			if lerr == nil {
				t.Fatal("lateQueued completed with nil error")
			}
		case <-time.After(time.Second):
			t.Fatal("lateQueued was not completed by fail()")
		}
		select {
		case extra := <-lateQueued.done:
			t.Fatalf("lateQueued completed more than once: %v", extra)
		default:
		}
		if gotCalls := conn.calls.Load(); gotCalls != 1 {
			t.Fatalf("underlying conn.Write calls = %d, want 1", gotCalls)
		}
	})

	// Case C: newSession sets rawWrite before start() launches recvLoop/writeLoop.
	t.Run("newsession_sets_rawwrite_before_start", func(t *testing.T) {
		bw := wrapBufferedWriteConn(discardConn{})
		s := newSession(&Outbound{}, bw.asNetConn(), bw, stop1, nil)
		if s.rawWrite != bw {
			t.Fatal("newSession did not initialize rawWrite at construction time")
		}
	})
}


func assertRecvPoolInvariants(t testing.TB) {
	t.Helper()
	recvPool.mu.Lock()
	defer recvPool.mu.Unlock()
	total := 0
	for i, slots := range recvPool.classes {
		if len(slots) > maxRecvClassSlot {
			t.Fatalf("class %d len=%d exceeds maxRecvClassSlot=%d", i, len(slots), maxRecvClassSlot)
		}
		backing := slots[:cap(slots)]
		for j := len(slots); j < len(backing); j++ {
			if backing[j] != nil {
				t.Fatalf("class %d popped slot %d (len=%d cap=%d) was not nilled", i, j, len(slots), cap(slots))
			}
		}
		for j, b := range slots {
			if cap(b) != recvClassCaps[i] || len(b) != recvClassCaps[i] {
				t.Fatalf("class %d slot %d has len=%d cap=%d, want %d", i, j, len(b), cap(b), recvClassCaps[i])
			}
		}
		total += len(slots) * recvClassCaps[i]
	}
	if recvPool.bytes != total {
		t.Fatalf("recvPool.bytes=%d does not match actual slot sum=%d", recvPool.bytes, total)
	}
	if recvPool.bytes > maxRecvPoolBytes {
		t.Fatalf("recvPool.bytes=%d exceeds maxRecvPoolBytes=%d", recvPool.bytes, maxRecvPoolBytes)
	}
}

func TestRecvBufPoolColdClassEvictionAndBounds(t *testing.T) {
	resetRecvPoolForTest()
	t.Cleanup(resetRecvPoolForTest)

	idx512 := recvClassIndex(512)
	idx2k := recvClassIndex(2048)
	idx16k := recvClassIndex(16384)
	idx32k := recvClassIndex(32768)
	idxMax := recvClassIndex(maxFrame)

	t.Run("full_old_class_budget_evicts_for_current_demand_within_2mib_32_slots", func(t *testing.T) {
		resetRecvPoolForTest()

		// Fill classes[4] (32KiB) with 32 buffers (1,048,576 B) and classes[5] (65535 B) with 16 buffers (1,048,560 B).
		// Total bytes = 2,097,136 B (only 16 B below maxRecvPoolBytes = 2,097,152 B).
		holders32k := make([][]byte, maxRecvClassSlot)
		for i := range holders32k {
			holders32k[i] = acquireRecvBuf(32768)
		}
		for _, b := range holders32k {
			releaseRecvBuf(b)
		}
		holdersMax16 := make([][]byte, 16)
		for i := range holdersMax16 {
			holdersMax16[i] = acquireRecvBuf(maxFrame)
		}
		for _, b := range holdersMax16 {
			releaseRecvBuf(b)
		}
		assertRecvPoolInvariants(t)
		slots32k, totalBytes := recvPoolCountForClass(idx32k)
		slotsMax, _ := recvPoolCountForClass(idxMax)
		if slots32k != 32 || slotsMax != 16 || totalBytes != 32*32768+16*maxFrame {
			t.Fatalf("initial state: slots32k=%d slotsMax=%d bytes=%d", slots32k, slotsMax, totalBytes)
		}

		// Now acquire 32 maxFrame buffers simultaneously (e.g. 16 streams * 2 buffers) and release all 32.
		wave := make([][]byte, maxRecvClassSlot)
		for i := range wave {
			wave[i] = acquireRecvBuf(maxFrame)
		}
		for _, b := range wave {
			releaseRecvBuf(b)
			assertRecvPoolInvariants(t)
		}

		slots32kAfter, totalAfter := recvPoolCountForClass(idx32k)
		slotsMaxAfter, _ := recvPoolCountForClass(idxMax)
		if slotsMaxAfter != maxRecvClassSlot {
			t.Fatalf("after releasing 32 maxFrame buffers: slotsMax=%d, want %d", slotsMaxAfter, maxRecvClassSlot)
		}
		if slots32kAfter != 0 {
			t.Fatalf("after releasing 32 maxFrame buffers: slots32k=%d, want 0", slots32kAfter)
		}
		if totalAfter != maxRecvClassSlot*maxFrame {
			t.Fatalf("after releasing 32 maxFrame buffers: bytes=%d, want %d", totalAfter, maxRecvClassSlot*maxFrame)
		}

		// A 33rd maxFrame buffer must not exceed maxRecvClassSlot (32).
		extra := make([]byte, maxFrame)
		releaseRecvBuf(extra)
		assertRecvPoolInvariants(t)
		if s, _ := recvPoolCountForClass(idxMax); s != maxRecvClassSlot {
			t.Fatalf("33rd release exceeded maxRecvClassSlot: got %d", s)
		}

		// Subsequent 32-buffer maxFrame wave must hit all 32 pooled buffers with 0 allocations.
		allocs := testing.AllocsPerRun(20, func() {
			for i := range wave {
				wave[i] = acquireRecvBuf(maxFrame)
			}
			for i, b := range wave {
				releaseRecvBuf(b)
				wave[i] = nil
			}
		})
		if allocs != 0 {
			t.Fatalf("32x maxFrame wave after cold-class eviction allocated %v objects/run, want 0", allocs)
		}
	})

	t.Run("recency_order_evicts_least_recently_used_class_first", func(t *testing.T) {
		resetRecvPoolForTest()

		// Populate classes in order: 2KiB (idx2k), 16KiB (idx16k), 32KiB (idx32k).
		b2k := acquireRecvBuf(2048)
		releaseRecvBuf(b2k)
		b16k := acquireRecvBuf(16384)
		releaseRecvBuf(b16k)
		h32 := make([][]byte, 31)
		for i := range h32 {
			h32[i] = acquireRecvBuf(32768)
		}
		for _, b := range h32 {
			releaseRecvBuf(b)
		}
		// Touch 2KiB class so 16KiB becomes the oldest (coldest) non-empty class, then 32KiB, then 2KiB.
		b2k = acquireRecvBuf(2048)
		releaseRecvBuf(b2k)

		// Fill maxFrame slots until budget is nearly full:
		// Currently bytes = 2048 + 16384 + 31*32768 = 1,034,240 B.
		// 16 * 65535 = 1,048,560 B -> sum = 2,082,800 B (14,352 B spare).
		hMax := make([][]byte, 16)
		for i := range hMax {
			hMax[i] = acquireRecvBuf(maxFrame)
		}
		for _, b := range hMax {
			releaseRecvBuf(b)
		}
		assertRecvPoolInvariants(t)
		if s16, _ := recvPoolCountForClass(idx16k); s16 != 1 {
			t.Fatalf("expected 16KiB slot still present before overflow, got %d", s16)
		}

		// Release a 17th maxFrame (needs 65535 - 14352 = 51183 B):
		// Must evict oldest class 16KiB (16384 B) first, then 2 slots of next-oldest 32KiB (65536 B),
		// leaving the recently-used 2KiB class untouched!
		m17 := make([]byte, maxFrame)
		releaseRecvBuf(m17)
		assertRecvPoolInvariants(t)

		s16After, _ := recvPoolCountForClass(idx16k)
		s32After, _ := recvPoolCountForClass(idx32k)
		s2After, _ := recvPoolCountForClass(idx2k)
		sMaxAfter, _ := recvPoolCountForClass(idxMax)
		if s16After != 0 || s32After != 29 || s2After != 1 || sMaxAfter != 17 {
			t.Fatalf("LRU eviction mismatch: s16=%d (want 0), s32=%d (want 29), s2=%d (want 1), sMax=%d (want 17)",
				s16After, s32After, s2After, sMaxAfter)
		}

		// Also verify smallest class (512B) works cleanly under eviction.
		b512 := acquireRecvBuf(512)
		releaseRecvBuf(b512)
		if s512, _ := recvPoolCountForClass(idx512); s512 != 1 {
			t.Fatalf("s512=%d, want 1", s512)
		}
	})

	t.Run("interleaved_and_concurrent_acquire_release_never_reuses_live_buffers", func(t *testing.T) {
		resetRecvPoolForTest()

		var activeMu sync.Mutex
		activePtrs := make(map[*byte]int)

		sizes := []int{512, 2048, 8192, 16384, 32768, maxFrame}
		var wg sync.WaitGroup
		const workers = 12
		const iters = 150
		errCh := make(chan error, workers)

		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				held := make([][]byte, 0, 6)
				for it := 0; it < iters; it++ {
					sz := sizes[(workerID+it)%len(sizes)]
					b := acquireRecvBuf(sz)
					full := b[:cap(b)]
					ptr := &full[0]
					tag := byte((workerID*37 + it) & 0xff)

					activeMu.Lock()
					if prev, dup := activePtrs[ptr]; dup {
						activeMu.Unlock()
						errCh <- fmt.Errorf("live buffer %p simultaneously held by worker %d and %d", ptr, prev, workerID)
						return
					}
					activePtrs[ptr] = workerID
					activeMu.Unlock()

					b[0] = tag
					b[len(b)-1] = tag ^ 0x5a
					held = append(held, b)

					if len(held) >= 4 || it == iters-1 {
						for _, hb := range held {
							hfull := hb[:cap(hb)]
							hptr := &hfull[0]
							if hb[len(hb)-1] != (hb[0] ^ 0x5a) {
								errCh <- fmt.Errorf("live buffer %p corrupted while held", hptr)
								return
							}
							activeMu.Lock()
							delete(activePtrs, hptr)
							activeMu.Unlock()
							releaseRecvBuf(hb)
						}
						held = held[:0]
					}
				}
			}(w)
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			t.Fatal(err)
		}
		assertRecvPoolInvariants(t)
	})
}

// chunkQueueConn is a deterministic scriptable net.Conn for readFrames testing.
// Each Read returns from the current chunk; payload reads can be counted and gated.
type chunkQueueConn struct {
	mu          sync.Mutex
	cond        *sync.Cond
	chunks      [][]byte
	closed      bool
	readErr     error
	payloadGate bool
	payloadRead atomic.Int64
	headerRead  atomic.Int64
}

func newChunkQueueConn() *chunkQueueConn {
	c := &chunkQueueConn{}
	c.cond = sync.NewCond(&c.mu)
	return c
}

func (c *chunkQueueConn) pushChunk(b []byte) {
	cp := append([]byte(nil), b...)
	c.mu.Lock()
	c.chunks = append(c.chunks, cp)
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *chunkQueueConn) setPayloadGate(CountAsPayload bool) {
	c.mu.Lock()
	c.payloadGate = CountAsPayload
	c.mu.Unlock()
}

func (c *chunkQueueConn) closeWithError(err error) {
	c.mu.Lock()
	c.closed = true
	c.readErr = err
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *chunkQueueConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	for len(c.chunks) == 0 && !c.closed {
		c.cond.Wait()
	}
	if len(c.chunks) == 0 {
		err := c.readErr
		c.mu.Unlock()
		if err == nil {
			err = io.EOF
		}
		return 0, err
	}
	cur := c.chunks[0]
	n := copy(p, cur)
	if n == len(cur) {
		c.chunks = c.chunks[1:]
	} else {
		c.chunks[0] = cur[n:]
	}
	gate := c.payloadGate
	c.mu.Unlock()
	if gate {
		c.payloadRead.Add(int64(n))
	} else {
		c.headerRead.Add(int64(n))
	}
	return n, nil
}

func (c *chunkQueueConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *chunkQueueConn) Close() error                       { c.closeWithError(net.ErrClosed); return nil }
func (c *chunkQueueConn) LocalAddr() net.Addr                { return dummyAddr("local") }
func (c *chunkQueueConn) RemoteAddr() net.Addr               { return dummyAddr("remote") }
func (c *chunkQueueConn) SetDeadline(time.Time) error        { return nil }
func (c *chunkQueueConn) SetReadDeadline(time.Time) error    { return nil }
func (c *chunkQueueConn) SetWriteDeadline(time.Time) error   { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }

func waitStreamInBytes(t *testing.T, st *stream, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st.mu.Lock()
		got := st.inBytes
		st.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	st.mu.Lock()
	got := st.inBytes
	st.mu.Unlock()
	t.Fatalf("timeout waiting for st.inBytes=%d, got %d", want, got)
}

func TestReadFramesWaitSpaceBeforeAcquireAndSemantics(t *testing.T) {
	resetRecvPoolForTest()
	t.Cleanup(resetRecvPoolForTest)

	idxMax := recvClassIndex(maxFrame)

	t.Run("full_window_blocks_before_acquire_and_payload_read_and_advances_after_drain", func(t *testing.T) {
		resetRecvPoolForTest()
		conn := newChunkQueueConn()
		s := &session{
			o:       &Outbound{},
			conn:    conn,
			streams: make(map[uint32]*stream),
			wake:    make(chan struct{}, 1),
			done:    make(chan struct{}),
		}
		st := newStream(s, 1)
		s.streams[1] = st

		recvDone := make(chan error, 1)
		go func() {
			recvDone <- s.readFrames()
		}()

		// Push 16 full maxFrame (65535B) frames -> 1,048,560 B (<= maxStreamBuffer = 1,048,576 B).
		var expected []byte
		for i := 0; i < 16; i++ {
			p := pattern(100+i, maxFrame)
			expected = append(expected, p...)
			conn.pushChunk(appendFrame(nil, cmdPSH, 1, p))
		}
		waitStreamInBytes(t, st, 16*maxFrame)

		// Put 1 known maxFrame buffer into recvPool so we can observe whether frame 17 acquires it prematurely.
		sentinel := make([]byte, maxFrame)
		releaseRecvBuf(sentinel)
		if slots, _ := recvPoolCountForClass(idxMax); slots != 1 {
			t.Fatalf("expected 1 pooled maxFrame sentinel before frame 17 header, got %d", slots)
		}

		// Send ONLY the 7-byte header for frame 17 (cmdPSH, id=1, len=maxFrame), then arm payload counter
		// and queue frame 17's payload as the next chunk. Because bufio.Reader reads the 7-byte header chunk
		// in one Read call and readFrames blocks in st.waitSpace(maxFrame) BEFORE acquireRecvBuf or io.ReadFull(payload),
		// neither acquireRecvBuf nor the payload Read may occur while the window is full!
		var hdr17 [headerSize]byte
		hdr17[0] = cmdPSH
		binary.BigEndian.PutUint32(hdr17[1:5], 1)
		binary.BigEndian.PutUint16(hdr17[5:7], uint16(maxFrame))
		conn.pushChunk(hdr17[:])

		deadline := time.Now().Add(time.Second)
		for conn.headerRead.Load() < int64(16*(headerSize+maxFrame)+headerSize) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		conn.setPayloadGate(true)
		p17 := pattern(217, maxFrame)
		expected = append(expected, p17...)
		conn.pushChunk(p17)
		conn.pushChunk(appendFrame(nil, cmdFIN, 1, nil))

		time.Sleep(25 * time.Millisecond)
		if slots, _ := recvPoolCountForClass(idxMax); slots != 1 {
			t.Fatalf("acquireRecvBuf ran prematurely while window was full: slots=%d, want 1", slots)
		}
		if gotPayload := conn.payloadRead.Load(); gotPayload != 0 {
			t.Fatalf("underlying payload Read ran prematurely while window was full: payloadRead=%d, want 0", gotPayload)
		}

		// Partial Read(1000) on frame 0 does NOT free a frame (st.inBytes remains 16*maxFrame):
		// waitSpace must remain blocked (no acquire, no payload Read).
		part := make([]byte, 1000)
		nPart, err := st.Read(part)
		if err != nil || nPart != 1000 {
			t.Fatalf("partial Read(1000) = (%d, %v)", nPart, err)
		}
		time.Sleep(15 * time.Millisecond)
		if slots, _ := recvPoolCountForClass(idxMax); slots != 1 {
			t.Fatalf("acquireRecvBuf ran after partial Read before frame 0 was drained: slots=%d, want 1", slots)
		}
		if gotPayload := conn.payloadRead.Load(); gotPayload != 0 {
			t.Fatalf("payload Read ran after partial Read before frame 0 was drained: payloadRead=%d, want 0", gotPayload)
		}

		// Drain the remaining maxFrame-1000 bytes of frame 0: this frees frame 0, signals st.space,
		// and unblocks waitSpace so frame 17 acquires from pool and reads its payload.
		rest0 := make([]byte, maxFrame-1000)
		nRest, err := st.Read(rest0)
		if err != nil || nRest != maxFrame-1000 {
			t.Fatalf("rest of frame 0 Read = (%d, %v)", nRest, err)
		}
		waitStreamInBytes(t, st, 16*maxFrame)
		if gotPayload := conn.payloadRead.Load(); gotPayload < int64(maxFrame) {
			t.Fatalf("expected frame 17 payload Read after draining frame 0, got %d", gotPayload)
		}

		// Drain all remaining 16 frames and verify EOF + full payload integrity.
		tail, err := io.ReadAll(st)
		if err != nil {
			t.Fatalf("ReadAll remaining frames: %v", err)
		}
		gotAll := append(append(part[:nPart], rest0[:nRest]...), tail...)
		if !bytes.Equal(gotAll, expected) {
			t.Fatalf("reconstructed stream len=%d want=%d mismatch", len(gotAll), len(expected))
		}
		_ = st.Close()
		conn.closeWithError(io.EOF)
		<-recvDone
		assertRecvPoolInvariants(t)
	})

	t.Run("close_while_waiting_discards_frame_and_preserves_next_header_alignment", func(t *testing.T) {
		resetRecvPoolForTest()
		conn := newChunkQueueConn()
		s := &session{
			o:       &Outbound{},
			conn:    conn,
			streams: make(map[uint32]*stream),
			wake:    make(chan struct{}, 1),
			done:    make(chan struct{}),
		}
		st1 := newStream(s, 1)
		st2 := newStream(s, 2)
		s.streams[1] = st1
		s.streams[2] = st2

		recvDone := make(chan error, 1)
		go func() {
			recvDone <- s.readFrames()
		}()

		for i := 0; i < 16; i++ {
			conn.pushChunk(appendFrame(nil, cmdPSH, 1, pattern(i+1, maxFrame)))
		}
		waitStreamInBytes(t, st1, 16*maxFrame)

		// Send frame 17 header on stream 1, wait until readFrames has read the header and is waiting in waitSpace.
		var hdr17 [headerSize]byte
		hdr17[0] = cmdPSH
		binary.BigEndian.PutUint32(hdr17[1:5], 1)
		binary.BigEndian.PutUint16(hdr17[5:7], uint16(maxFrame))
		conn.pushChunk(hdr17[:])
		deadline := time.Now().Add(time.Second)
		for conn.headerRead.Load() < int64(16*(headerSize+maxFrame)+headerSize) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}

		// Queue frame 17's payload followed by a heartbeat request and stream 2's PSH+FIN frames.
		wantSt2 := pattern(77, 2048)
		conn.pushChunk(pattern(99, maxFrame))
		conn.pushChunk(appendFrame(nil, cmdHeartRequest, 42, nil))
		conn.pushChunk(appendFrame(nil, cmdPSH, 2, wantSt2))
		conn.pushChunk(appendFrame(nil, cmdFIN, 2, nil))

		// Close st1 while readFrames is blocked in waitSpace:
		// st1.Close() must release the 16 queued buffers, unblock waitSpace, discard frame 17's payload
		// without corrupting framing, process cmdHeartRequest, and deliver stream 2's PSH+FIN intact!
		_ = st1.Close()

		gotSt2, err := io.ReadAll(st2)
		if err != nil {
			t.Fatalf("st2 ReadAll after st1 Close during waitSpace: %v", err)
		}
		if !bytes.Equal(gotSt2, wantSt2) {
			t.Fatalf("st2 payload mismatch after st1 Close discarded in-flight frame")
		}
		_ = st2.Close()
		conn.closeWithError(io.EOF)
		<-recvDone
		assertRecvPoolInvariants(t)
	})

	t.Run("abort_and_session_fail_while_waiting_preserve_queued_data_before_error", func(t *testing.T) {
		// Case A: s.fail(boom) while readFrames is blocked in waitSpace (without frame 17 payload even sent).
		resetRecvPoolForTest()
		conn := newChunkQueueConn()
		s := &session{
			o:       &Outbound{},
			conn:    conn,
			streams: make(map[uint32]*stream),
			wake:    make(chan struct{}, 1),
			done:    make(chan struct{}),
		}
		st := newStream(s, 1)
		s.streams[1] = st

		recvDone := make(chan error, 1)
		go func() {
			recvDone <- s.readFrames()
		}()

		var want16 []byte
		for i := 0; i < 16; i++ {
			p := pattern(30+i, maxFrame)
			want16 = append(want16, p...)
			conn.pushChunk(appendFrame(nil, cmdPSH, 1, p))
		}
		waitStreamInBytes(t, st, 16*maxFrame)

		var hdr17 [headerSize]byte
		hdr17[0] = cmdPSH
		binary.BigEndian.PutUint32(hdr17[1:5], 1)
		binary.BigEndian.PutUint16(hdr17[5:7], uint16(maxFrame))
		conn.pushChunk(hdr17[:])
		deadline := time.Now().Add(time.Second)
		for conn.headerRead.Load() < int64(16*(headerSize+maxFrame)+headerSize) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}

		boom := errors.New("transport reset during backpressure wait")
		s.fail(boom)

		select {
		case rerr := <-recvDone:
			if !errors.Is(rerr, boom) {
				t.Fatalf("readFrames after s.fail = %v, want %v", rerr, boom)
			}
		case <-time.After(time.Second):
			t.Fatal("readFrames did not terminate on s.fail during waitSpace")
		}

		// All 16 queued frames must still be delivered before Read returns the session failure error.
		buf := make([]byte, 64<<10)
		var got16 []byte
		for len(got16) < len(want16) {
			n, err := st.Read(buf)
			if err != nil {
				t.Fatalf("unexpected error after %d/%d queued bytes: %v", len(got16), len(want16), err)
			}
			got16 = append(got16, buf[:n]...)
		}
		if !bytes.Equal(got16, want16) {
			t.Fatal("queued bytes before session fail corrupted")
		}
		if n, err := st.Read(buf); n != 0 || !errors.Is(err, boom) {
			t.Fatalf("post-drain Read after s.fail = (%d, %v), want (0, %v)", n, err, boom)
		}
		if slots, _ := recvPoolCountForClass(idxMax); slots != 16 {
			t.Fatalf("expected all 16 drained buffers returned to pool, got %d", slots)
		}
		_ = st.Close()
		assertRecvPoolInvariants(t)

		// Case B: per-stream st.abort(boom) while session continues to next stream frame.
		resetRecvPoolForTest()
		conn2 := newChunkQueueConn()
		s2 := &session{
			o:       &Outbound{},
			conn:    conn2,
			streams: make(map[uint32]*stream),
			wake:    make(chan struct{}, 1),
			done:    make(chan struct{}),
		}
		stA := newStream(s2, 1)
		stB := newStream(s2, 2)
		s2.streams[1] = stA
		s2.streams[2] = stB
		recvDone2 := make(chan error, 1)
		go func() {
			recvDone2 <- s2.readFrames()
		}()

		for i := 0; i < 16; i++ {
			conn2.pushChunk(appendFrame(nil, cmdPSH, 1, pattern(50+i, maxFrame)))
		}
		waitStreamInBytes(t, stA, 16*maxFrame)
		conn2.pushChunk(hdr17[:])
		deadline = time.Now().Add(time.Second)
		for conn2.headerRead.Load() < int64(16*(headerSize+maxFrame)+headerSize) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}

		wantB := pattern(88, 1024)
		conn2.pushChunk(pattern(90, maxFrame))
		conn2.pushChunk(appendFrame(nil, cmdPSH, 2, wantB))
		conn2.pushChunk(appendFrame(nil, cmdFIN, 2, nil))

		abortErr := errors.New("stream-scoped abort while waiting")
		stA.abort(abortErr)

		gotB, err := io.ReadAll(stB)
		if err != nil || !bytes.Equal(gotB, wantB) {
			t.Fatalf("stB ReadAll after stA.abort = (%d, %v)", len(gotB), err)
		}
		for i := 0; i < 16; i++ {
			n, err := stA.Read(buf)
			if err != nil || n != maxFrame {
				t.Fatalf("stA queued frame %d Read = (%d, %v)", i, n, err)
			}
		}
		if n, err := stA.Read(buf); n != 0 || !errors.Is(err, abortErr) {
			t.Fatalf("stA final Read after abort = (%d, %v), want (0, %v)", n, err, abortErr)
		}
		_ = stA.Close()
		_ = stB.Close()
		conn2.closeWithError(io.EOF)
		<-recvDone2
		assertRecvPoolInvariants(t)
	})

	t.Run("remote_fin_while_waiting_discards_frame_and_delivers_queued_data_before_eof", func(t *testing.T) {
		resetRecvPoolForTest()
		conn := newChunkQueueConn()
		s := &session{
			o:       &Outbound{},
			conn:    conn,
			streams: make(map[uint32]*stream),
			wake:    make(chan struct{}, 1),
			done:    make(chan struct{}),
		}
		st1 := newStream(s, 1)
		st2 := newStream(s, 2)
		s.streams[1] = st1
		s.streams[2] = st2

		recvDone := make(chan error, 1)
		go func() {
			recvDone <- s.readFrames()
		}()

		var want1 []byte
		for i := 0; i < 16; i++ {
			p := pattern(60+i, maxFrame)
			want1 = append(want1, p...)
			conn.pushChunk(appendFrame(nil, cmdPSH, 1, p))
		}
		waitStreamInBytes(t, st1, 16*maxFrame)

		var hdr17 [headerSize]byte
		hdr17[0] = cmdPSH
		binary.BigEndian.PutUint32(hdr17[1:5], 1)
		binary.BigEndian.PutUint16(hdr17[5:7], uint16(maxFrame))
		conn.pushChunk(hdr17[:])
		deadline := time.Now().Add(time.Second)
		for conn.headerRead.Load() < int64(16*(headerSize+maxFrame)+headerSize) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}

		want2 := pattern(61, 512)
		conn.pushChunk(pattern(62, maxFrame))
		conn.pushChunk(appendFrame(nil, cmdPSH, 2, want2))
		conn.pushChunk(appendFrame(nil, cmdFIN, 2, nil))

		st1.remoteClose(io.EOF)

		got2, err := io.ReadAll(st2)
		if err != nil || !bytes.Equal(got2, want2) {
			t.Fatalf("st2 ReadAll after st1.remoteClose = (%d, %v)", len(got2), err)
		}
		got1, err := io.ReadAll(st1)
		if err != nil || !bytes.Equal(got1, want1) {
			t.Fatalf("st1 ReadAll after remoteClose = (len=%d want=%d, err=%v)", len(got1), len(want1), err)
		}
		_ = st1.Close()
		_ = st2.Close()
		conn.closeWithError(io.EOF)
		<-recvDone
		assertRecvPoolInvariants(t)
	})

	t.Run("short_frame_1b_small_stream_and_deadline_cancel_timing", func(t *testing.T) {
		// 1. Short frame during r.Discard(n) after st.Close() while waiting in waitSpace returns io.ErrUnexpectedEOF.
		resetRecvPoolForTest()
		conn := newChunkQueueConn()
		s := &session{
			o:       &Outbound{},
			conn:    conn,
			streams: make(map[uint32]*stream),
			wake:    make(chan struct{}, 1),
			done:    make(chan struct{}),
		}
		st := newStream(s, 1)
		s.streams[1] = st
		recvDone := make(chan error, 1)
		go func() {
			recvDone <- s.readFrames()
		}()

		for i := 0; i < 16; i++ {
			conn.pushChunk(appendFrame(nil, cmdPSH, 1, pattern(i+1, maxFrame)))
		}
		waitStreamInBytes(t, st, 16*maxFrame)

		var hdr17 [headerSize]byte
		hdr17[0] = cmdPSH
		binary.BigEndian.PutUint32(hdr17[1:5], 1)
		binary.BigEndian.PutUint16(hdr17[5:7], 4096)
		conn.pushChunk(hdr17[:])
		deadline := time.Now().Add(time.Second)
		for conn.headerRead.Load() < int64(16*(headerSize+maxFrame)+headerSize) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		// Only 500 bytes of the 4096B frame arrive before EOF.
		conn.pushChunk(make([]byte, 500))
		conn.closeWithError(io.EOF)
		_ = st.Close()

		if err := <-recvDone; !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("truncated discard after Close = %v, want io.ErrUnexpectedEOF", err)
		}
		assertRecvPoolInvariants(t)

		// 2. 1-byte small stream frames (n=1 < minPooledFrame), zero-length PSH, cross-frame read,
		// and read deadline timeout + recovery while backpressured.
		resetRecvPoolForTest()
		connSmall := newChunkQueueConn()
		sSmall := &session{
			o:       &Outbound{},
			conn:    connSmall,
			streams: make(map[uint32]*stream),
			wake:    make(chan struct{}, 1),
			done:    make(chan struct{}),
		}
		stSmall := newStream(sSmall, 9)
		sSmall.streams[9] = stSmall
		recvDoneSmall := make(chan error, 1)
		go func() {
			recvDoneSmall <- sSmall.readFrames()
		}()

		// Fill window with 16 * maxFrame, then queue 1-byte PSH frames + 0-byte PSH + FIN.
		var wantAll []byte
		for i := 0; i < 16; i++ {
			p := pattern(10+i, maxFrame)
			wantAll = append(wantAll, p...)
			connSmall.pushChunk(appendFrame(nil, cmdPSH, 9, p))
		}
		waitStreamInBytes(t, stSmall, 16*maxFrame)

		connSmall.pushChunk(appendFrame(nil, cmdPSH, 9, nil)) // 0-byte PSH
		for i := 0; i < 7; i++ {
			b1 := []byte{byte('A' + i)}
			wantAll = append(wantAll, b1...)
			connSmall.pushChunk(appendFrame(nil, cmdPSH, 9, b1))
		}
		connSmall.pushChunk(appendFrame(nil, cmdFIN, 9, nil))

		// Expire read deadline before draining: Read must fail with ErrDeadlineExceeded without losing buffered frames.
		_ = stSmall.SetReadDeadline(time.Now().Add(-time.Millisecond))
		if n, err := stSmall.Read(make([]byte, 16)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("expired deadline Read = (%d, %v), want (0, ErrDeadlineExceeded)", n, err)
		}
		// Cross-frame read: drain 1000B partial + remaining 64535B + next full 65535B frame in two Reads.
		_ = stSmall.SetReadDeadline(time.Time{})
		partA := make([]byte, 1000)
		nA, err := stSmall.Read(partA)
		if err != nil || nA != 1000 {
			t.Fatalf("partA Read = (%d, %v)", nA, err)
		}
		// Cross-frame buffer large enough for rest of frame 0 (64535B) + full frame 1 (65535B) = 130070B.
		crossBuf := make([]byte, (maxFrame-1000)+maxFrame)
		nCross, err := stSmall.Read(crossBuf)
		if err != nil || nCross != len(crossBuf) {
			t.Fatalf("cross-frame Read = (%d, %v), want (%d, nil)", nCross, err, len(crossBuf))
		}
		// Cancel active blocked Read via immediate SetReadDeadline(now) once remaining frames are drained:
		restSmall, err := io.ReadAll(stSmall)
		if err != nil {
			t.Fatalf("ReadAll after cross-frame read: %v", err)
		}
		gotSmall := append(append(partA[:nA], crossBuf[:nCross]...), restSmall...)
		if !bytes.Equal(gotSmall, wantAll) {
			t.Fatalf("small-frame + cross-frame + backpressure stream mismatch: got %dB, want %dB", len(gotSmall), len(wantAll))
		}
		_ = stSmall.Close()
		connSmall.closeWithError(io.EOF)
		<-recvDoneSmall

		// 3. Short frame / unexpected EOF after waitSpace unblocks (during io.ReadFull of frame 17)
		// plus active Read cancel timing via SetReadDeadline while reader is blocked.
		resetRecvPoolForTest()
		connShort := newChunkQueueConn()
		sShort := &session{
			o:       &Outbound{},
			conn:    connShort,
			streams: make(map[uint32]*stream),
			wake:    make(chan struct{}, 1),
			done:    make(chan struct{}),
		}
		stShort := newStream(sShort, 10)
		sShort.streams[10] = stShort
		// Verify active blocked Read wakes on SetReadDeadline cancel before any frame arrives.
		readCancelErr := make(chan error, 1)
		go func() {
			_, rerr := stShort.Read(make([]byte, 32))
			readCancelErr <- rerr
		}()
		time.Sleep(10 * time.Millisecond)
		_ = stShort.SetReadDeadline(time.Now())
		if rerr := <-readCancelErr; !errors.Is(rerr, os.ErrDeadlineExceeded) {
			t.Fatalf("canceled blocked Read = %v, want os.ErrDeadlineExceeded", rerr)
		}
		_ = stShort.SetReadDeadline(time.Time{})

		recvDoneShort := make(chan error, 1)
		go func() {
			recvDoneShort <- sShort.readFrames()
		}()
		for i := 0; i < 16; i++ {
			connShort.pushChunk(appendFrame(nil, cmdPSH, 10, pattern(i+1, maxFrame)))
		}
		waitStreamInBytes(t, stShort, 16*maxFrame)
		connShort.pushChunk(hdr17[:]) // 4096B header
		deadline = time.Now().Add(time.Second)
		for connShort.headerRead.Load() < int64(16*(headerSize+maxFrame)+headerSize) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		connShort.pushChunk(make([]byte, 1200)) // short payload (1200 < 4096)
		connShort.closeWithError(io.EOF)
		// Drain frame 0 to unblock waitSpace(4096): io.ReadFull then hits unexpected EOF and releases the 8KiB buffer back to pool.
		if n, err := stShort.Read(make([]byte, 64<<10)); err != nil || n != maxFrame {
			t.Fatalf("drain frame 0 on stShort = (%d, %v)", n, err)
		}
		if err := <-recvDoneShort; !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("short payload after waitSpace unblock = %v, want io.ErrUnexpectedEOF", err)
		}
		_ = stShort.Close()
		assertRecvPoolInvariants(t)
	})
}

func TestRecvPoolColdClassEvictionAllocCountReduction(t *testing.T) {
	resetRecvPoolForTest()
	t.Cleanup(resetRecvPoolForTest)

	// Pre-fill 32 slots of 32KiB (1 MiB) and 16 slots of maxFrame (1 MiB), reproducing the cold-class occupation state.
	h32 := make([][]byte, maxRecvClassSlot)
	for i := range h32 {
		h32[i] = acquireRecvBuf(32768)
	}
	for _, b := range h32 {
		releaseRecvBuf(b)
	}
	hMax := make([][]byte, 16)
	for i := range hMax {
		hMax[i] = acquireRecvBuf(maxFrame)
	}
	for _, b := range hMax {
		releaseRecvBuf(b)
	}

	// First wave of 32 maxFrame buffers (16 streams * 2 buffers) evicts the idle 32KiB slots on release.
	wave := make([][]byte, maxRecvClassSlot)
	for i := range wave {
		wave[i] = acquireRecvBuf(maxFrame)
	}
	for i, b := range wave {
		releaseRecvBuf(b)
		wave[i] = nil
	}

	// Measure steady-state allocations over 32-buffer maxFrame waves: must be 0 allocs/op (vs 16 * 64KiB = 1 MiB per wave before fix).
	allocsWave := testing.AllocsPerRun(50, func() {
		for i := range wave {
			wave[i] = acquireRecvBuf(maxFrame)
		}
		for i, b := range wave {
			releaseRecvBuf(b)
			wave[i] = nil
		}
	})
	if allocsWave != 0 {
		t.Fatalf("steady-state 32x maxFrame wave allocs = %v, want 0", allocsWave)
	}

	// Also verify single-stream full-window backpressure (16 queued frames) with only 16 maxFrame buffers in pool:
	// because waitSpace waits for st.Read to drain & release frame 0 BEFORE acquiring frame 17, 0 heap allocations occur.
	resetRecvPoolForTest()
	s := &session{
		o:       &Outbound{},
		streams: make(map[uint32]*stream),
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	st := newStream(s, 1)
	for i := 0; i < 16; i++ {
		st.pushPooled(acquireRecvBuf(maxFrame))
	}
	readBuf := make([]byte, 64<<10)
	allocsSingle := testing.AllocsPerRun(50, func() {
		// Drain 1 frame from full 16-frame window (releases 1 maxFrame buffer to recvPool),
		// then waitSpace(maxFrame) + acquireRecvBuf(maxFrame) + pushPooled reuses that exact buffer.
		n, err := st.Read(readBuf)
		if err != nil || n != maxFrame {
			t.Fatalf("Read = (%d, %v)", n, err)
		}
		ok, _ := st.waitSpace(maxFrame)
		if !ok {
			t.Fatal("waitSpace returned false")
		}
		st.pushPooled(acquireRecvBuf(maxFrame))
	})
	_ = st.Close()
	if allocsSingle != 0 {
		t.Fatalf("single-stream 16-frame full-window step allocs = %v, want 0", allocsSingle)
	}
	t.Logf("cold-class occupation 32x maxFrame wave: steady-state allocs/op=%.0f (was 16 allocs = 1048576 B/wave without cold-class eviction); single-stream full-window backpressure step: steady-state allocs/op=%.0f (was 1 alloc = 65536 B/frame when acquireRecvBuf ran before waitSpace)", allocsWave, allocsSingle)
}

func BenchmarkRecvPoolColdClassEvictionMaxFrameWave(b *testing.B) {
	resetRecvPoolForTest()
	h32 := make([][]byte, maxRecvClassSlot)
	for i := range h32 {
		h32[i] = acquireRecvBuf(32768)
	}
	for _, buf := range h32 {
		releaseRecvBuf(buf)
	}
	wave := make([][]byte, maxRecvClassSlot)
	for i := range wave {
		wave[i] = acquireRecvBuf(maxFrame)
	}
	for i, buf := range wave {
		releaseRecvBuf(buf)
		wave[i] = nil
	}
	b.ReportAllocs()
	b.SetBytes(int64(maxRecvClassSlot * maxFrame))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range wave {
			wave[j] = acquireRecvBuf(maxFrame)
		}
		for j, buf := range wave {
			releaseRecvBuf(buf)
			wave[j] = nil
		}
	}
}
