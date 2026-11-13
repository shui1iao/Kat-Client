package kernel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/stats"
)

type recordChunkConn struct {
	net.Conn
	mu          sync.Mutex
	readChunks  [][]byte
	reads       int
	writes      int
	written     bytes.Buffer
	closeWrites atomic.Int32
	closed      atomic.Bool
}

func (c *recordChunkConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	if len(c.readChunks) == 0 {
		return 0, io.EOF
	}
	cur := c.readChunks[0]
	n := copy(p, cur)
	if n == len(cur) {
		c.readChunks = c.readChunks[1:]
	} else {
		c.readChunks[0] = cur[n:]
	}
	return n, nil
}

func (c *recordChunkConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	return c.written.Write(p)
}

func (c *recordChunkConn) CloseWrite() error {
	c.closeWrites.Add(1)
	if c.Conn != nil {
		return closeWrite(c.Conn)
	}
	return nil
}

func (c *recordChunkConn) Close() error {
	c.closed.Store(true)
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

func (c *recordChunkConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *recordChunkConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *recordChunkConn) SetDeadline(time.Time) error      { return nil }
func (c *recordChunkConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordChunkConn) SetWriteDeadline(time.Time) error { return nil }

func TestRelayBufferPoolPreservesInputsAndBudget(t *testing.T) {
	for _, tc := range []struct {
		name       string
		inSize     int
		inCount    int
		wantSize   int
		wantCap    int
		wantBudget int
	}{
		{"clientcore_default_64k_x_64", 64 << 10, 64, 64 << 10, 64, 4 << 20},
		{"kernel_default_16k_x_128", 16 << 10, 128, 16 << 10, 128, 2 << 20},
		{"custom_small_4k_x_16", 4 << 10, 16, 4 << 10, 16, 64 << 10},
		{"custom_32k_x_32", 32 << 10, 32, 32 << 10, 32, 1 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newBufferPool(tc.inSize, tc.inCount)
			if p.size != tc.wantSize {
				t.Fatalf("p.size = %d, want %d", p.size, tc.wantSize)
			}
			if cap(p.free) != tc.wantCap {
				t.Fatalf("cap(p.free) = %d, want %d", cap(p.free), tc.wantCap)
			}
			if gotBudget := p.size * cap(p.free); gotBudget != tc.wantBudget {
				t.Fatalf("retained budget = %d, want %d", gotBudget, tc.wantBudget)
			}

			// Overflow beyond cap(p.free) never blocks and discards excess on put().
			total := tc.wantCap + 16
			bufs := make([][]byte, total)
			for i := range bufs {
				bufs[i] = p.get()
				if len(bufs[i]) != tc.wantSize {
					t.Fatalf("len(get()) = %d, want %d", len(bufs[i]), tc.wantSize)
				}
				bufs[i][0] = 0x5a
			}
			for _, b := range bufs {
				p.put(b)
			}
			if len(p.free) != tc.wantCap {
				t.Fatalf("len(p.free) = %d, want %d", len(p.free), tc.wantCap)
			}
			reused := p.get()
			if reused[0] != 0 {
				t.Fatalf("pooled buffer was not cleared before reuse: %d", reused[0])
			}
		})
	}
}

func TestRelayCopyM64KWriteCountAndMetering(t *testing.T) {
	const (
		ss2022MaxRecord = 65535
		numRecords      = 64
	)
	makeChunks := func() ([][]byte, []byte) {
		chunks := make([][]byte, numRecords)
		want := make([]byte, 0, numRecords*ss2022MaxRecord)
		for i := range chunks {
			b := make([]byte, ss2022MaxRecord)
			for j := range b {
				b[j] = byte((i*29 + j) & 0xff)
			}
			chunks[i] = b
			want = append(want, b...)
		}
		return chunks, want
	}

	// 1. Legacy 32KiB pool splits each 65535B SS2022 record into 2 writes (128 writes).
	chunks32, want := makeChunks()
	src32 := &recordChunkConn{readChunks: chunks32}
	dst32 := &recordChunkConn{}
	s32 := &Server{
		core: &core{reg: stats.New(nil, nil, nil, nil, time.Now())},
		pool: &bufferPool{size: 32 << 10, free: make(chan []byte, 4)},
	}
	f32, ctx32 := s32.newFlow(context.Background(), "tcp", Address{})
	_, down32 := meters(ctx32)
	if e := s32.copyM(dst32, src32, down32); e != nil {
		t.Fatal(e)
	}

	// 2. Optimized 64KiB pool delivers each 65535B SS2022 record in 1 write (64 writes).
	chunks64, _ := makeChunks()
	src64 := &recordChunkConn{readChunks: chunks64}
	dst64 := &recordChunkConn{}
	s64 := &Server{
		core: &core{reg: stats.New(nil, nil, nil, nil, time.Now())},
		pool: newBufferPool(64<<10, 64),
	}
	f64, ctx64 := s64.newFlow(context.Background(), "tcp", Address{})
	_, down64 := meters(ctx64)
	if e := s64.copyM(dst64, src64, down64); e != nil {
		t.Fatal(e)
	}

	if !bytes.Equal(dst32.written.Bytes(), want) || !bytes.Equal(dst64.written.Bytes(), want) {
		t.Fatal("copied payload mismatch")
	}
	wantBytes := uint64(numRecords * ss2022MaxRecord)
	if f32.down.Load() != wantBytes || f64.down.Load() != wantBytes || s64.reg.Total.Load().Down != wantBytes {
		t.Fatalf("meter mismatch: f32=%d f64=%d total=%d want=%d",
			f32.down.Load(), f64.down.Load(), s64.reg.Total.Load().Down, wantBytes)
	}
	t.Logf("64x65535B copyM: 32KiB pool reads=%d writes=%d; 64KiB pool reads=%d writes=%d",
		src32.reads, dst32.writes, src64.reads, dst64.writes)
	if dst32.writes != numRecords*2 || dst64.writes != numRecords {
		t.Fatalf("write count: 32KiB=%d (want %d), 64KiB=%d (want %d)",
			dst32.writes, numRecords*2, dst64.writes, numRecords)
	}
}

type halfClosePipeConn struct {
	net.Conn
	writeEOF    func()
	closeWrites *atomic.Int32
}

func (c *halfClosePipeConn) CloseWrite() error {
	c.closeWrites.Add(1)
	if c.writeEOF != nil {
		c.writeEOF()
	}
	return nil
}

func newHalfClosePair() (a, b net.Conn, aCloseWrites, bCloseWrites *atomic.Int32) {
	ar, bw := net.Pipe()
	br, aw := net.Pipe()
	aCW := &atomic.Int32{}
	bCW := &atomic.Int32{}
	a = &halfClosePipeConn{
		Conn:        &duplexPipeConn{r: ar, w: aw},
		writeEOF:    func() { _ = aw.Close() },
		closeWrites: aCW,
	}
	b = &halfClosePipeConn{
		Conn:        &duplexPipeConn{r: br, w: bw},
		writeEOF:    func() { _ = bw.Close() },
		closeWrites: bCW,
	}
	return a, b, aCW, bCW
}

type duplexPipeConn struct {
	r net.Conn
	w net.Conn
}

func (c *duplexPipeConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *duplexPipeConn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *duplexPipeConn) Close() error {
	_ = c.r.Close()
	return c.w.Close()
}
func (c *duplexPipeConn) LocalAddr() net.Addr  { return c.r.LocalAddr() }
func (c *duplexPipeConn) RemoteAddr() net.Addr { return c.r.RemoteAddr() }
func (c *duplexPipeConn) SetDeadline(t time.Time) error {
	_ = c.r.SetDeadline(t)
	return c.w.SetDeadline(t)
}
func (c *duplexPipeConn) SetReadDeadline(t time.Time) error  { return c.r.SetReadDeadline(t) }
func (c *duplexPipeConn) SetWriteDeadline(t time.Time) error { return c.w.SetWriteDeadline(t) }

func TestRelaySmallStreamHalfCloseCancelAndIdle(t *testing.T) {
	newTestServer := func() *Server {
		var c Config
		c.Limits.DrainTimeout = Duration(2 * time.Second)
		return &Server{
			core: &core{reg: stats.New(nil, nil, nil, nil, time.Now()), flows: map[uint64]*flow{}},
			cfg:  c,
			pool: newBufferPool(64<<10, 64),
		}
	}

	// 1. Small stream immediate return + half-close + metering.
	t.Run("small_stream_and_half_close", func(t *testing.T) {
		s := newTestServer()
		f, ctx := s.newFlow(context.Background(), "tcp", Address{})
		aPeer, aRelay, _, aRelayCW := newHalfClosePair()
		bRelay, bPeer, bRelayCW, _ := newHalfClosePair()
		defer aPeer.Close()
		defer bPeer.Close()

		done := make(chan error, 1)
		go func() {
			done <- s.relayIdle(ctx, aRelay, bRelay, time.Second)
		}()

		// Send small 5-byte upload chunk without closing; must arrive immediately without waiting for 64KiB.
		start := time.Now()
		if _, e := aPeer.Write([]byte("ping!")); e != nil {
			t.Fatal(e)
		}
		buf := make([]byte, 16)
		if n, e := bPeer.Read(buf); e != nil || string(buf[:n]) != "ping!" {
			t.Fatalf("small upload read: %q %v", buf[:n], e)
		}
		if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
			t.Fatalf("small upload delayed: %v", elapsed)
		}

		// Half-close upload from client side; target side bRelay must receive CloseWrite while download continues.
		_ = closeWrite(aPeer)
		if n, e := bPeer.Read(buf); n != 0 || e != io.EOF {
			t.Fatalf("expected EOF on bPeer after upload half-close: n=%d err=%v", n, e)
		}
		if bRelayCW.Load() != 1 {
			t.Fatalf("bRelay CloseWrite count = %d, want 1", bRelayCW.Load())
		}

		// Target still sends download data after upload half-close.
		if _, e := bPeer.Write([]byte("pong-after-half-close")); e != nil {
			t.Fatal(e)
		}
		_ = closeWrite(bPeer)
		downGot, e := io.ReadAll(aPeer)
		if e != nil || string(downGot) != "pong-after-half-close" {
			t.Fatalf("download after half-close: %q %v", downGot, e)
		}
		if e := <-done; e != nil {
			t.Fatalf("relayIdle returned %v", e)
		}
		if aRelayCW.Load() != 1 {
			t.Fatalf("aRelay CloseWrite count = %d, want 1", aRelayCW.Load())
		}
		if f.up.Load() != 5 || f.down.Load() != uint64(len("pong-after-half-close")) {
			t.Fatalf("meters up=%d down=%d", f.up.Load(), f.down.Load())
		}
	})

	// 2. Context cancellation immediately terminates relay.
	t.Run("cancel", func(t *testing.T) {
		s := newTestServer()
		ctx, cancel := context.WithCancel(context.Background())
		a1, a2 := net.Pipe()
		b1, b2 := net.Pipe()
		defer a1.Close()
		defer b2.Close()

		done := make(chan error, 1)
		go func() {
			done <- s.relayIdle(ctx, a2, b1, time.Second)
		}()
		cancel()
		select {
		case e := <-done:
			if !errors.Is(e, context.Canceled) {
				t.Fatalf("got %v, want context.Canceled", e)
			}
		case <-time.After(time.Second):
			t.Fatal("relayIdle did not exit after cancel")
		}
	})

	// 3. activityStream idle timeout closes both sides when inactive.
	t.Run("idle_timeout", func(t *testing.T) {
		s := newTestServer()
		a1, a2 := net.Pipe()
		b1, b2 := net.Pipe()
		defer a1.Close()
		defer b2.Close()

		start := time.Now()
		_ = s.relayIdle(context.Background(), a2, b1, 50*time.Millisecond)
		if elapsed := time.Since(start); elapsed < 40*time.Millisecond || elapsed > 500*time.Millisecond {
			t.Fatalf("idle timeout elapsed = %v", elapsed)
		}
	})
}

func BenchmarkRelayCopyM64K(b *testing.B) {
	const (
		ss2022MaxRecord = 65535
		numRecords      = 16
	)
	payload := make([]byte, ss2022MaxRecord)
	s := &Server{
		core: &core{reg: stats.New(nil, nil, nil, nil, time.Now())},
		pool: newBufferPool(64<<10, 64),
	}
	_, ctx := s.newFlow(context.Background(), "tcp", Address{})
	_, down := meters(ctx)

	b.SetBytes(int64(numRecords * ss2022MaxRecord))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		chunks := make([][]byte, numRecords)
		for j := range chunks {
			chunks[j] = payload
		}
		src := &recordChunkConn{readChunks: chunks}
		dst := &recordChunkConn{}
		if e := s.copyM(dst, src, down); e != nil {
			b.Fatal(e)
		}
	}
}
