package kernel

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type bufferPool struct {
	size int
	free chan []byte
}

func newBufferPool(size, count int) *bufferPool { return &bufferPool{size, make(chan []byte, count)} }
func (p *bufferPool) get() []byte {
	select {
	case b := <-p.free:
		return b
	default:
		return make([]byte, p.size)
	}
}
func (p *bufferPool) put(b []byte) {
	if cap(b) != p.size {
		return
	}
	clear(b[:cap(b)])
	select {
	case p.free <- b[:p.size]:
	default:
	}
}
func (p *bufferPool) bytes() uint64 {
	if p == nil {
		return 0
	}
	return uint64(len(p.free)) * uint64(p.size)
}
func (p *bufferPool) drain() int {
	if p == nil {
		return 0
	}
	dropped := 0
	for {
		select {
		case <-p.free:
			dropped++
		default:
			return dropped
		}
	}
}

// TrimBuffers drops idle relay buffers cached in the generation pool so long
// idle periods return their spans to the OS.
// ActiveTraffic returns the current number of active logical TCP/UDP flows.
func (s *Server) ActiveTraffic() int64 {
	if s == nil || s.core == nil {
		return 0
	}
	return s.core.logical.Load()
}

func (s *Server) TrimBuffers() int {
	if s == nil {
		return 0
	}
	cur := s.current()
	if cur == nil || cur.pool == nil {
		return 0
	}
	return cur.pool.drain()
}

const (
	smallRelayBufSize      = 8 << 10
	smallRelayDemoteThresh = 4 << 10
)

var smallRelayBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, smallRelayBufSize)
		return &b
	},
}

type readOnly struct{ io.Reader }
type writeOnly struct{ io.Writer }

func (s *Server) copy(dst, src net.Conn) error { return s.copyM(dst, src, meter{}) }

// spliceChunk bounds one kernel splice while statistics are kept, so that
// counters and rates advance during long transfers.
const spliceChunk = 64 << 10

// copyM is copy with payload metering: m counts the bytes written to dst.
func (s *Server) copyM(dst, src net.Conn, m meter) error {
	if !s.cfg.Limits.DisableFastPath {
		rawDst, dstAct := unwrapActivity(dst)
		rawSrc, srcAct := unwrapActivity(src)
		if d, ok := rawDst.(*net.TCPConn); ok {
			if r, ok := rawSrc.(*net.TCPConn); ok {
				act := dstAct
				if act == nil {
					act = srcAct
				}
				if m.f == nil && act == nil {
					_, e := d.ReadFrom(r)
					return e
				}
				for {
					// LimitedReader over a TCPConn preserves Linux kernel splice(2)
					// while advancing flow statistics and idle activity timestamps.
					n, e := d.ReadFrom(&io.LimitedReader{R: r, N: spliceChunk})
					if n > 0 {
						m.add(int(n))
						if act != nil {
							act.Store(time.Now().UnixNano())
						}
					}
					if e != nil || n < spliceChunk {
						return e
					}
				}
			}
		}
	}
	rawSrc := src
	if as, ok := src.(*activityStream); ok {
		rawSrc = as.Conn
	}
	if wt, ok := rawSrc.(io.WriterTo); ok {
		if _, isTCP := rawSrc.(*net.TCPConn); !isTCP {
			w := m.writer(dst)
			if _, ok := w.(interface {
				WriteBuffers(*net.Buffers) (int64, error)
			}); !ok {
				if _, isTCPDst := dst.(*net.TCPConn); isTCPDst {
					w = tcpBuffersWriter{dst}
				}
			}
			_, e := wt.WriteTo(w)
			return e
		}
	}
	if s.pool.size <= smallRelayBufSize {
		b := s.pool.get()
		defer s.pool.put(b)
		_, e := io.CopyBuffer(writeOnly{m.writer(dst)}, readOnly{src}, b)
		return e
	}
	return copyAdaptive(dst, src, m, s.pool)
}
func closeWrite(c net.Conn) error {
	if v, ok := c.(interface{ CloseWrite() error }); ok {
		err := v.CloseWrite()
		if errors.Is(err, errors.ErrUnsupported) {
			return nil
		}
		return err
	}
	return nil
}

func unwrapActivity(c net.Conn) (net.Conn, *atomic.Int64) {
	if a, ok := c.(*activityStream); ok {
		return a.Conn, a.last
	}
	return c, nil
}

type activityStream struct {
	net.Conn
	last *atomic.Int64
}

func (c *activityStream) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, e
}
func (c *activityStream) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, e
}
func (c *activityStream) WriteBuffers(b *net.Buffers) (int64, error) {
	n, e := b.WriteTo(c.Conn)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, e
}
func (c *activityStream) CloseWrite() error { return closeWrite(c.Conn) }

type tcpBuffersWriter struct {
	io.Writer
}

func (w tcpBuffersWriter) WriteBuffers(b *net.Buffers) (int64, error) {
	return b.WriteTo(w.Writer)
}
func (s *Server) relay(ctx context.Context, a, b net.Conn) error {
	return s.relayIdle(ctx, a, b, s.cfg.Limits.TCPIdle.value())
}
func (s *Server) relayIdle(ctx context.Context, a, b net.Conn, idle time.Duration) (result error) {
	observedStart := time.Now()
	defer func() {
		if !quietFailure(result) {
			s.runtimeFailure(ctx, "relay", "unknown", result, observedStart)
		}
	}()
	if idle > 0 {
		var last atomic.Int64
		last.Store(time.Now().UnixNano())
		stop := make(chan struct{})
		exited := make(chan struct{})
		defer func() { close(stop); <-exited }()
		originalA, originalB := a, b
		go func() {
			defer close(exited)
			prevProgress, hasProgress := tcpPairProgress(originalA, originalB)
			timer := time.NewTimer(idle)
			defer timer.Stop()
			for {
				select {
				case <-stop:
					return
				case <-timer.C:
					remaining := idle - time.Since(time.Unix(0, last.Load()))
					if remaining <= 0 {
						if hasProgress {
							if cur, ok := tcpPairProgress(originalA, originalB); ok && cur != prevProgress {
								prevProgress = cur
								last.Store(time.Now().UnixNano())
								timer.Reset(idle)
								continue
							}
						}
						originalA.Close()
						originalB.Close()
						return
					}
					timer.Reset(remaining)
				}
			}
		}()
		a = &activityStream{a, &last}
		b = &activityStream{b, &last}
	}

	done := make(chan error, 2)
	up, down := meters(ctx)
	transfer := func(dst, src net.Conn, m meter) {
		e := s.copyM(dst, src, m)
		if e == nil {
			e = closeWrite(dst)
		}
		done <- e
	}
	// a is the client side, b the target: b->a is download, a->b upload.
	go transfer(a, b, down)
	go transfer(b, a, up)
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		a.Close()
		b.Close()
		<-done
		<-done
		return ctx.Err()
	}
	if err != nil {
		a.Close()
		b.Close()
	} else {
		deadline := time.Now().Add(s.cfg.Limits.DrainTimeout.value())
		a.SetDeadline(deadline)
		b.SetDeadline(deadline)
	}
	select {
	case e := <-done:
		if err == nil && !quietFailure(e) {
			err = e
		}
	case <-ctx.Done():
		a.Close()
		b.Close()
		<-done
		err = ctx.Err()
	}
	return err
}

// copyAdaptive starts with the full pool buffer (preserving single-write bulk
// framing such as 64 KiB SS2022 records) and demotes idle/small-frame streams
// (<= 4 KiB read) to an 8 KiB pooled buffer while blocked in Read, promoting
// immediately back to the full buffer as soon as a read fills 8 KiB.
func copyAdaptive(dst, src net.Conn, m meter, pool *bufferPool) error {
	w := m.writer(dst)
	large := pool.get()
	var smallPtr *[]byte
	cur := large
	defer func() {
		if large != nil {
			pool.put(large)
		}
		if smallPtr != nil {
			clear(*smallPtr)
			smallRelayBufPool.Put(smallPtr)
		}
	}()
	for {
		nr, er := src.Read(cur)
		if nr > 0 {
			nw, ew := w.Write(cur[:nr])
			if ew != nil {
				return ew
			}
			if nr != nw {
				return io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return nil
			}
			return er
		}
		if large != nil && nr <= smallRelayDemoteThresh {
			pool.put(large)
			large = nil
			smallPtr = smallRelayBufPool.Get().(*[]byte)
			cur = *smallPtr
		} else if large == nil && nr == len(cur) {
			clear(*smallPtr)
			smallRelayBufPool.Put(smallPtr)
			smallPtr = nil
			large = pool.get()
			cur = large
		}
	}
}
