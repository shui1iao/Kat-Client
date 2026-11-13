package anytls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const (
	// Received-but-unread bytes buffered per stream. Beyond it the session
	// reader stops reading the TLS connection until the application reads:
	// plain TCP backpressure on the stream's own (exclusive) session.
	maxStreamBuffer = 1024 << 10
	// Align per-request write chunk with the 64 KiB relay buffer so a 65536-byte
	// write is framed in a single writeData request instead of splitting into
	// 65535 + 1 lockstep requests; each PSH frame remains bounded by maxFrame (65535).
	writeChunk = 64 << 10

	// Minimum PSH payload size eligible for the bounded receive buffer pool.
	// Smaller frames use exact-size allocations so tiny frames never pin larger
	// backing arrays while queued under maxStreamBuffer.
	minPooledFrame = 128
	// Hard upper bounds on pooled receive buffers across the process.
	maxRecvPoolBytes = 2 << 20
	maxRecvClassSlot = 32
)

var recvClassCaps = [...]int{
	512,
	2048,
	8192,
	16384,
	32768,
	maxFrame,
}

var recvPool struct {
	mu       sync.Mutex
	classes  [len(recvClassCaps)][][]byte
	lastUsed [len(recvClassCaps)]uint64
	seq      uint64
	bytes    int
}

func recvClassIndex(n int) int {
	if n < minPooledFrame || n > maxFrame {
		return -1
	}
	for i, c := range recvClassCaps {
		if n <= c {
			return i
		}
	}
	return -1
}

func acquireRecvBuf(n int) []byte {
	idx := recvClassIndex(n)
	if idx < 0 {
		return make([]byte, n)
	}
	c := recvClassCaps[idx]
	recvPool.mu.Lock()
	recvPool.seq++
	recvPool.lastUsed[idx] = recvPool.seq
	slots := recvPool.classes[idx]
	if last := len(slots) - 1; last >= 0 {
		b := slots[last]
		slots[last] = nil
		recvPool.classes[idx] = slots[:last]
		recvPool.bytes -= c
		recvPool.mu.Unlock()
		return b[:n]
	}
	recvPool.mu.Unlock()
	return make([]byte, n, c)
}

func releaseRecvBuf(b []byte) {
	idx := recvClassIndex(len(b))
	if idx < 0 || cap(b) != recvClassCaps[idx] {
		return
	}
	c := recvClassCaps[idx]
	b = b[:c]
	recvPool.mu.Lock()
	recvPool.seq++
	recvPool.lastUsed[idx] = recvPool.seq
	if len(recvPool.classes[idx]) < maxRecvClassSlot {
		for recvPool.bytes+c > maxRecvPoolBytes {
			victim := -1
			for i := range recvPool.classes {
				if i == idx || len(recvPool.classes[i]) == 0 {
					continue
				}
				if victim < 0 || recvPool.lastUsed[i] < recvPool.lastUsed[victim] {
					victim = i
				}
			}
			if victim < 0 {
				break
			}
			vslots := recvPool.classes[victim]
			vcap := recvClassCaps[victim]
			for len(vslots) > 0 && recvPool.bytes+c > maxRecvPoolBytes {
				last := len(vslots) - 1
				vslots[last] = nil
				vslots = vslots[:last]
				recvPool.bytes -= vcap
			}
			recvPool.classes[victim] = vslots
		}
		if recvPool.bytes+c <= maxRecvPoolBytes {
			recvPool.classes[idx] = append(recvPool.classes[idx], b)
			recvPool.bytes += c
		}
	}
	recvPool.mu.Unlock()
}

var errClosedByPeer = errors.New("anytls: stream closed by server")

// stream is one logical AnyTLS stream; it is the net.Conn returned by DialTCP.
// FIN closes the whole logical stream in both directions (the protocol has no
// half-close), so no CloseWrite is offered. Deadlines apply to this stream only.
type stream struct {
	s      *session
	id     uint32
	sentAt int64

	rmu, wmu sync.Mutex // serialize Read / Write callers
	wbuf     []byte

	mu       sync.Mutex
	in       [][]byte
	inHead   int
	off      int
	inBytes  int
	pooled   bool
	rerr     error // terminal read state (io.EOF after FIN, or failure)
	werr     error // terminal write state
	acked    bool
	synErr   error
	closed   bool // local Close
	detached bool // removed from the session, slot released

	rch     chan struct{} // capacity 1: data/state for readers and await
	space   chan struct{} // capacity 1: buffer drained
	closing chan struct{} // closed by local Close

	rd, wd deadline
}

func newStream(s *session, id uint32) *stream {
	st := &stream{s: s, id: id, rch: make(chan struct{}, 1), space: make(chan struct{}, 1), closing: make(chan struct{})}
	st.rd.init()
	st.wd.init()
	return st
}

func signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// await waits for the server's verdict on a new stream. TCP needs the v2
// SYNACK; UoT only needs proof the session is authenticated (server settings),
// because servers may delay SYNACK until the UoT request arrives.
func (st *stream) awaitWrite(ctx context.Context, req *writeReq) error {
	s := st.s
	select {
	case e := <-req.done:
		if e != nil {
			return e
		}
	case <-s.done:
		return s.cause()
	case <-ctx.Done():
		if !s.cancel(req) {
			select {
			case e := <-req.done:
				if e != nil {
					return e
				}
			case <-s.done:
				return s.cause()
			}
		}
		return fmt.Errorf("anytls: waiting for server: %w", ctx.Err())
	}
	return st.await(ctx, false)
}

func (st *stream) await(ctx context.Context, needAck bool) error {
	s := st.s
	ver := s.ver
	for {
		st.mu.Lock()
		acked, synErr, rerr := st.acked, st.synErr, st.rerr
		st.mu.Unlock()
		if synErr != nil {
			return synErr
		}
		if acked {
			// Accepted; data already delivered stays readable even if the
			// session failed right after.
			return nil
		}
		if rerr != nil && rerr != io.EOF {
			return rerr
		}
		if rerr == io.EOF {
			return errClosedByPeer
		}
		if v, known := s.version(); known && (!needAck || v < 2) {
			return nil
		}
		if needAck {
			if _, known := s.version(); known {
				ver = nil // keep waiting for SYNACK only
			}
		}
		select {
		case <-st.rch:
		case <-ver:
		case <-ctx.Done():
			// Nothing at all came back since this stream was sent: treat the
			// session as dead so it is not reused.
			if s.lastRecv.Load() < st.sentAt {
				s.fail(errNoResponse)
			}
			return fmt.Errorf("anytls: waiting for server: %w", ctx.Err())
		}
	}
}

func (st *stream) acknowledge(msg []byte) {
	st.mu.Lock()
	if len(msg) == 0 {
		st.acked = true
		st.mu.Unlock()
		signal(st.rch)
		return
	}
	st.synErr = fmt.Errorf("anytls: server refused stream: %s", printable(msg))
	if st.rerr == nil {
		st.rerr = st.synErr
	}
	if st.werr == nil {
		st.werr = st.synErr
	}
	st.mu.Unlock()
	signal(st.rch)
	st.detach(false)
}

// push hands received data to the reader. When the buffer is full the session
// reader waits for the application (or stream close / session failure); the
// session is exclusive to this stream, so no other stream is held up and
// memory stays bounded by maxStreamBuffer plus one frame.
func (st *stream) push(b []byte) {
	st.enqueueIn(b, false)
}

func (st *stream) pushPooled(b []byte) {
	st.enqueueIn(b, true)
}

// waitSpace blocks until the stream's receive window can accept a frame of n
// bytes, the stream stops accepting incoming frames, or the session fails.
func (st *stream) waitSpace(n int) (ok bool, sessionDone bool) {
	for {
		st.mu.Lock()
		closed := st.closed || st.rerr != nil
		ready := !closed && (st.inBytes == 0 || st.inBytes+n <= maxStreamBuffer)
		st.mu.Unlock()
		if closed {
			select {
			case <-st.s.done:
				return false, true
			default:
				return false, false
			}
		}
		if ready {
			return true, false
		}
		select {
		case <-st.space:
		case <-st.closing:
		case <-st.s.done:
			return false, true
		}
	}
}

func (st *stream) enqueueIn(b []byte, pooled bool) {
	for {
		st.mu.Lock()
		if st.closed || st.rerr != nil {
			st.mu.Unlock()
			if pooled {
				releaseRecvBuf(b)
			}
			return
		}
		if st.inBytes == 0 || st.inBytes+len(b) <= maxStreamBuffer {
			if pooled {
				st.pooled = true
			}
			if st.inHead > 0 && st.inHead == len(st.in) {
				st.in = st.in[:0]
				st.inHead = 0
			} else if st.inHead >= 64 && st.inHead*2 >= len(st.in) {
				n := copy(st.in, st.in[st.inHead:])
				clear(st.in[n:])
				st.in = st.in[:n]
				st.inHead = 0
			}
			st.in = append(st.in, b)
			st.inBytes += len(b)
			st.mu.Unlock()
			signal(st.rch)
			return
		}
		st.mu.Unlock()
		select {
		case <-st.space:
		case <-st.closing:
		case <-st.s.done:
			if pooled {
				releaseRecvBuf(b)
			}
			return
		}
	}
}

// remoteClose handles the server's FIN: buffered data stays readable, then EOF.
func (st *stream) remoteClose(err error) {
	st.mu.Lock()
	if st.rerr == nil {
		st.rerr = err
	}
	if st.werr == nil {
		st.werr = errClosedByPeer
	}
	if st.inHead == len(st.in) {
		st.in = nil
		st.inHead = 0
	}
	signal(st.space)
	st.mu.Unlock()
	signal(st.rch)
	st.detach(false)
}

// abort is session failure: every operation errors (after buffered data).
func (st *stream) abort(err error) {
	st.mu.Lock()
	if st.rerr == nil || st.rerr == io.EOF {
		st.rerr = err
	}
	if st.werr == nil || st.werr == errClosedByPeer {
		st.werr = err
	}
	if st.inHead == len(st.in) {
		st.in = nil
		st.inHead = 0
	}
	signal(st.space)
	st.mu.Unlock()
	signal(st.rch)
	st.detach(false)
}

// detach removes the stream from its session once, optionally sending FIN,
// and returns its pool slot.
func (st *stream) detach(sendFIN bool) {
	st.mu.Lock()
	if st.detached {
		st.mu.Unlock()
		return
	}
	st.detached = true
	st.mu.Unlock()
	s := st.s
	s.detachStream(st.id)
	if sendFIN {
		_ = s.enqueue(&writeReq{wire: appendFrame(nil, cmdFIN, st.id, nil), done: make(chan error, 1)})
	}
	s.o.release(s)
}

func (st *stream) Read(p []byte) (int, error) {
	st.rmu.Lock()
	defer st.rmu.Unlock()
	for {
		st.mu.Lock()
		if st.closed {
			st.mu.Unlock()
			return 0, net.ErrClosed
		}
		if st.rd.expired() {
			st.mu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}
		if st.inHead < len(st.in) {
			if len(p) == 0 {
				st.mu.Unlock()
				return 0, nil
			}
			total := 0
			drained := false
			for len(p) > 0 && st.inHead < len(st.in) {
				b := st.in[st.inHead]
				if total > 0 && st.off == 0 && len(p) < len(b) {
					break
				}
				n := copy(p, b[st.off:])
				total += n
				p = p[n:]
				st.off += n
				if st.off == len(b) {
					st.in[st.inHead] = nil
					if st.pooled {
						releaseRecvBuf(b)
					}
					st.inHead++
					st.off = 0
					st.inBytes -= len(b)
					drained = true
				}
			}
			if st.inHead == len(st.in) {
				if st.rerr != nil {
					st.in = nil
				} else {
					st.in = st.in[:0]
				}
				st.inHead = 0
			}
			if drained {
				signal(st.space)
			}
			st.mu.Unlock()
			return total, nil
		}
		if st.rerr != nil {
			st.in = nil
			st.inHead = 0
			e := st.rerr
			st.mu.Unlock()
			return 0, e
		}
		st.mu.Unlock()
		if len(p) == 0 {
			return 0, nil
		}
		select {
		case <-st.rch:
		case <-st.rd.done():
		case <-st.closing:
		}
	}
}

func (st *stream) Write(p []byte) (int, error) {
	st.wmu.Lock()
	defer st.wmu.Unlock()
	total := 0
	for len(p) > 0 {
		n := min(len(p), writeChunk)
		if e := st.writeData(p[:n]); e != nil {
			return total, e
		}
		total += n
		p = p[n:]
	}
	if total == 0 {
		if e := st.writeState(); e != nil {
			return 0, e
		}
	}
	return total, nil
}

func (st *stream) writeState() error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.closed {
		return net.ErrClosed
	}
	if st.werr != nil {
		return st.werr
	}
	if st.wd.expired() {
		return os.ErrDeadlineExceeded
	}
	return nil
}

// writeData sends data as PSH frames in one writer request: either all of it
// reaches the writer or (on deadline/close before pickup) none of it does.
func (st *stream) writeData(data []byte) error {
	if e := st.writeState(); e != nil {
		return e
	}
	s := st.s
	frames := (len(data) + maxFrame - 1) / maxFrame
	need := len(data) + headerSize*max(frames, 1)
	if cap(st.wbuf) < need {
		st.wbuf = make([]byte, 0, need)
	}
	wire := st.wbuf[:0]
	if len(data) == 64<<10 {
		// Split an exact 64 KiB relay write into two 32 KiB PSH frames rather
		// than 65535 + 1 so neither frame is a 1-byte micro-frame while total
		// wire overhead (2 * 7B headers) is identical.
		const half = 32 << 10
		wire = appendFrame(wire, cmdPSH, st.id, data[:half])
		wire = appendFrame(wire, cmdPSH, st.id, data[half:])
	} else {
		for len(data) > 0 {
			n := min(len(data), maxFrame)
			wire = appendFrame(wire, cmdPSH, st.id, data[:n])
			data = data[n:]
		}
	}
	if !st.wd.active() {
		ok, err := s.tryAcquireInlineWrite()
		if err != nil {
			return err
		}
		if ok {
			if e := st.writeState(); e != nil {
				s.releaseInlineWrite()
				return e
			}
			if st.wd.active() {
				s.releaseInlineWrite()
			} else {
				return s.writeInline(wire)
			}
		}
	}
	req := &writeReq{wire: wire, done: make(chan error, 1)}
	if e := s.enqueue(req); e != nil {
		return e
	}
	var stop error
	select {
	case e := <-req.done:
		return e
	case <-s.done:
		return s.cause()
	case <-st.wd.done():
		stop = os.ErrDeadlineExceeded
	case <-st.closing:
		stop = net.ErrClosed
	}
	if s.cancel(req) {
		return stop
	}
	// Already on the wire path: report the real outcome.
	select {
	case e := <-req.done:
		return e
	case <-s.done:
		return s.cause()
	}
}

// Close closes the logical stream (FIN) and never the shared session.
func (st *stream) Close() error {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return nil
	}
	st.closed = true
	in := st.in
	head := st.inHead
	pooled := st.pooled
	st.in = nil
	st.inHead = 0
	st.off = 0
	st.inBytes = 0
	close(st.closing)
	st.mu.Unlock()
	if pooled {
		for i := head; i < len(in); i++ {
			if in[i] != nil {
				releaseRecvBuf(in[i])
				in[i] = nil
			}
		}
	}
	signal(st.space)
	st.rd.stop()
	st.wd.stop()
	st.detach(true)
	return nil
}

func (st *stream) LocalAddr() net.Addr  { return st.s.conn.LocalAddr() }
func (st *stream) RemoteAddr() net.Addr { return st.s.conn.RemoteAddr() }
func (st *stream) SetDeadline(t time.Time) error {
	st.rd.set(t)
	st.wd.set(t)
	return nil
}
func (st *stream) SetReadDeadline(t time.Time) error  { st.rd.set(t); return nil }
func (st *stream) SetWriteDeadline(t time.Time) error { st.wd.set(t); return nil }

var _ net.Conn = (*stream)(nil)

// deadline is a resettable timer-backed channel closed when the deadline passes.
type deadline struct {
	mu      sync.Mutex
	ch      chan struct{}
	timer   *time.Timer
	gen     uint64
	hasSet  bool
	isEnded bool
}

func (d *deadline) init() { d.ch = make(chan struct{}) }

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.gen++
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	if d.isEnded {
		d.ch = make(chan struct{})
		d.isEnded = false
	}
	if t.IsZero() {
		d.hasSet = false
		return
	}
	d.hasSet = true
	wait := time.Until(t)
	if wait <= 0 {
		close(d.ch)
		d.isEnded = true
		return
	}
	gen := d.gen
	d.timer = time.AfterFunc(wait, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.gen == gen && !d.isEnded {
			close(d.ch)
			d.isEnded = true
		}
	})
}

func (d *deadline) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.gen++
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
}

func (d *deadline) done() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ch
}

func (d *deadline) expired() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.isEnded
}

func (d *deadline) active() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hasSet
}
