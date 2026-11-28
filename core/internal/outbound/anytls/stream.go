package anytls

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// Received-but-unread bytes buffered per stream. Beyond it the session
	// reader stops reading the TLS connection until the application reads:
	// plain TCP backpressure on the stream's own (exclusive) session.
	maxStreamBuffer = 1024 << 10
	tlsMaxPlaintext = 16384
	// Align large PSH frames with 2 full TLS 1.3 records (2*16384 - 7 = 32761) so
	// each frame + 7B header is 32768B (zero 7-byte TLS tail record), and align
	// writeChunk (2 * 32761 = 65522) so 2 frames + headers = 65536B (4 full TLS records).
	tlsAlignedFrame = 2*tlsMaxPlaintext - headerSize
	writeChunk      = 2 * tlsAlignedFrame

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

func releaseRecvBufLocked(b []byte) {
	idx := recvClassIndex(len(b))
	if idx < 0 || cap(b) != recvClassCaps[idx] {
		return
	}
	c := recvClassCaps[idx]
	b = b[:c]
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
}

func releaseRecvBuf(b []byte) {
	idx := recvClassIndex(len(b))
	if idx < 0 || cap(b) != recvClassCaps[idx] {
		return
	}
	recvPool.mu.Lock()
	releaseRecvBufLocked(b)
	recvPool.mu.Unlock()
}

func releaseRecvBufs(bufs [][]byte) {
	if len(bufs) == 0 {
		return
	}
	recvPool.mu.Lock()
	for _, b := range bufs {
		releaseRecvBufLocked(b)
	}
	recvPool.mu.Unlock()
}

var errClosedByPeer = errors.New("anytls: stream closed by server")

// stream is one logical AnyTLS stream; it is the net.Conn returned by DialTCP.
// FIN closes the whole logical stream in both directions (the protocol has no
// half-close), so no CloseWrite is offered. Deadlines apply to this stream only.
type directSink struct {
	w       io.Writer
	written int64
	err     error
	done    chan struct{}
}

type stream struct {
	s      *session
	id     uint32
	sentAt int64

	rmu, wmu sync.Mutex // serialize Read / Write callers
	wbuf     []byte
	wvec     [16][]byte
	wbufs    net.Buffers

	freeMu   sync.Mutex
	freeBufs [][]byte

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

	inBytesAtomic atomic.Int32
	stopped       atomic.Bool // true once closed or rerr != nil

	sink       *directSink // non-nil while WriteTo is directly serviced by recvLoop
	sinkActive bool        // true while recvLoop is inside sink.w.Write
	sinkIdle   chan struct{}
	dsink      directSink
	dsinkDone  chan struct{}

	wreq     writeReq
	wdone    chan error
	wreqBusy bool

	rch        chan struct{} // capacity 1: data/state for readers and await
	space      chan struct{} // capacity 1: buffer drained
	closing    chan struct{} // closed by local Close
	wabort     chan struct{} // closed on async SYNACK refusal to wake blocked writes
	wabortOnce sync.Once

	rd, wd deadline
}

func newStream(s *session, id uint32) *stream {
	activeStreams.Add(1)
	st := &stream{
		s:         s,
		id:        id,
		dsinkDone: make(chan struct{}, 1),
		wdone:     make(chan error, 1),
		rch:       make(chan struct{}, 1),
		space:     make(chan struct{}, 1),
		closing:   make(chan struct{}),
		wabort:    make(chan struct{}),
	}
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

// On reuse, the previous stream already authenticated the session. Flush this
// stream's SYN/target before evaluating its protocol-specific verdict.
// awaitWriteOnly flushes SYN/target onto a reused carrier without waiting for
// the remote SYNACK round-trip, allowing dead pooled sessions to be detected
// and retried locally while keeping stream open 0-RTT on healthy carriers.
func (st *stream) awaitWriteOnly(ctx context.Context, req *writeReq) error {
	s := st.s
	select {
	case e := <-req.done:
		return e
	case <-s.done:
		return s.cause()
	case <-ctx.Done():
		s.cancel(req)
		return fmt.Errorf("anytls: waiting for server: %w", ctx.Err())
	}
}

func (st *stream) awaitWrite(ctx context.Context, req *writeReq, needAck bool) error {
	if e := st.awaitWriteOnly(ctx, req); e != nil {
		return e
	}
	return st.await(ctx, needAck)
}

// await waits for the server's verdict on a new stream. TCP needs the v2
// SYNACK; UoT only needs proof the session is authenticated (server settings),
// because servers may delay SYNACK until the UoT request arrives.
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
		if v, known := s.version(); known {
			if !needAck || v < 2 {
				return nil
			}
			ver = nil // v2 TCP: only this stream's SYNACK is sufficient.
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

func (st *stream) acknowledge(accepted bool) {
	st.mu.Lock()
	if accepted {
		st.acked = true
		st.mu.Unlock()
		signal(st.rch)
		return
	}
	st.synErr = errStreamRefused
	if st.rerr == nil {
		st.rerr = st.synErr
	}
	if st.werr == nil {
		st.werr = st.synErr
	}
	st.stopped.Store(true)
	st.wakeDirectSinkLocked()
	st.mu.Unlock()
	st.wabortOnce.Do(func() { close(st.wabort) })
	signal(st.rch)
	signal(st.space)
	st.detach(false)
}

// push hands received data to the reader. When the buffer is full the session
// reader waits for the application (or stream close / session failure); the
// session is exclusive to this stream, so no other stream is held up and
// memory stays bounded by maxStreamBuffer plus one frame.
const maxStreamFreeBufs = 8

func (st *stream) acquireBuf(n int) []byte {
	idx := recvClassIndex(n)
	if idx < 0 {
		return make([]byte, n)
	}
	c := recvClassCaps[idx]
	st.freeMu.Lock()
	for i := len(st.freeBufs) - 1; i >= 0; i-- {
		if cap(st.freeBufs[i]) == c {
			b := st.freeBufs[i]
			last := len(st.freeBufs) - 1
			st.freeBufs[i] = st.freeBufs[last]
			st.freeBufs[last] = nil
			st.freeBufs = st.freeBufs[:last]
			st.freeMu.Unlock()
			return b[:n]
		}
	}
	st.freeMu.Unlock()
	return acquireRecvBuf(n)
}

func (st *stream) releaseBuf(b []byte) {
	idx := recvClassIndex(len(b))
	if idx < 0 || cap(b) != recvClassCaps[idx] {
		return
	}
	st.freeMu.Lock()
	if !st.stopped.Load() && len(st.freeBufs) < maxStreamFreeBufs {
		st.freeBufs = append(st.freeBufs, b[:cap(b)])
		st.freeMu.Unlock()
		return
	}
	st.freeMu.Unlock()
	releaseRecvBuf(b)
}

func (st *stream) releaseBufs(bufs [][]byte) {
	if len(bufs) == 0 {
		return
	}
	var overflow [16][]byte
	nOver := 0
	st.freeMu.Lock()
	canCache := !st.stopped.Load()
	for _, b := range bufs {
		idx := recvClassIndex(len(b))
		if idx < 0 || cap(b) != recvClassCaps[idx] {
			continue
		}
		if canCache && len(st.freeBufs) < maxStreamFreeBufs {
			st.freeBufs = append(st.freeBufs, b[:cap(b)])
		} else if nOver < len(overflow) {
			overflow[nOver] = b
			nOver++
		} else {
			st.freeMu.Unlock()
			releaseRecvBuf(b)
			st.freeMu.Lock()
		}
	}
	st.freeMu.Unlock()
	if nOver > 0 {
		releaseRecvBufs(overflow[:nOver])
	}
}

func (st *stream) drainFreeBufs() {
	st.freeMu.Lock()
	bufs := st.freeBufs
	st.freeBufs = nil
	st.freeMu.Unlock()
	if len(bufs) > 0 {
		releaseRecvBufs(bufs)
	}
}

func (st *stream) push(b []byte) {
	st.enqueueIn(b, false)
}

func (st *stream) pushPooled(b []byte) {
	st.enqueueIn(b, true)
}

// waitSpace blocks until the stream's receive window can accept a frame of n
// bytes, the stream stops accepting incoming frames, or the session fails.
func (st *stream) waitSpace(n int) (ok bool, sessionDone bool) {
	if !st.stopped.Load() {
		if cur := int(st.inBytesAtomic.Load()); cur == 0 || cur+n <= maxStreamBuffer {
			return true, false
		}
	}
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
			st.inBytesAtomic.Store(int32(st.inBytes))
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
	st.stopped.Store(true)
	if st.inHead == len(st.in) {
		st.in = nil
		st.inHead = 0
	}
	st.wakeDirectSinkLocked()
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
	st.stopped.Store(true)
	if st.inHead == len(st.in) {
		st.in = nil
		st.inHead = 0
	}
	st.wakeDirectSinkLocked()
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
	activeStreams.Add(-1)
	s := st.s
	s.detachStream(st.id)
	if sendFIN {
		if err := s.enqueue(&writeReq{wire: appendFrame(nil, cmdFIN, st.id, nil), done: make(chan error, 1)}); errors.Is(err, errQueueFull) {
			// A FIN cannot be dropped or reordered. Retire this carrier instead
			// of making Close wait behind a stalled writer.
			s.fail(err)
		}
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
			// Pop complete chunks under st.mu so copy + recvPool release happen
			// outside the stream mutex, avoiding lock nesting and contention.
			var popBuf [16][]byte
			var popOff [16]int
			nPop := 0
			rem := len(p)
			drained := false
			pooled := st.pooled
			partialCopied := 0
			for rem > 0 && st.inHead < len(st.in) && nPop < len(popBuf) {
				b := st.in[st.inHead]
				avail := len(b) - st.off
				if nPop > 0 && st.off == 0 && rem < avail {
					break
				}
				if rem >= avail {
					popBuf[nPop] = b
					popOff[nPop] = st.off
					nPop++
					rem -= avail
					st.in[st.inHead] = nil
					st.inHead++
					st.off = 0
					st.inBytes -= len(b)
					drained = true
				} else {
					// Copy partial chunk under st.mu so Close cannot recycle it concurrently.
					// Destination offset is len(p)-rem (all popped chunks go before it).
					dstOff := len(p) - rem
					n := copy(p[dstOff:], b[st.off:st.off+rem])
					st.off += n
					partialCopied = n
					rem -= n
					break
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
				st.inBytesAtomic.Store(int32(st.inBytes))
			}
			st.mu.Unlock()
			total := 0
			for i := 0; i < nPop; i++ {
				n := copy(p, popBuf[i][popOff[i]:])
				total += n
				p = p[n:]
			}
			total += partialCopied
			if pooled && nPop > 0 {
				releaseRecvBufs(popBuf[:nPop])
			}
			if drained {
				signal(st.space)
			}
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

func (st *stream) acquireDirectSink() *directSink {
	st.mu.Lock()
	if st.closed || st.rerr != nil || st.sink == nil || st.inHead < len(st.in) {
		st.mu.Unlock()
		return nil
	}
	st.sinkActive = true
	sk := st.sink
	st.mu.Unlock()
	return sk
}

func (st *stream) releaseDirectSink(writeErr error) {
	st.mu.Lock()
	sk := st.sink
	st.sinkActive = false
	if st.sinkIdle != nil {
		close(st.sinkIdle)
		st.sinkIdle = nil
	}
	if writeErr != nil && sk != nil {
		sk.err = writeErr
		st.sink = nil
		signal(sk.done)
	}
	st.mu.Unlock()
}

func (st *stream) wakeDirectSinkLocked() {
	if st.sink != nil {
		sk := st.sink
		st.sink = nil
		signal(sk.done)
	}
}

type buffersWriter interface {
	WriteBuffers(*net.Buffers) (int64, error)
}

func (st *stream) WriteTo(w io.Writer) (int64, error) {
	st.rmu.Lock()
	defer st.rmu.Unlock()
	bw, hasBW := w.(buffersWriter)
	var total int64
	for {
		st.mu.Lock()
		if st.closed {
			st.mu.Unlock()
			return total, net.ErrClosed
		}
		if st.rd.expired() {
			st.mu.Unlock()
			return total, os.ErrDeadlineExceeded
		}
		if st.inHead < len(st.in) {
			var popBuf [16][]byte
			var popOff [16]int
			nPop := 0
			pooled := st.pooled
			for st.inHead < len(st.in) && nPop < len(popBuf) {
				b := st.in[st.inHead]
				popBuf[nPop] = b
				popOff[nPop] = st.off
				nPop++
				st.in[st.inHead] = nil
				st.inHead++
				st.off = 0
				st.inBytes -= len(b)
			}
			if st.inHead == len(st.in) {
				if st.rerr != nil {
					st.in = nil
				} else {
					st.in = st.in[:0]
				}
				st.inHead = 0
			}
			st.inBytesAtomic.Store(int32(st.inBytes))
			st.mu.Unlock()

			var writeErr error
			if nPop == 1 {
				chunk := popBuf[0][popOff[0]:]
				for len(chunk) > 0 {
					nw, ew := w.Write(chunk)
					total += int64(nw)
					chunk = chunk[nw:]
					if ew != nil {
						writeErr = ew
						break
					}
					if nw == 0 {
						writeErr = io.ErrShortWrite
						break
					}
				}
			} else if hasBW {
				for i := 0; i < nPop; i++ {
					st.wvec[i] = popBuf[i][popOff[i]:]
				}
				st.wbufs = net.Buffers(st.wvec[:nPop])
				for len(st.wbufs) > 0 {
					nw, ew := bw.WriteBuffers(&st.wbufs)
					total += nw
					if ew != nil {
						writeErr = ew
						break
					}
				}
				for i := 0; i < nPop; i++ {
					st.wvec[i] = nil
				}
				st.wbufs = nil
			} else {
				for i := 0; i < nPop && writeErr == nil; i++ {
					chunk := popBuf[i][popOff[i]:]
					for len(chunk) > 0 {
						nw, ew := w.Write(chunk)
						total += int64(nw)
						chunk = chunk[nw:]
						if ew != nil {
							writeErr = ew
							break
						}
						if nw == 0 {
							writeErr = io.ErrShortWrite
							break
						}
					}
				}
			}
			if pooled {
				st.releaseBufs(popBuf[:nPop])
			}
			signal(st.space)
			if writeErr != nil {
				return total, writeErr
			}
			continue
		}
		if st.rerr != nil {
			st.in = nil
			st.inHead = 0
			e := st.rerr
			st.mu.Unlock()
			if e == io.EOF {
				return total, nil
			}
			return total, e
		}
		if st.s.rawWrite != nil && !st.rd.active() {
			select {
			case <-st.dsinkDone:
			default:
			}
			st.dsink = directSink{w: w, done: st.dsinkDone}
			sk := &st.dsink
			st.sink = sk
			st.mu.Unlock()
			select {
			case <-sk.done:
			case <-st.rd.done():
			case <-st.closing:
			}
			st.mu.Lock()
			if st.sink == sk {
				st.sink = nil
			}
			for st.sinkActive {
				if st.sinkIdle == nil {
					st.sinkIdle = make(chan struct{})
				}
				ch := st.sinkIdle
				st.mu.Unlock()
				<-ch
				st.mu.Lock()
			}
			total += sk.written
			writeErr := sk.err
			sk.w = nil
			st.mu.Unlock()
			if writeErr != nil {
				return total, writeErr
			}
			continue
		}
		st.mu.Unlock()
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
	if st.s.failed.Load() {
		return st.s.cause()
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
	frames := (len(data) + tlsAlignedFrame - 1) / tlsAlignedFrame
	need := len(data) + headerSize*max(frames, 1)
	if cap(st.wbuf) < need {
		st.wbuf = make([]byte, 0, need)
	}
	wire := st.wbuf[:0]
	for len(data) > 0 {
		n := min(len(data), tlsAlignedFrame)
		wire = appendFrame(wire, cmdPSH, st.id, data[:n])
		data = data[n:]
	}
	_, hasDL, dlExpired := st.wd.snapshot()
	if dlExpired {
		return os.ErrDeadlineExceeded
	}
	if !hasDL {
		ok, err := s.tryAcquireInlineWrite()
		if err != nil {
			return err
		}
		if ok {
			if e := st.writeState(); e != nil {
				s.releaseInlineWrite()
				return e
			}
			_, hasDL2, dlExpired2 := st.wd.snapshot()
			if dlExpired2 {
				s.releaseInlineWrite()
				return os.ErrDeadlineExceeded
			}
			if !hasDL2 {
				return s.writeInline(wire)
			}
			s.releaseInlineWrite()
		}
	}
	var req *writeReq
	reusedReq := false
	if !st.wreqBusy {
		select {
		case <-st.wdone:
		default:
		}
		st.wreq = writeReq{wire: wire, done: st.wdone}
		req = &st.wreq
		reusedReq = true
	} else {
		req = &writeReq{wire: wire, done: make(chan error, 1)}
	}
	if e := s.enqueue(req); e != nil {
		if reusedReq {
			st.wreq.wire = nil
		}
		return e
	}
	var stop error
	select {
	case e := <-req.done:
		if reusedReq {
			st.wreq.wire = nil
		}
		return e
	case <-s.done:
		if reusedReq {
			st.wreqBusy = true
		}
		st.wbuf = nil
		return s.cause()
	case <-st.wd.done():
		stop = os.ErrDeadlineExceeded
	case <-st.closing:
		stop = net.ErrClosed
	case <-st.wabort:
		stop = errStreamRefused
	}
	if s.cancel(req) {
		if reusedReq {
			st.wreq.wire = nil
		}
		return stop
	}
	// Already on the wire path: report the real outcome.
	select {
	case e := <-req.done:
		if reusedReq {
			st.wreq.wire = nil
		}
		return e
	case <-s.done:
		if reusedReq {
			st.wreqBusy = true
		}
		st.wbuf = nil
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
	st.stopped.Store(true)
	in := st.in
	head := st.inHead
	pooled := st.pooled
	st.in = nil
	st.inHead = 0
	st.off = 0
	st.inBytes = 0
	st.inBytesAtomic.Store(0)
	st.wakeDirectSinkLocked()
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
	st.drainFreeBufs()
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
	target  time.Time
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
		d.target = time.Time{}
		return
	}
	d.hasSet = true
	d.target = t
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

func (d *deadline) snapshot() (target time.Time, hasSet bool, expired bool) {
	d.mu.Lock()
	target, hasSet, expired = d.target, d.hasSet, d.isEnded
	d.mu.Unlock()
	return
}

// RecvPoolBytes returns total bytes currently held in AnyTLS idle receive and
// session frame slab pools.
func RecvPoolBytes() uint64 {
	recvPool.mu.Lock()
	rb := recvPool.bytes
	recvPool.mu.Unlock()
	sessionIOPools.mu.Lock()
	sb := len(sessionIOPools.slabs) * frameSlabSize
	sessionIOPools.mu.Unlock()
	if rb < 0 {
		rb = 0
	}
	return uint64(rb + sb)
}

// TrimRecvBufPool drops idle pooled receive buffers when the desktop core
// trims memory during quiet intervals.
func TrimRecvBufPool() int {
	recvPool.mu.Lock()
	defer recvPool.mu.Unlock()
	dropped := 0
	for i := range recvPool.classes {
		if n := len(recvPool.classes[i]); n > 0 {
			clear(recvPool.classes[i])
			recvPool.classes[i] = nil
			dropped += n
		}
	}
	recvPool.bytes = 0
	dropped += trimSessionIOPools()
	return dropped
}
