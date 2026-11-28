package anytls

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Frame commands (AnyTLS protocol): header is cmd(1) | streamID(4) | length(2).
const (
	cmdWaste byte = iota
	cmdSYN
	cmdPSH
	cmdFIN
	cmdSettings
	cmdAlert
	cmdUpdatePaddingScheme
	cmdSYNACK
	cmdHeartRequest
	cmdHeartResponse
	cmdServerSettings
)

const (
	headerSize = 7
	maxFrame   = 65535
	// Bytes coalesced into one physical write by the session writer.
	maxBatch = 256 << 10
	// Per-session FIFO admission bound (data writes are also chunked).
	maxQueuedWrites = 64
	// Leave space for the exclusive stream's open, data and FIN even if
	// the reader is paused waiting to enqueue another heartbeat response.
	responseHighWater = maxQueuedWrites - 3
	// A physical write that makes no progress for this long fails the session
	// (session-internal stall guard; stream deadlines never touch the transport).
	writeStall = 30 * time.Second
)

func appendFrame(b []byte, cmd byte, id uint32, data []byte) []byte {
	b = append(b, cmd)
	b = binary.BigEndian.AppendUint32(b, id)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

// sessionError marks a failure of the whole session (transport/protocol), as
// opposed to a per-stream rejection.
type sessionError struct{ cause error }

func (e *sessionError) Error() string { return "anytls: session failed: " + e.cause.Error() }
func (e *sessionError) Unwrap() error { return e.cause }

type writeReq struct {
	wire  []byte
	taken bool
	done  chan error // capacity 1; the writer never blocks
}

// maxRawWriteBatch bounds the synchronous per-writePadded buffer that coalesces
// multiple 16 KiB TLS records (and any framing tail record) produced within a
// single logical write into one underlying conn.Write call before immediate flush.
const (
	maxRawWriteBatch = 132 << 10
	frameSlabSize    = 64 << 10
	maxSessionPool   = 16
)

var (
	activeSessions atomic.Int64
	activeStreams  atomic.Int64
)

// ActiveStats returns the current count of live AnyTLS client sessions (busy +
// idle/warm) and active logical streams across the process.
func ActiveStats() (sessions, streams uint64) {
	s := activeSessions.Load()
	if s < 0 {
		s = 0
	}
	st := activeStreams.Load()
	if st < 0 {
		st = 0
	}
	return uint64(s), uint64(st)
}

var sessionIOPools struct {
	mu    sync.Mutex
	slabs [][]byte
}

func acquireFrameSlab() []byte {
	sessionIOPools.mu.Lock()
	if n := len(sessionIOPools.slabs); n > 0 {
		b := sessionIOPools.slabs[n-1]
		sessionIOPools.slabs[n-1] = nil
		sessionIOPools.slabs = sessionIOPools.slabs[:n-1]
		sessionIOPools.mu.Unlock()
		return b
	}
	sessionIOPools.mu.Unlock()
	return make([]byte, frameSlabSize)
}

func releaseFrameSlab(b []byte) {
	if cap(b) != frameSlabSize {
		return
	}
	b = b[:frameSlabSize]
	sessionIOPools.mu.Lock()
	if len(sessionIOPools.slabs) < maxSessionPool {
		sessionIOPools.slabs = append(sessionIOPools.slabs, b)
	}
	sessionIOPools.mu.Unlock()
}

func trimSessionIOPools() int {
	sessionIOPools.mu.Lock()
	defer sessionIOPools.mu.Unlock()
	d := len(sessionIOPools.slabs)
	clear(sessionIOPools.slabs)
	sessionIOPools.slabs = nil
	return d
}

type bufferedWriteConn struct {
	net.Conn
	mu       sync.Mutex
	batching bool
	buf      []byte
}

type bufferedWriteConnCW struct {
	*bufferedWriteConn
	cw interface{ CloseWrite() error }
}

func (c *bufferedWriteConnCW) CloseWrite() error {
	if err := c.endBatchWrite(); err != nil {
		_ = c.cw.CloseWrite()
		return err
	}
	return c.cw.CloseWrite()
}

func wrapBufferedWriteConn(raw net.Conn) *bufferedWriteConn {
	return &bufferedWriteConn{Conn: raw}
}

func (c *bufferedWriteConn) asNetConn() net.Conn {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return &bufferedWriteConnCW{bufferedWriteConn: c, cw: cw}
	}
	return c
}

func (c *bufferedWriteConn) beginBatchWrite() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.batching = true
	c.mu.Unlock()
}

func (c *bufferedWriteConn) endBatchWrite() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batching = false
	if len(c.buf) == 0 {
		return nil
	}
	err := writeAll(c.Conn, c.buf)
	c.buf = c.buf[:0]
	if cap(c.buf) > maxRawWriteBatch*2 {
		c.buf = nil
	}
	return err
}

func (c *bufferedWriteConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.batching {
		if len(c.buf) > 0 {
			if err := writeAll(c.Conn, c.buf); err != nil {
				c.buf = c.buf[:0]
				return 0, err
			}
			c.buf = c.buf[:0]
		}
		return c.Conn.Write(p)
	}
	if len(c.buf) == 0 && len(p) >= maxRawWriteBatch {
		if err := writeAll(c.Conn, p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	if len(c.buf)+len(p) > maxRawWriteBatch && len(c.buf) > 0 {
		if err := writeAll(c.Conn, c.buf); err != nil {
			c.buf = c.buf[:0]
			return 0, err
		}
		c.buf = c.buf[:0]
		if len(p) >= maxRawWriteBatch {
			if err := writeAll(c.Conn, p); err != nil {
				return 0, err
			}
			return len(p), nil
		}
	}
	if cap(c.buf) < maxRawWriteBatch {
		buf := make([]byte, len(c.buf), maxRawWriteBatch)
		copy(buf, c.buf)
		c.buf = buf
	}
	c.buf = append(c.buf, p...)
	return len(p), nil
}

type session struct {
	o            *Outbound
	conn         net.Conn // *tls.Conn over the under connection
	rawWrite     *bufferedWriteConn
	scheme       *paddingScheme
	packet       int   // writer-owned padding packet counter (auth was packet 0)
	lastDeadline int64 // writer-owned unix nanos of last SetWriteDeadline

	mu              sync.Mutex
	streams         map[uint32]*stream
	nextID          uint32
	writing         bool
	queue           []*writeReq
	queueSpace      chan struct{} // non-nil only while the reader is backpressured
	pendingSettings []byte
	err             error
	peerVersion     int

	wake     chan struct{} // capacity 1
	done     chan struct{} // closed on failure
	ver      chan struct{} // closed when server settings arrive
	verOnce  sync.Once
	failOnce sync.Once
	failed   atomic.Bool
	lastRecv atomic.Int64 // unix nanos of the last frame received
	wg       sync.WaitGroup

	// Pool bookkeeping, guarded by Outbound.mu.
	reserved  int
	usedCount uint64
	lastUsed  time.Time
	idleGen   uint64
	idleTimer *time.Timer

	// Immutable guards for the actual carrier path (nil for a static path).
	route []func() bool
}

func newSession(o *Outbound, conn net.Conn, rawWrite *bufferedWriteConn, scheme *paddingScheme, settings []byte) *session {
	activeSessions.Add(1)
	return &session{
		o: o, conn: conn, rawWrite: rawWrite, scheme: scheme, packet: 1, streams: make(map[uint32]*stream),
		pendingSettings: settings, wake: make(chan struct{}, 1), done: make(chan struct{}), ver: make(chan struct{}),
	}
}

func (s *session) start() {
	s.wg.Add(2)
	go s.recvLoop()
	go s.writeLoop()
}

func (s *session) stopIdleLocked() {
	s.idleGen++
	if s.idleTimer != nil {
		s.idleTimer.Stop()
		s.idleTimer = nil
	}
}

func (s *session) cause() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// fail tears the session down once: transport closed, every stream errors,
// queued writes complete with the error, and the pool forgets the session.
func (s *session) fail(err error) {
	s.failOnce.Do(func() {
		activeSessions.Add(-1)
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		s.mu.Lock()
		se := s.err
		if se == nil {
			se = &sessionError{err}
			s.err = se
		}
		s.failed.Store(true)
		streams := s.streams
		s.streams = make(map[uint32]*stream)
		queue := s.queue
		s.queue = nil
		close(s.done)
		s.mu.Unlock()
		if s.conn != nil {
			_ = s.conn.Close()
		}
		for _, q := range queue {
			q.done <- se
		}
		for _, st := range streams {
			st.abort(se)
		}
		s.o.removeSession(s)
	})
}

// openStream registers a stream and queues [settings]+SYN+PSH(first). It does
// not wait; await observes the server's answer.
func (s *session) openStream(first []byte) (*stream, *writeReq, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, nil, s.err
	}
	if len(s.queue) >= maxQueuedWrites {
		return nil, nil, errQueueFull
	}
	s.nextID++
	st := newStream(s, s.nextID)
	s.streams[st.id] = st
	wire := s.pendingSettings
	s.pendingSettings = nil
	wire = appendFrame(wire, cmdSYN, st.id, nil)
	wire = appendFrame(wire, cmdPSH, st.id, first)
	st.sentAt = time.Now().UnixNano()
	req := &writeReq{wire: wire, done: make(chan error, 1)}
	s.enqueueLocked(req)
	return st, req, nil
}

func (s *session) enqueueLocked(r *writeReq) {
	s.queue = append(s.queue, r)
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// enqueue queues r unless the session failed.
func (s *session) enqueue(r *writeReq) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	if len(s.queue) >= maxQueuedWrites {
		return errQueueFull
	}
	s.enqueueLocked(r)
	return nil
}

// Block the reader at a full FIFO instead of buffering arbitrary heartbeat
// responses. Writer pickup, withdrawal, and session shutdown resume the reader.
func (s *session) enqueueResponse(id uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.err == nil && len(s.queue) >= responseHighWater {
		if s.queueSpace == nil {
			s.queueSpace = make(chan struct{})
		}
		space := s.queueSpace
		s.mu.Unlock()
		select {
		case <-space:
		case <-s.done:
		}
		s.mu.Lock()
	}
	if s.err != nil {
		return s.err
	}
	s.enqueueLocked(&writeReq{wire: appendFrame(nil, cmdHeartResponse, id, nil), done: make(chan error, 1)})
	return nil
}
func (s *session) notifySpaceLocked() {
	if s.queueSpace != nil {
		close(s.queueSpace)
		s.queueSpace = nil
	}
}

// cancel withdraws r if the writer has not taken it yet (then nothing of it
// reached the wire).
func (s *session) cancel(r *writeReq) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.taken {
		return false
	}
	for i, q := range s.queue {
		if q == r {
			copy(s.queue[i:], s.queue[i+1:])
			s.queue[len(s.queue)-1] = nil
			s.queue = s.queue[:len(s.queue)-1]
			s.notifySpaceLocked()
			return true
		}
	}
	return false
}

func (s *session) detachStream(id uint32) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

func (s *session) lookup(id uint32) *stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streams[id]
}

// tryAcquireInlineWrite claims the writer token when the session has no active
// writer and no queued requests ahead of the caller, preserving strict FIFO
// ordering with queued control/FIN/other-stream frames.
func (s *session) tryAcquireInlineWrite() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return false, s.err
	}
	if s.conn == nil || s.writing || len(s.queue) > 0 {
		return false, nil
	}
	s.writing = true
	return true, nil
}

func (s *session) releaseInlineWrite() {
	s.mu.Lock()
	s.writing = false
	hasQueued := len(s.queue) > 0 && s.err == nil
	s.mu.Unlock()
	if hasQueued {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

func (s *session) writeInline(wire []byte) error {
	e := s.writePadded(wire)
	if e != nil {
		// Fail the session (sets s.err, drains s.queue, closes s.done) BEFORE
		// releasing s.writing, and keep s.err non-nil so no concurrent stream or
		// writeLoop can acquire the token or emit another frame after a failed write.
		s.fail(e)
		s.mu.Lock()
		s.writing = false
		cause := s.err
		s.mu.Unlock()
		return cause
	}
	s.releaseInlineWrite()
	return nil
}

func (s *session) writeLoop() {
	defer s.wg.Done()
	var (
		buf      []byte
		batchBuf [8]*writeReq
	)
	for {
		s.mu.Lock()
		for (len(s.queue) == 0 || s.writing) && s.err == nil {
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
		s.writing = true
		n, size := 0, 0
		for n < len(s.queue) && (n == 0 || size+len(s.queue[n].wire) <= maxBatch) {
			s.queue[n].taken = true
			size += len(s.queue[n].wire)
			n++
		}
		var batch []*writeReq
		if n <= len(batchBuf) {
			batch = batchBuf[:n]
			copy(batch, s.queue[:n])
		} else {
			batch = append([]*writeReq(nil), s.queue[:n]...)
		}
		remaining := copy(s.queue, s.queue[n:])
		clear(s.queue[remaining:])
		s.queue = s.queue[:remaining]
		s.notifySpaceLocked()
		s.mu.Unlock()

		var payload []byte
		if len(batch) == 1 {
			payload = batch[0].wire
		} else {
			buf = buf[:0]
			for _, r := range batch {
				buf = append(buf, r.wire...)
			}
			payload = buf
		}
		e := s.writePadded(payload)
		if e != nil {
			s.fail(e)
			s.mu.Lock()
			s.writing = false
			cause := s.err
			s.mu.Unlock()
			for i, r := range batch {
				r.done <- cause
				batch[i] = nil
			}
			return
		}
		for i, r := range batch {
			r.done <- nil
			batch[i] = nil
		}
		s.mu.Lock()
		s.writing = false
		s.mu.Unlock()
		if cap(buf) > maxBatch*2 {
			buf = nil
		}
	}
}

// writePadded performs one session write ("packet"). While the packet counter is
// below the scheme's stop, the payload is cut into records of the sampled sizes;
// a record left with spare room is topped up with a waste frame, and a size
// with no payload left becomes a pure waste record. A checkpoint ends padding
// for this packet once the payload is exhausted.
func (s *session) writePadded(b []byte) (err error) {
	if now := time.Now(); now.UnixNano()-s.lastDeadline >= int64(5*time.Second) {
		_ = s.conn.SetWriteDeadline(now.Add(writeStall))
		s.lastDeadline = now.UnixNano()
	}
	if s.rawWrite != nil {
		s.rawWrite.beginBatchWrite()
		defer func() {
			if fe := s.rawWrite.endBatchWrite(); err == nil {
				err = fe
			}
		}()
	}
	packet := s.packet
	if s.scheme != nil && packet < s.scheme.stop {
		s.packet++
	}
	var sizes []int
	if s.scheme != nil {
		sizes = s.scheme.sizes(packet)
	}
	for _, size := range sizes {
		if size == checkMark {
			if len(b) == 0 {
				break
			}
			continue
		}
		switch {
		case len(b) > size:
			if e := writeAll(s.conn, b[:size]); e != nil {
				return e
			}
			b = b[size:]
		case len(b) > 0:
			record := b
			if pad := size - len(b) - headerSize; pad > 0 {
				record = appendFrame(append([]byte(nil), b...), cmdWaste, 0, make([]byte, pad))
			}
			if e := writeAll(s.conn, record); e != nil {
				return e
			}
			b = nil
		default:
			pad := max(size-headerSize, 0)
			if e := writeAll(s.conn, appendFrame(nil, cmdWaste, 0, make([]byte, pad))); e != nil {
				return e
			}
		}
	}
	if len(b) == 0 {
		return nil
	}
	return writeAll(s.conn, b)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		b = b[n:]
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (s *session) recvLoop() {
	defer s.wg.Done()
	s.fail(s.readFrames())
}

func (s *session) readFrames() error {
	if s.rawWrite != nil {
		return s.readFramesFast()
	}
	r := s.conn
	var header [headerSize]byte
	var lastID uint32
	var lastSt *stream
	for {
		if _, e := io.ReadFull(r, header[:]); e != nil {
			return e
		}
		cmd := header[0]
		id := binary.BigEndian.Uint32(header[1:5])
		n := int(binary.BigEndian.Uint16(header[5:7]))
		switch cmd {
		case cmdPSH:
			var st *stream
			if id == lastID && lastSt != nil && !lastSt.stopped.Load() {
				st = lastSt
			} else {
				st = s.lookup(id)
				lastID, lastSt = id, st
			}
			if st == nil {
				if _, e := discardN(r, n); e != nil {
					return unexpected(e)
				}
				continue
			}
			if n == 0 {
				continue
			}
			ok, sessionDone := st.waitSpace(n)
			if !ok {
				if sessionDone {
					if e := s.cause(); e != nil {
						return e
					}
					return io.ErrUnexpectedEOF
				}
				if _, e := discardN(r, n); e != nil {
					return unexpected(e)
				}
				continue
			}
			data := st.acquireBuf(n)
			if _, e := io.ReadFull(r, data); e != nil {
				releaseRecvBuf(data)
				return unexpected(e)
			}
			st.pushPooled(data)
		case cmdFIN:
			s.lastRecv.Store(time.Now().UnixNano())
			if id == lastID {
				lastID, lastSt = 0, nil
			}
			if st := s.lookup(id); st != nil {
				st.remoteClose(io.EOF)
			}
			if _, e := discardN(r, n); e != nil {
				return unexpected(e)
			}
		case cmdSYNACK:
			s.lastRecv.Store(time.Now().UnixNano())
			if _, e := discardN(r, n); e != nil {
				return unexpected(e)
			}
			if st := s.lookup(id); st != nil {
				st.acknowledge(n == 0)
			}
		case cmdWaste, cmdHeartResponse:
			if _, e := discardN(r, n); e != nil {
				return unexpected(e)
			}
		case cmdHeartRequest:
			if _, e := discardN(r, n); e != nil {
				return unexpected(e)
			}
			if err := s.enqueueResponse(id); err != nil {
				return err
			}
		case cmdServerSettings:
			body, e := readBody(r, n)
			if e != nil {
				return e
			}
			s.verOnce.Do(func() {
				s.mu.Lock()
				s.peerVersion = parseVersion(body)
				s.mu.Unlock()
				close(s.ver)
			})
		case cmdUpdatePaddingScheme:
			body, e := readBody(r, n)
			if e != nil {
				return e
			}
			if p, e := parsePaddingScheme(string(body)); e == nil {
				s.o.scheme.Store(p)
				s.o.paddingUpdates.Add(1)
			}
		case cmdAlert:
			if _, e := discardN(r, n); e != nil {
				return unexpected(e)
			}
			return errServerAlert
		default:
			return fmt.Errorf("%w: command %d", errProtocol, cmd)
		}
	}
}

// readFramesFast reads TLS plaintext directly into a pooled 64 KiB slab and
// parses AnyTLS frame headers in-place. When a stream has an active direct
// WriteTo sink, PSH payloads are written directly from the slab to the sink
// without intermediate buffer allocation, copy, or goroutine wakeup.
func (s *session) readFramesFast() error {
	slab := acquireFrameSlab()
	defer releaseFrameSlab(slab)
	start, end := 0, 0
	var lastID uint32
	var lastSt *stream

	ensure := func(need int) error {
		if end-start >= need {
			return nil
		}
		if start > 0 {
			if start < end {
				copy(slab, slab[start:end])
				end -= start
			} else {
				end = 0
			}
			start = 0
		}
		for end < need {
			nr, err := s.conn.Read(slab[end:])
			if nr > 0 {
				end += nr
			}
			if end >= need {
				return nil
			}
			if err != nil {
				return err
			}
			if nr == 0 {
				return io.ErrUnexpectedEOF
			}
		}
		return nil
	}

	discardSlab := func(n int) error {
		for n > 0 {
			avail := end - start
			if avail == 0 {
				start, end = 0, 0
				nr, err := s.conn.Read(slab)
				if nr > 0 {
					end = nr
					avail = nr
				} else if err != nil {
					return unexpected(err)
				} else {
					return io.ErrUnexpectedEOF
				}
			}
			take := n
			if take > avail {
				take = avail
			}
			start += take
			n -= take
		}
		return nil
	}

	readExact := func(dst []byte) error {
		off := 0
		if avail := end - start; avail > 0 {
			take := copy(dst, slab[start:end])
			start += take
			off += take
			if start == end {
				start, end = 0, 0
			}
		}
		if off < len(dst) {
			if _, err := io.ReadFull(s.conn, dst[off:]); err != nil {
				return unexpected(err)
			}
		}
		return nil
	}

	for {
		if err := ensure(headerSize); err != nil {
			return err
		}
		cmd := slab[start]
		id := binary.BigEndian.Uint32(slab[start+1 : start+5])
		n := int(binary.BigEndian.Uint16(slab[start+5 : start+7]))
		start += headerSize
		if start == end {
			start, end = 0, 0
		}

		switch cmd {
		case cmdPSH:
			var st *stream
			if id == lastID && lastSt != nil && !lastSt.stopped.Load() {
				st = lastSt
			} else {
				st = s.lookup(id)
				lastID, lastSt = id, st
			}
			if st == nil {
				if err := discardSlab(n); err != nil {
					return err
				}
				continue
			}
			if n == 0 {
				continue
			}
			// Zero-hop fast path: if WriteTo has registered a direct sink on st,
			// assemble the full in-flight frame (up to 59 KiB to fill jumbo MTU
			// without waiting past this frame) and coalesce any consecutive
			// same-stream cmdPSH frames already buffered in slab into one write.
			if sink := st.acquireDirectSink(); sink != nil {
				const coalesceTarget = 59000
				rem := n
				var writeErr error
				writeAll := func(chunk []byte) {
					for len(chunk) > 0 && writeErr == nil {
						nw, ew := sink.w.Write(chunk)
						sink.written += int64(nw)
						chunk = chunk[nw:]
						if ew != nil {
							writeErr = ew
							return
						}
						if nw == 0 {
							writeErr = io.ErrShortWrite
							return
						}
					}
				}
				for rem > 0 {
					want := rem
					if want > coalesceTarget {
						want = coalesceTarget
					}
					if want > len(slab) {
						want = len(slab)
					}
					if end-start < want {
						if start > 0 {
							if start < end {
								copy(slab, slab[start:end])
								end -= start
							} else {
								end = 0
							}
							start = 0
						}
						for end < want {
							nr, rerr := s.conn.Read(slab[end:])
							if nr > 0 {
								end += nr
							}
							if end >= want {
								break
							}
							if rerr != nil {
								if end > 0 {
									writeAll(slab[:end])
									end = 0
								}
								st.releaseDirectSink(writeErr)
								return unexpected(rerr)
							}
							if nr == 0 {
								st.releaseDirectSink(writeErr)
								return io.ErrUnexpectedEOF
							}
						}
					}
					take := rem
					if avail := end - start; take > avail {
						take = avail
					}
					chunk := slab[start : start+take]
					start += take
					if start == end {
						start, end = 0, 0
					}
					rem -= take
					if writeErr == nil {
						// Opportunistically coalesce any complete follow-up cmdPSH frames for the
						// exact same stream already sitting in slab (zero wait, zero extra copy).
						if rem == 0 && end-start >= headerSize && len(chunk) < coalesceTarget {
							if bw, ok := sink.w.(interface {
								WriteBuffers(*net.Buffers) (int64, error)
							}); ok {
								var vec [8][]byte
								vec[0] = chunk
								vcnt := 1
								totBytes := len(chunk)
								for vcnt < len(vec) && end-start >= headerSize && totBytes < coalesceTarget {
									if slab[start] != cmdPSH {
										break
									}
									nid := binary.BigEndian.Uint32(slab[start+1 : start+5])
									if nid != id {
										break
									}
									nlen := int(binary.BigEndian.Uint16(slab[start+5 : start+7]))
									if nlen == 0 || end-start < headerSize+nlen || totBytes+nlen > coalesceTarget {
										break
									}
									start += headerSize
									vec[vcnt] = slab[start : start+nlen]
									start += nlen
									if start == end {
										start, end = 0, 0
									}
									vcnt++
									totBytes += nlen
								}
								if vcnt > 1 {
									bufs := net.Buffers(vec[:vcnt])
									nw, ew := bw.WriteBuffers(&bufs)
									sink.written += nw
									if ew != nil {
										writeErr = ew
									}
									continue
								}
							}
						}
						writeAll(chunk)
					}
				}
				st.releaseDirectSink(writeErr)
				continue
			}
			ok, sessionDone := st.waitSpace(n)
			if !ok {
				if sessionDone {
					if e := s.cause(); e != nil {
						return e
					}
					return io.ErrUnexpectedEOF
				}
				if err := discardSlab(n); err != nil {
					return err
				}
				continue
			}
			data := st.acquireBuf(n)
			if err := readExact(data); err != nil {
				releaseRecvBuf(data)
				return err
			}
			st.pushPooled(data)
		case cmdFIN:
			s.lastRecv.Store(time.Now().UnixNano())
			if id == lastID {
				lastID, lastSt = 0, nil
			}
			if st := s.lookup(id); st != nil {
				st.remoteClose(io.EOF)
			}
			if err := discardSlab(n); err != nil {
				return err
			}
		case cmdSYNACK:
			s.lastRecv.Store(time.Now().UnixNano())
			if err := discardSlab(n); err != nil {
				return err
			}
			if st := s.lookup(id); st != nil {
				st.acknowledge(n == 0)
			}
		case cmdWaste, cmdHeartResponse:
			if err := discardSlab(n); err != nil {
				return err
			}
		case cmdHeartRequest:
			if err := discardSlab(n); err != nil {
				return err
			}
			if err := s.enqueueResponse(id); err != nil {
				return err
			}
		case cmdServerSettings:
			body := make([]byte, n)
			if err := readExact(body); err != nil {
				return err
			}
			s.verOnce.Do(func() {
				s.mu.Lock()
				s.peerVersion = parseVersion(body)
				s.mu.Unlock()
				close(s.ver)
			})
		case cmdUpdatePaddingScheme:
			body := make([]byte, n)
			if err := readExact(body); err != nil {
				return err
			}
			if p, e := parsePaddingScheme(string(body)); e == nil {
				s.o.scheme.Store(p)
				s.o.paddingUpdates.Add(1)
			}
		case cmdAlert:
			if err := discardSlab(n); err != nil {
				return err
			}
			return errServerAlert
		default:
			return fmt.Errorf("%w: command %d", errProtocol, cmd)
		}
	}
}

func readBody(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, e := io.ReadFull(r, b); e != nil {
		return nil, unexpected(e)
	}
	return b, nil
}

func unexpected(e error) error {
	if e == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return e
}

// parseVersion reads "v=N" from the server settings; anything else is 0.
func parseVersion(b []byte) int {
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k == "v" {
			if n, e := strconv.Atoi(v); e == nil && n > 0 {
				return n
			}
		}
	}
	return 0
}

func (s *session) version() (int, bool) {
	select {
	case <-s.ver:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.peerVersion, true
	default:
		return 0, false
	}
}

func discardN(r io.Reader, n int) (int64, error) {
	if n <= 0 {
		return 0, nil
	}
	return io.CopyN(io.Discard, r, int64(n))
}
