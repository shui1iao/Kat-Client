package anytls

import (
	"bufio"
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
const maxRawWriteBatch = 68 << 10

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
	o        *Outbound
	conn     net.Conn // *tls.Conn over the under connection
	rawWrite *bufferedWriteConn
	scheme   *paddingScheme
	packet   int // writer-owned padding packet counter (auth was packet 0)

	mu              sync.Mutex
	streams         map[uint32]*stream
	nextID          uint32
	writing         bool
	queue           []*writeReq
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
	lastUsed  time.Time
	idleGen   uint64
	idleTimer *time.Timer

	// Immutable guards for the actual carrier path (nil for a static path).
	route []func() bool
}

func newSession(o *Outbound, conn net.Conn, rawWrite *bufferedWriteConn, scheme *paddingScheme, settings []byte) *session {
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
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		s.failed.Store(true)
		s.mu.Lock()
		se := s.err
		if se == nil {
			se = &sessionError{err}
			s.err = se
		}
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
	s.enqueueLocked(r)
	return nil
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
	_ = s.conn.SetWriteDeadline(time.Now().Add(writeStall))
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
	r := bufio.NewReaderSize(s.conn, 32<<10)
	var header [headerSize]byte
	for {
		if _, e := io.ReadFull(r, header[:]); e != nil {
			return e
		}
		s.lastRecv.Store(time.Now().UnixNano())
		cmd := header[0]
		id := binary.BigEndian.Uint32(header[1:5])
		n := int(binary.BigEndian.Uint16(header[5:7]))
		switch cmd {
		case cmdPSH:
			st := s.lookup(id)
			if st == nil {
				if _, e := r.Discard(n); e != nil {
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
				if _, e := r.Discard(n); e != nil {
					return unexpected(e)
				}
				continue
			}
			data := acquireRecvBuf(n)
			if _, e := io.ReadFull(r, data); e != nil {
				releaseRecvBuf(data)
				return unexpected(e)
			}
			st.pushPooled(data)
		case cmdFIN:
			if st := s.lookup(id); st != nil {
				st.remoteClose(io.EOF)
			}
			if _, e := r.Discard(n); e != nil {
				return unexpected(e)
			}
		case cmdSYNACK:
			msg, e := readBody(r, n)
			if e != nil {
				return e
			}
			if st := s.lookup(id); st != nil {
				st.acknowledge(msg)
			}
		case cmdWaste, cmdHeartResponse:
			if _, e := r.Discard(n); e != nil {
				return unexpected(e)
			}
		case cmdHeartRequest:
			if _, e := r.Discard(n); e != nil {
				return unexpected(e)
			}
			_ = s.enqueue(&writeReq{wire: appendFrame(nil, cmdHeartResponse, id, nil), done: make(chan error, 1)})
		case cmdServerSettings:
			body, e := readBody(r, n)
			if e != nil {
				return e
			}
			v := parseVersion(body)
			s.mu.Lock()
			s.peerVersion = v
			s.mu.Unlock()
			s.verOnce.Do(func() { close(s.ver) })
		case cmdUpdatePaddingScheme:
			body, e := readBody(r, n)
			if e != nil {
				return e
			}
			// Applies to sessions created from now on; a malformed scheme is ignored.
			if p, e := parsePaddingScheme(string(body)); e == nil {
				s.o.scheme.Store(p)
				s.o.paddingUpdates.Add(1)
			}
		case cmdAlert:
			body, _ := readBody(r, n)
			return fmt.Errorf("anytls: server alert: %s", printable(body))
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

// printable bounds and sanitizes server-provided text before it enters errors.
func printable(b []byte) string {
	if len(b) > 200 {
		b = b[:200]
	}
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			out = append(out, c)
		} else {
			out = append(out, '?')
		}
	}
	return string(out)
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
