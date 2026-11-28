package anytls

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type raceProbeConn struct {
	entered  chan struct{}
	release  chan struct{}
	closed   chan struct{}
	once     sync.Once
	clOnce   sync.Once
	checksum atomic.Uint64
}

func (c *raceProbeConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	var sum uint64
	for _, b := range p {
		sum += uint64(b)
	}
	select {
	case <-c.release:
	case <-c.closed:
	}
	// Re-read every byte of wire slice while caller may already have woken on <-s.done
	// and attempted a follow-up st.Write; any st.wbuf reuse races here under -race!
	for _, b := range p {
		sum ^= uint64(b)
	}
	c.checksum.Add(sum)
	return len(p), nil
}

func (c *raceProbeConn) Read([]byte) (int, error)         { <-c.closed; return 0, io.EOF }
func (c *raceProbeConn) Close() error                     { c.clOnce.Do(func() { close(c.closed) }); return nil }
func (c *raceProbeConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *raceProbeConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *raceProbeConn) SetDeadline(time.Time) error      { return nil }
func (c *raceProbeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *raceProbeConn) SetWriteDeadline(time.Time) error { return nil }

// [GO-P1-1] Verify concurrent session.fail() + stream.Write() never causes a data race
// on st.wbuf across both <-s.done wake paths, and writeState() observes s.failed immediately.
func TestSessionFailConcurrentStreamWriteNoWbufRace(t *testing.T) {
	stop1, err := parsePaddingScheme("stop=1\n0=30-30")
	if err != nil {
		t.Fatal(err)
	}

	for round := 0; round < 64; round++ {
		c := &raceProbeConn{
			entered: make(chan struct{}),
			release: make(chan struct{}),
			closed:  make(chan struct{}),
		}
		s := newSession(&Outbound{}, c, nil, stop1, nil)
		s.packet = 8
		st1 := newStream(s, 1)
		st2 := newStream(s, 2)
		s.streams[1] = st1
		s.streams[2] = st2

		// Force queued write path on both streams:
		// - st1 uses a long deadline -> hits primary select case <-s.done
		// - st2 uses a 2ms deadline -> after pickup hits secondary select case <-s.done
		_ = st1.SetWriteDeadline(time.Now().Add(time.Hour))
		_ = st2.SetWriteDeadline(time.Now().Add(2 * time.Millisecond))

		s.wg.Add(1)
		go s.writeLoop()

		var wg sync.WaitGroup
		wg.Add(2)
		p1 := bytes.Repeat([]byte{byte(round + 1)}, 512)
		p2 := bytes.Repeat([]byte{byte(round + 0x55)}, 512)

		go func() {
			defer wg.Done()
			_, _ = st1.Write(p1)
			for i := 0; i < 8; i++ {
				if _, err := st1.Write(p2); err == nil {
					t.Errorf("round %d: st1.Write succeeded after session fail", round)
					return
				}
			}
		}()

		go func() {
			defer wg.Done()
			_, _ = st2.Write(p2)
			_ = st2.SetWriteDeadline(time.Now().Add(time.Hour))
			for i := 0; i < 8; i++ {
				if _, err := st2.Write(p1); err == nil {
					t.Errorf("round %d: st2.Write succeeded after session fail", round)
					return
				}
			}
		}()

		<-c.entered
		if round%2 == 1 {
			time.Sleep(3 * time.Millisecond)
		}
		s.fail(io.ErrUnexpectedEOF)
		close(c.release)
		wg.Wait()
		s.wg.Wait()
	}
}

type deadlineAwareBackpressureConn struct {
	mu          sync.Mutex
	wdl         time.Time
	shortDLSeen atomic.Bool
	blockGate   chan struct{}
	closed      chan struct{}
	clOnce      sync.Once

	wroteMu sync.Mutex
	wireLog []byte
}

func newDeadlineAwareBackpressureConn() *deadlineAwareBackpressureConn {
	return &deadlineAwareBackpressureConn{closed: make(chan struct{})}
}

func (c *deadlineAwareBackpressureConn) setBlockGate(ch chan struct{}) {
	c.mu.Lock()
	c.blockGate = ch
	c.mu.Unlock()
}

func (c *deadlineAwareBackpressureConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.wdl = t
	if !t.IsZero() && time.Until(t) < 5*time.Second {
		c.shortDLSeen.Store(true)
	}
	c.mu.Unlock()
	return nil
}

func (c *deadlineAwareBackpressureConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	gate := c.blockGate
	wdl := c.wdl
	c.mu.Unlock()

	if gate != nil {
		if !wdl.IsZero() {
			wait := time.Until(wdl)
			if wait <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			tm := time.NewTimer(wait)
			defer tm.Stop()
			select {
			case <-gate:
			case <-tm.C:
				return 0, os.ErrDeadlineExceeded
			case <-c.closed:
				return 0, net.ErrClosed
			}
		} else {
			select {
			case <-gate:
			case <-c.closed:
				return 0, net.ErrClosed
			}
		}
	}

	c.wroteMu.Lock()
	c.wireLog = append(c.wireLog, p...)
	c.wroteMu.Unlock()
	return len(p), nil
}

func (c *deadlineAwareBackpressureConn) Read([]byte) (int, error) { <-c.closed; return 0, io.EOF }
func (c *deadlineAwareBackpressureConn) Close() error {
	c.clOnce.Do(func() { close(c.closed) })
	return nil
}
func (c *deadlineAwareBackpressureConn) LocalAddr() net.Addr             { return &net.TCPAddr{} }
func (c *deadlineAwareBackpressureConn) RemoteAddr() net.Addr            { return &net.TCPAddr{} }
func (c *deadlineAwareBackpressureConn) SetDeadline(t time.Time) error   { return c.SetWriteDeadline(t) }
func (c *deadlineAwareBackpressureConn) SetReadDeadline(time.Time) error { return nil }

// [GO-P1-2] Test 1: A single stream with a short 65ms WriteDeadline MUST NOT touch
// s.conn.SetWriteDeadline or tear down sibling healthy streams on the same multiplexed Session.
func TestShortStreamWriteDeadlineIsolatesSiblingStreams(t *testing.T) {
	stop1, err := parsePaddingScheme("stop=1\n0=30-30")
	if err != nil {
		t.Fatal(err)
	}

	c := newDeadlineAwareBackpressureConn()
	s := newSession(&Outbound{}, c, nil, stop1, nil)
	s.packet = 8
	stCarrier := newStream(s, 1)
	stShort := newStream(s, 2)
	stHealthy := newStream(s, 3)
	s.streams[1] = stCarrier
	s.streams[2] = stShort
	s.streams[3] = stHealthy

	s.wg.Add(1)
	go s.writeLoop()
	defer func() {
		s.fail(io.EOF)
		s.wg.Wait()
	}()

	// Subcase A: Idle session when 65ms stream writes while transport experiences 140ms transient stall.
	gateA := make(chan struct{})
	c.setBlockGate(gateA)
	go func() {
		time.Sleep(140 * time.Millisecond)
		close(gateA)
	}()

	_ = stShort.SetWriteDeadline(time.Now().Add(65 * time.Millisecond))
	errShortCh := make(chan error, 1)
	go func() {
		_, e := stShort.Write([]byte("dns-fallback-probe"))
		errShortCh <- e
	}()

	time.Sleep(15 * time.Millisecond)
	errHealthyCh := make(chan error, 1)
	go func() {
		_, e := stHealthy.Write([]byte("healthy-sibling-payload-A"))
		errHealthyCh <- e
	}()

	<-errShortCh
	if errH := <-errHealthyCh; errH != nil {
		t.Fatalf("sibling healthy stream failed during 65ms stream write: %v", errH)
	}
	if c.shortDLSeen.Load() {
		t.Fatal("stream WriteDeadline leaked onto shared s.conn.SetWriteDeadline!")
	}
	if s.failed.Load() {
		t.Fatal("shared session was destroyed by single-stream 65ms WriteDeadline!")
	}

	// Subcase B: Transport busy for 180ms; stShort (65ms deadline) withdraws cleanly with
	// os.ErrDeadlineExceeded while stHealthy completes unaffected on the same session!
	gateB := make(chan struct{})
	c.setBlockGate(gateB)
	carrierDone := make(chan error, 1)
	go func() {
		_, e := stCarrier.Write([]byte("inflight-carrier-write"))
		carrierDone <- e
	}()
	time.Sleep(15 * time.Millisecond)

	startShort := time.Now()
	_ = stShort.SetWriteDeadline(startShort.Add(65 * time.Millisecond))
	shortErr2 := make(chan error, 1)
	go func() {
		_, e := stShort.Write([]byte("must-withdraw-at-65ms"))
		shortErr2 <- e
	}()

	healthyDone2 := make(chan error, 1)
	go func() {
		_, e := stHealthy.Write([]byte("healthy-sibling-payload-B"))
		healthyDone2 <- e
	}()

	if e := <-shortErr2; !errors.Is(e, os.ErrDeadlineExceeded) {
		t.Fatalf("expected stShort 65ms timeout, got %v", e)
	}
	if elapsed := time.Since(startShort); elapsed > 150*time.Millisecond {
		t.Fatalf("stShort took %v to time out, want ~65ms (<150ms)", elapsed)
	}

	time.Sleep(30 * time.Millisecond)
	c.setBlockGate(nil)
	close(gateB)

	if e := <-carrierDone; e != nil {
		t.Fatalf("carrier stream failed: %v", e)
	}
	if e := <-healthyDone2; e != nil {
		t.Fatalf("healthy sibling stream failed: %v", e)
	}
	if s.failed.Load() || c.shortDLSeen.Load() {
		t.Fatalf("session failed=%v shortDLSeen=%v, want both false", s.failed.Load(), c.shortDLSeen.Load())
	}
}

// [GO-P1-2] Test 2: Calling st.SetWriteDeadline(past) dynamically while st.Write is blocked
// MUST immediately wake and withdraw the write within tens of milliseconds without harming the Session.
func TestDynamicPastWriteDeadlineUnblocksImmediately(t *testing.T) {
	stop1, err := parsePaddingScheme("stop=1\n0=30-30")
	if err != nil {
		t.Fatal(err)
	}

	c := newDeadlineAwareBackpressureConn()
	gate := make(chan struct{})
	c.setBlockGate(gate)

	s := newSession(&Outbound{}, c, nil, stop1, nil)
	s.packet = 8
	stBlocker := newStream(s, 1)
	stTarget := newStream(s, 2)
	s.streams[1] = stBlocker
	s.streams[2] = stTarget

	s.wg.Add(1)
	go s.writeLoop()
	defer func() {
		s.fail(io.EOF)
		s.wg.Wait()
	}()

	blockerDone := make(chan error, 1)
	go func() {
		_, e := stBlocker.Write([]byte("occupy-transport-writer"))
		blockerDone <- e
	}()
	time.Sleep(15 * time.Millisecond)

	_ = stTarget.SetWriteDeadline(time.Now().Add(30 * time.Second))
	targetErrCh := make(chan error, 1)
	go func() {
		_, e := stTarget.Write([]byte("blocked-queued-write"))
		targetErrCh <- e
	}()
	time.Sleep(20 * time.Millisecond)

	cancelAt := time.Now()
	_ = stTarget.SetWriteDeadline(cancelAt.Add(-time.Second))

	select {
	case e := <-targetErrCh:
		if !errors.Is(e, os.ErrDeadlineExceeded) {
			t.Fatalf("stTarget.Write returned %v, want os.ErrDeadlineExceeded", e)
		}
		if elapsed := time.Since(cancelAt); elapsed > 80*time.Millisecond {
			t.Fatalf("dynamic SetWriteDeadline(past) took %v to unblock, want <80ms", elapsed)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("stTarget.Write remained blocked after dynamic SetWriteDeadline(past)")
	}

	c.setBlockGate(nil)
	close(gate)
	if e := <-blockerDone; e != nil {
		t.Fatalf("stBlocker.Write failed: %v", e)
	}
	if s.failed.Load() {
		t.Fatal("session failed after dynamic per-stream write cancellation")
	}
	_ = stTarget.SetWriteDeadline(time.Time{})
	if _, e := stTarget.Write([]byte("post-cancel-recovery")); e != nil {
		t.Fatalf("stTarget follow-up Write after clearing deadline failed: %v", e)
	}
}
