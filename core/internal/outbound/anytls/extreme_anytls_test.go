package anytls

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

func TestHotStandbyPrewarmBurstAndIdleConvergence(t *testing.T) {
	cert, ks := katFixture(t)
	echo := tcpEchoServer(t)
	under := &countingDialer{}
	opt := baseOptions(ks.addr, testPassword, &outbound.TLSOptions{PinSHA256: cert.pin})
	opt.IdleSessions = 8
	opt.MinIdleSessions = 6
	opt.IdleTimeout = outbound.Duration(1 * time.Second)
	o := newTestOutbound(t, opt, under)

	// Zero network I/O before first real traffic.
	if o.sessionsCreated.Load() != 0 || under.n.Load() != 0 {
		t.Fatalf("New must not dial: sessions=%d under=%d", o.sessionsCreated.Load(), under.n.Load())
	}

	// First real dial triggers background hot-standby pre-warming.
	c1, err := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
	if err != nil {
		t.Fatal(err)
	}
	if err := echoRoundTrip(c1, []byte("warm-check")); err != nil {
		t.Fatal(err)
	}
	_ = c1.Close()

	// Wait for background warmers to populate standby pool (>= 6 idle).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		busy, idle := o.sessionCount()
		if busy == 0 && idle >= 6 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	busy, idle := o.sessionCount()
	if busy != 0 || idle < 6 || idle > 8 {
		t.Fatalf("expected 6..8 warmed idle sessions, got busy=%d idle=%d", busy, idle)
	}
	beforeCreated := o.sessionsCreated.Load()

	// Sequential 6-stream burst should reuse warmed sessions without new dials.
	conns := make([]net.Conn, 6)
	for i := range conns {
		c, err := o.DialTCP(ctxTimeout(t, 5*time.Second), echo)
		if err != nil {
			t.Fatal(err)
		}
		conns[i] = c
	}
	for i, c := range conns {
		msg := []byte{byte(i), 1, 2, 3, 4}
		if err := echoRoundTrip(c, msg); err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
	if after := o.sessionsCreated.Load(); after < beforeCreated {
		t.Fatalf("unexpected sessionsCreated regression: %d < %d", after, beforeCreated)
	}

	// Idle convergence: after idleTimeout (1s), pool must converge strictly to 0 without re-warming.
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, id := o.sessionCount()
		if b == 0 && id == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	b, id := o.sessionCount()
	t.Fatalf("idle sessions did not converge to 0: busy=%d idle=%d", b, id)
}

func TestCoalescedPSHAndBufferedRWConnIntegrity(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	rw := wrapBufferedWriteConn(c1)
	payload := bytes.Repeat([]byte("KAT-EXTREME-ANYTLS-1234567890!"), 4096) // ~120 KiB
	errCh := make(chan error, 1)
	go func() {
		// Write in 16 KiB chunks to exercise buffered read + coalescing.
		for off := 0; off < len(payload); off += 4096 {
			end := off + 4096
			if end > len(payload) {
				end = len(payload)
			}
			if _, err := c2.Write(payload[off:end]); err != nil {
				errCh <- err
				return
			}
		}
		errCh <- nil
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(rw, got); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("bufferedRWConn payload mismatch")
	}
	_ = rw.Close()
	_ = TrimRecvBufPool()
}

func TestHotStandbyCloseCancelsInFlightWarmers(t *testing.T) {
	started := make(chan struct{}, 16)
	release := make(chan struct{})
	under := dialFunc(func(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
			return nil, context.Canceled
		}
	})
	opt := outbound.Options{
		Name: "any", Type: "anytls", Server: "127.0.0.1", Port: 443, Password: "pw",
		TLS: &outbound.TLSOptions{ServerName: "a.test"}, IdleSessions: 8, MinIdleSessions: 4,
	}
	raw, err := New(opt, under)
	if err != nil {
		t.Fatal(err)
	}
	o := raw.(*Outbound)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, _ = o.DialTCP(ctx, outbound.Addr{Host: "127.0.0.1", Port: 80})
	// Close must cancel all in-flight warmers promptly without hanging.
	done := make(chan struct{})
	go func() {
		_ = o.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("Outbound.Close hung waiting for warmers")
	}
}

type dialFunc func(context.Context, outbound.Addr) (net.Conn, error)

func (f dialFunc) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) { return f(ctx, dst) }
func (f dialFunc) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return nil, outbound.ErrUDPUnsupported
}
func (f dialFunc) UDP() bool { return false }
