package kernel

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"net"

	"net/netip"

	"syscall"
	"testing"
	"time"
)

// ---- SOCKS5 UDP reassembly ----

func newTestReassembly(maxBytes int, total int64, timeout time.Duration) (*reassembly, *fragmentPool) {
	p := &fragmentPool{}
	return newReassembly(p, func() int64 { return total }, maxBytes, timeout), p
}

func TestReassemblyOrdersDuplicatesAndLimits(t *testing.T) {
	a, b := Address{"127.0.0.1", 9}, Address{"127.0.0.1", 10}
	r, p := newTestReassembly(1024, 1<<20, time.Minute)
	// In order.
	r.add(1, a, []byte("ab"))
	r.add(2, a, []byte("cd"))
	if to, got, ok := r.add(3|0x80, a, []byte("ef")); !ok || string(got) != "abcdef" || to != a {
		t.Fatalf("in order: %q %v", got, ok)
	}
	// Out of order, with a duplicate.
	r.add(3|0x80, a, []byte("3"))
	r.add(1, a, []byte("1"))
	if _, _, ok := r.add(1, a, []byte("1")); ok {
		t.Fatal("duplicate completed")
	}
	if _, got, ok := r.add(2, a, []byte("2")); !ok || string(got) != "123" {
		t.Fatalf("reordered: %q %v", got, ok)
	}
	if p.dropped.Load() != 1 || p.reassembled.Load() != 2 || p.used.Load() != 0 {
		t.Fatalf("counters dropped=%d reassembled=%d used=%d", p.dropped.Load(), p.reassembled.Load(), p.used.Load())
	}
	// A changed duplicate or another destination starts a new datagram.
	r.add(1, a, []byte("old"))
	r.add(1, a, []byte("new"))
	r.add(1, b, []byte("x"))
	if _, got, ok := r.add(2|0x80, b, []byte("y")); !ok || string(got) != "xy" {
		t.Fatalf("restart: %q %v", got, ok)
	}
	// Malformed: position 0, last before a higher position, beyond the end.
	if _, _, ok := r.add(0x80, a, []byte("z")); ok {
		t.Fatal("position 0 accepted")
	}
	r.add(3, a, []byte("3"))
	r.add(2|0x80, a, []byte("2")) // inconsistent with position 3: restarts
	r.add(1, a, []byte("1"))
	if p.used.Load() != 0 || r.active {
		t.Fatalf("after completion used=%d active=%v", p.used.Load(), r.active)
	}
	// Per-association limit.
	r.add(1, a, make([]byte, 1000))
	if _, _, ok := r.add(2|0x80, a, make([]byte, 100)); ok || r.active || p.used.Load() != 0 {
		t.Fatal("association limit not applied")
	}
	r.close()
	if _, _, ok := r.add(1|0x80, a, []byte("x")); ok || p.used.Load() != 0 {
		t.Fatal("closed reassembly accepted a fragment")
	}
}

func TestReassemblyGlobalBudgetAndTimeout(t *testing.T) {
	a := Address{"127.0.0.1", 9}
	p := &fragmentPool{}
	limit := func() int64 { return 1500 }
	r1 := newReassembly(p, limit, 65535, 50*time.Millisecond)
	r2 := newReassembly(p, limit, 65535, 50*time.Millisecond)
	r1.add(1, a, make([]byte, 1000))
	r2.add(1, a, make([]byte, 400))
	if _, _, ok := r2.add(2|0x80, a, make([]byte, 200)); ok || r2.active {
		t.Fatal("global budget not applied")
	}
	if p.used.Load() != 1000 {
		t.Fatalf("used %d", p.used.Load())
	}
	time.Sleep(150 * time.Millisecond)
	if p.used.Load() != 0 {
		t.Fatalf("timeout did not release: %d", p.used.Load())
	}
	if _, _, ok := r1.add(2|0x80, a, []byte("late")); ok {
		t.Fatal("expired datagram completed")
	}
	r1.close()
	r2.close()
	if p.used.Load() != 0 {
		t.Fatal("bytes kept after close")
	}
}

func FuzzReassembly(f *testing.F) {
	f.Add([]byte{1, 0, 10, 0x82, 0, 10})
	f.Add([]byte{0x81, 1, 255, 0, 0, 0, 3, 0, 1})
	f.Fuzz(func(t *testing.T, ops []byte) {
		p := &fragmentPool{}
		const total = 8192
		r := newReassembly(p, func() int64 { return total }, 4096, time.Minute)
		targets := []Address{{"127.0.0.1", 1}, {"127.0.0.1", 2}}
		for len(ops) >= 3 {
			frag, tgt, size := ops[0], targets[ops[1]&1], int(ops[2])*int(ops[1]>>1+1)
			ops = ops[3:]
			payload := bytes.Repeat([]byte{frag}, size)
			_, out, ok := r.add(frag, tgt, payload)
			if ok && (len(out) > 4096 || len(out) > maxDatagram) {
				t.Fatalf("datagram of %d bytes", len(out))
			}
			if u := p.used.Load(); u < 0 || u > total || u > 4096 {
				t.Fatalf("used %d", u)
			}
		}
		r.close()
		if p.used.Load() != 0 {
			t.Fatalf("used %d after close", p.used.Load())
		}
	})
}

// ---- source guard ----

func dialFrom(t *testing.T, src string, addr net.Addr) net.Conn {
	t.Helper()
	d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
	c, e := d.Dial("tcp", addr.String())
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}

// socksTry runs a SOCKS5 username/password handshake from src and reports
// whether authentication succeeded (false also when the server closed the
// connection without answering).
func socksTry(t *testing.T, s *Server, src, pass string) bool {
	t.Helper()
	d := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
	c, e := d.Dial("tcp", s.Addresses()[0].String())
	if errors.Is(e, syscall.ECONNRESET) {
		return false // accept-stage RST may race with connect completion
	}
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if writeAll(c, []byte{5, 1, 2}) != nil {
		return false
	}
	if b, e := readN(c, 2); e != nil || b[1] != 2 {
		return false
	}
	b := append([]byte{1, 4}, "user"...)
	b = append(b, byte(len(pass)))
	b = append(b, pass...)
	if writeAll(c, b) != nil {
		return false
	}
	r, e := readN(c, 2)
	return e == nil && r[1] == 0
}

// refusedAtAccept reports whether a connection from src is closed by the
// server before any byte is exchanged.

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// ---- Trojan fallback ----

func trojanSend(t *testing.T, s *Server, pool *x509.CertPool, data []byte) net.Conn {
	t.Helper()
	cfg := &tls.Config{ServerName: "localhost", MinVersion: tls.VersionTLS12, RootCAs: pool}
	c, e := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.Addresses()[0].String(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { c.Close() })
	if len(data) > 0 {
		writeAll(c, data)
	}
	return c
}

// ---- SOCKS5 BIND ----

// An accepted old-generation handshake must not recreate a ban after a
// reload disabled the feature and emptied the process-wide table.

func TestReassemblyEmptyDuplicatesDoNotFillMissingPositions(t *testing.T) {
	r, p := newTestReassembly(1024, 65535, time.Minute)
	defer r.close()
	a := Address{"127.0.0.1", 9}
	r.add(1, a, nil)
	r.add(1, a, nil)
	if _, _, ok := r.add(0x83, a, []byte("C")); ok {
		t.Fatal("duplicate empty fragment filled missing position 2")
	}
	if _, b, ok := r.add(2, a, []byte("B")); !ok || string(b) != "BC" {
		t.Fatalf("completion %q %v", b, ok)
	}
	if p.used.Load() != 0 || p.reassembled.Load() != 1 || p.dropped.Load() != 1 {
		t.Fatal("incorrect counters after empty duplicate")
	}
}
