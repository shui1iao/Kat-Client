package ss

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

func testOutbound(t *testing.T, method string) *Outbound {
	t.Helper()
	m, ok := lookup(method)
	if !ok {
		t.Fatal(method)
	}
	key := make([]byte, m.keySize)
	rand.Read(key)
	s := &Outbound{name: "t", m: m, key: key, server: outbound.Addr{Host: "127.0.0.1", Port: 1}, now: time.Now}
	var e error
	if m.chacha {
		s.udpX, e = newXChaCha(key)
	} else {
		s.udpBlock, e = newAESBlock(key)
	}
	if e != nil {
		t.Fatal(e)
	}
	return s
}

// SIP022 TCP response checks: request-salt echo and timestamp window.
func TestTCP2022ResponseVerification(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-chacha20-poly1305"} {
		for _, tc := range []struct {
			name    string
			skew    time.Duration
			badSalt bool
			want    error
		}{{"ok", 0, false, nil}, {"stale", -40 * time.Second, false, errTime}, {"future", 40 * time.Second, false, errTime}, {"salt", 0, true, errSalt}} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				s := testOutbound(t, method)
				client, server := net.Pipe()
				defer client.Close()
				defer server.Close()
				c := &tcpConn{Conn: client, s: s, addr: []byte{1, 127, 0, 0, 1, 0, 80}, sentCh: make(chan struct{})}
				go func() {
					req := make([]byte, s.m.keySize)
					if _, e := io.ReadFull(server, req); e != nil {
						return
					}
					go io.Copy(io.Discard, server)
					if tc.badSalt {
						req[0] ^= 1
					}
					salt := make([]byte, s.m.keySize)
					rand.Read(salt)
					a, _ := sessionAEAD(s.m, s.key, salt)
					var n nonce
					h := []byte{1}
					h = binary.BigEndian.AppendUint64(h, uint64(time.Now().Add(tc.skew).Unix()))
					h = append(h, req...)
					h = binary.BigEndian.AppendUint16(h, 5)
					_, n0 := n.next()
					w := a.Seal(salt, n0, h, nil)
					_, n1 := n.next()
					w = a.Seal(w, n1, []byte("hello"), nil)
					server.Write(w)
				}()
				if _, e := c.Write([]byte("ping")); e != nil {
					t.Fatal(e)
				}
				client.SetReadDeadline(time.Now().Add(2 * time.Second))
				b := make([]byte, 16)
				k, e := c.Read(b)
				if tc.want == nil {
					if e != nil || string(b[:k]) != "hello" {
						t.Fatalf("%q %v", b[:k], e)
					}
				} else if !errors.Is(e, tc.want) {
					t.Fatalf("got %v want %v", e, tc.want)
				}
			})
		}
	}
}

// encodeResponse is a test-only SIP022 server-to-client UDP encoder.
func encodeResponse(s *Outbound, serverID, packetID, clientID uint64, stamp time.Time, payload []byte) []byte {
	var header [16]byte
	binary.BigEndian.PutUint64(header[:8], serverID)
	binary.BigEndian.PutUint64(header[8:], packetID)
	body := []byte{1}
	body = binary.BigEndian.AppendUint64(body, uint64(stamp.Unix()))
	body = binary.BigEndian.AppendUint64(body, clientID)
	body = append(body, 0, 3, 9, 9, 9) // 3 bytes padding
	body = append(body, 1, 127, 0, 0, 1, 0, 53)
	body = append(body, payload...)
	if s.m.chacha {
		n := make([]byte, 24)
		rand.Read(n)
		return s.udpX.Seal(n, n, append(header[:], body...), nil)
	}
	a, _ := sessionAEAD(s.m, s.key, header[:8])
	w := make([]byte, 16)
	s.udpBlock.Encrypt(w, header[:])
	return a.Seal(w, header[4:16], body, nil)
}

// SIP022 UDP response checks: client session binding, timestamp window,
// per-server-session replay window, server session change.
func TestUDP2022ResponseVerification(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		t.Run(method, func(t *testing.T) {
			s := testOutbound(t, method)
			p := &udpConn{s: s, session: 77}
			now := time.Now()
			check := func(name string, wire []byte, ok bool) {
				t.Helper()
				src, payload, e := p.decode2022(wire)
				if ok != (e == nil) {
					t.Fatalf("%s: err=%v", name, e)
				}
				if ok && (string(payload) != "pong" || src.Host != "127.0.0.1" || src.Port != 53) {
					t.Fatalf("%s: %q %v", name, payload, src)
				}
			}
			check("valid", encodeResponse(s, 1000, 0, 77, now, []byte("pong")), true)
			check("replay", encodeResponse(s, 1000, 0, 77, now, []byte("pong")), false)
			check("next", encodeResponse(s, 1000, 1, 77, now, []byte("pong")), true)
			check("foreign client session", encodeResponse(s, 1000, 2, 78, now, []byte("pong")), false)
			check("stale timestamp", encodeResponse(s, 1000, 3, 77, now.Add(-31*time.Second), []byte("pong")), false)
			check("future timestamp", encodeResponse(s, 1000, 4, 77, now.Add(31*time.Second), []byte("pong")), false)
			wire := encodeResponse(s, 1000, 5, 77, now, []byte("pong"))
			wire[len(wire)-1] ^= 1
			check("tampered", wire, false)
			check("new server session", encodeResponse(s, 2000, 0, 77, now, []byte("pong")), true)
			check("old session still tracked", encodeResponse(s, 1000, 6, 77, now, []byte("pong")), true)
			check("old session replay", encodeResponse(s, 1000, 1, 77, now, []byte("pong")), false)
			other := testOutbound(t, method)
			check("wrong key", encodeResponse(other, 1000, 7, 77, now, []byte("pong")), false)
		})
	}
}

// --- SS2022 68KiB bufio.Reader & 64KiB record read verification ---

type countingConn struct {
	net.Conn
	readBuf    []byte
	maxPerRead int
	maxWrite   int
	reads      int
	writes     int
	written    []byte
}

func (c *countingConn) Read(p []byte) (int, error) {
	c.reads++
	if len(c.readBuf) == 0 {
		if c.Conn != nil {
			if c.maxPerRead > 0 && len(p) > c.maxPerRead {
				p = p[:c.maxPerRead]
			}
			return c.Conn.Read(p)
		}
		return 0, io.EOF
	}
	limit := len(p)
	if c.maxPerRead > 0 && limit > c.maxPerRead {
		limit = c.maxPerRead
	}
	n := copy(p[:limit], c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes++
	limit := len(p)
	if c.maxWrite > 0 && limit > c.maxWrite {
		limit = c.maxWrite
	}
	c.written = append(c.written, p[:limit]...)
	if c.Conn != nil {
		return c.Conn.Write(p[:limit])
	}
	return limit, nil
}

func buildSS2022ResponseStream(t testing.TB, s *Outbound, reqSalt []byte, chunks [][]byte) []byte {
	t.Helper()
	salt := make([]byte, s.m.keySize)
	if _, e := rand.Read(salt); e != nil {
		t.Fatal(e)
	}
	a, e := sessionAEAD(s.m, s.key, salt)
	if e != nil {
		t.Fatal(e)
	}
	var n nonce
	first := []byte(nil)
	if len(chunks) > 0 {
		first = chunks[0]
		chunks = chunks[1:]
	}
	h := make([]byte, 0, 1+8+s.m.keySize+2)
	h = append(h, 1)
	h = binary.BigEndian.AppendUint64(h, uint64(s.now().Unix()))
	h = append(h, reqSalt...)
	h = binary.BigEndian.AppendUint16(h, uint16(len(first)))

	totalWire := len(salt) + len(h) + tagSize + len(first) + tagSize
	for _, ch := range chunks {
		totalWire += 2 + tagSize + len(ch) + tagSize
	}
	w := make([]byte, 0, totalWire)
	w = append(w, salt...)
	_, n0 := n.next()
	w = a.Seal(w, n0, h, nil)
	_, n1 := n.next()
	w = a.Seal(w, n1, first, nil)
	for _, ch := range chunks {
		var lh [2]byte
		binary.BigEndian.PutUint16(lh[:], uint16(len(ch)))
		_, nh := n.next()
		w = a.Seal(w, nh, lh[:], nil)
		_, np := n.next()
		w = a.Seal(w, np, ch, nil)
	}
	return w
}

func TestTCPReaderBufferSizeByMethod(t *testing.T) {
	for _, m := range []struct {
		name string
		want int
	}{
		{"aes-128-gcm", 32 << 10},
		{"aes-256-gcm", 32 << 10},
		{"chacha20-ietf-poly1305", 32 << 10},
		{"2022-blake3-aes-128-gcm", 68 << 10},
		{"2022-blake3-aes-256-gcm", 68 << 10},
		{"2022-blake3-chacha20-poly1305", 68 << 10},
	} {
		s := testOutbound(t, m.name)
		reqSalt := make([]byte, s.m.keySize)
		rand.Read(reqSalt)
		var wire []byte
		if s.m.v2022 {
			wire = buildSS2022ResponseStream(t, s, reqSalt, [][]byte{[]byte("ok")})
		} else {
			salt := make([]byte, s.m.keySize)
			rand.Read(salt)
			a, _ := sessionAEAD(s.m, s.key, salt)
			var n nonce
			_, n0 := n.next()
			w := a.Seal(salt, n0, []byte{0, 2}, nil)
			_, n1 := n.next()
			wire = a.Seal(w, n1, []byte("ok"), nil)
		}
		cc := &countingConn{readBuf: wire}
		c := &tcpConn{Conn: cc, s: s, sent: true, reqSalt: reqSalt, sentCh: make(chan struct{})}
		close(c.sentCh)
		buf := make([]byte, 8)
		n, e := c.Read(buf)
		if e != nil || string(buf[:n]) != "ok" {
			t.Fatalf("%s: got %q err=%v", m.name, buf[:n], e)
		}
		if got := c.br.Size(); got != m.want {
			t.Fatalf("%s: br.Size() = %d, want %d", m.name, got, m.want)
		}
	}
}

func TestTCP2022MaxRecordReadCallCountReduction(t *testing.T) {
	s := testOutbound(t, "2022-blake3-aes-256-gcm")
	reqSalt := make([]byte, s.m.keySize)
	rand.Read(reqSalt)

	const numRecords = 64
	chunks := make([][]byte, numRecords)
	want := make([]byte, 0, numRecords*maxChunk2022)
	for i := range chunks {
		b := make([]byte, maxChunk2022)
		for j := range b {
			b[j] = byte((i*31 + j) & 0xff)
		}
		chunks[i] = b
		want = append(want, b...)
	}
	wire := buildSS2022ResponseStream(t, s, reqSalt, chunks)

	// 1. Legacy 32KiB bufio.Reader + 32KiB relay copy buffer
	legacyConn := &countingConn{readBuf: wire}
	legacySS := &tcpConn{
		Conn:    legacyConn,
		s:       s,
		sent:    true,
		reqSalt: reqSalt,
		sentCh:  make(chan struct{}),
		br:      bufio.NewReaderSize(legacyConn, 32<<10),
	}
	close(legacySS.sentCh)
	legacyBuf := make([]byte, 32<<10)
	legacyGot := make([]byte, 0, len(want))
	legacyWrites := 0
	for {
		n, e := legacySS.Read(legacyBuf)
		if n > 0 {
			legacyWrites++
			legacyGot = append(legacyGot, legacyBuf[:n]...)
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}

	// 2. Optimized 68KiB bufio.Reader + 64KiB relay copy buffer
	optConn := &countingConn{readBuf: wire}
	optSS := &tcpConn{
		Conn:    optConn,
		s:       s,
		sent:    true,
		reqSalt: reqSalt,
		sentCh:  make(chan struct{}),
	}
	close(optSS.sentCh)
	optBuf := make([]byte, 64<<10)
	optGot := make([]byte, 0, len(want))
	optWrites := 0
	for {
		n, e := optSS.Read(optBuf)
		if n > 0 {
			optWrites++
			optGot = append(optGot, optBuf[:n]...)
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}

	if len(legacyGot) != len(want) || len(optGot) != len(want) {
		t.Fatalf("len mismatch: legacy=%d opt=%d want=%d", len(legacyGot), len(optGot), len(want))
	}
	for i := range want {
		if legacyGot[i] != want[i] || optGot[i] != want[i] {
			t.Fatalf("byte mismatch at %d", i)
		}
	}
	// Legacy splits every 65535B record into 2 Conn.Read and 2 downstream Writes (128 + 1 EOF = 129 reads, 128 writes).
	// Optimized reads <=1 Conn.Read per record (61 + 1 EOF = 62 reads) and 1 downstream Write per record (64 writes).
	t.Logf("64x64KiB records: legacy Conn.Read=%d downstream.Write=%d; optimized Conn.Read=%d downstream.Write=%d",
		legacyConn.reads, legacyWrites, optConn.reads, optWrites)
	if optConn.reads > numRecords+1 || optConn.reads*2 > legacyConn.reads {
		t.Fatalf("expected >=50%% reduction in Conn.Read calls: legacy=%d opt=%d", legacyConn.reads, optConn.reads)
	}
	if optWrites != numRecords || legacyWrites != numRecords*2 {
		t.Fatalf("unexpected downstream Write counts: legacy=%d (want %d), opt=%d (want %d)",
			legacyWrites, numRecords*2, optWrites, numRecords)
	}
}

func TestTCP2022PendingOwnershipShortReadWriteAndSmallStream(t *testing.T) {
	s := testOutbound(t, "2022-blake3-chacha20-poly1305")
	reqSalt := make([]byte, s.m.keySize)
	rand.Read(reqSalt)

	// (a) Small stream returns immediately without waiting for future records or filling 68KiB.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	c := &tcpConn{Conn: client, s: s, addr: []byte{1, 127, 0, 0, 1, 0, 80}, sentCh: make(chan struct{})}
	go func() {
		req := make([]byte, 4096)
		n, e := server.Read(req)
		if e != nil || n < s.m.keySize {
			return
		}
		wire := buildSS2022ResponseStream(t, s, req[:s.m.keySize], [][]byte{[]byte("immediate-small")})
		_, _ = server.Write(wire)
		// Keep server open without sending another record.
		time.Sleep(500 * time.Millisecond)
	}()
	if _, e := c.Write([]byte("hi")); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	smallBuf := make([]byte, 64)
	n, e := c.Read(smallBuf)
	if e != nil || string(smallBuf[:n]) != "immediate-small" {
		t.Fatalf("small read got %q err=%v", smallBuf[:n], e)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("small read blocked for %v", elapsed)
	}

	// (b) Mixed record sizes (including 0-byte, <=hbuf 48B, >hbuf 49B, 32KiB, 65535B)
	// with short underlying reads (517B) and small caller slices (1000B) to exercise
	// pending/rbuf ownership across partial reads.
	sizes := []int{0, 1, 48, 49, 1024, 32768, maxChunk2022, maxChunk2022, 19}
	chunks := make([][]byte, len(sizes))
	var want []byte
	for i, sz := range sizes {
		b := make([]byte, sz)
		for j := range b {
			b[j] = byte((i*17 + j*13 + 7) & 0xff)
		}
		chunks[i] = b
		want = append(want, b...)
	}
	wire := buildSS2022ResponseStream(t, s, reqSalt, chunks)
	shortConn := &countingConn{readBuf: wire, maxPerRead: 517, maxWrite: 409}
	sc := &tcpConn{Conn: shortConn, s: s, addr: []byte{1, 127, 0, 0, 1, 0, 80}, sent: true, reqSalt: reqSalt, sentCh: make(chan struct{})}
	close(sc.sentCh)

	// Also verify short writes on Write() path.
	sc.enc, _ = sessionAEAD(s.m, s.key, reqSalt)
	writePayload := make([]byte, 70000)
	rand.Read(writePayload)
	if wn, we := sc.Write(writePayload); we != nil || wn != len(writePayload) {
		t.Fatalf("short write failed: wn=%d err=%v", wn, we)
	}

	var slices [][]byte
	for {
		// Allocate a fresh slice and keep all slices alive to ensure subsequent readRecord()
		// reusing rbuf/hbuf never mutates already-returned caller data.
		p := make([]byte, 1000)
		rn, re := sc.Read(p)
		if rn > 0 {
			slices = append(slices, p[:rn:rn])
		}
		if re == io.EOF {
			break
		}
		if re != nil {
			t.Fatal(re)
		}
	}
	var got []byte
	for _, sl := range slices {
		got = append(got, sl...)
	}
	if len(got) != len(want) {
		t.Fatalf("mixed read len=%d want=%d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("mixed read mismatch at %d: got %d want %d", i, got[i], want[i])
		}
	}
}

func TestTCP2022NonceAEADFailureAndEOFBoundaries(t *testing.T) {
	s := testOutbound(t, "2022-blake3-aes-128-gcm")
	reqSalt := make([]byte, s.m.keySize)
	rand.Read(reqSalt)
	wire := buildSS2022ResponseStream(t, s, reqSalt, [][]byte{[]byte("first"), []byte("second")})

	newConn := func(b []byte) *tcpConn {
		cc := &countingConn{readBuf: append([]byte(nil), b...)}
		c := &tcpConn{Conn: cc, s: s, sent: true, reqSalt: reqSalt, sentCh: make(chan struct{})}
		close(c.sentCh)
		return c
	}

	// 1. Truncated salt -> ErrUnexpectedEOF
	c := newConn(wire[:5])
	if _, e := c.Read(make([]byte, 16)); !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated salt: got %v want ErrUnexpectedEOF", e)
	}
	// 2. EOF right after salt -> ErrUnexpectedEOF
	c = newConn(wire[:s.m.keySize])
	if _, e := c.Read(make([]byte, 16)); !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatalf("EOF after salt: got %v want ErrUnexpectedEOF", e)
	}
	// 3. Truncated first payload -> ErrUnexpectedEOF
	firstEnd := s.m.keySize + (1 + 8 + s.m.keySize + 2 + tagSize) + 5 + tagSize
	c = newConn(wire[:firstEnd-3])
	if _, e := c.Read(make([]byte, 16)); !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated first payload: got %v want ErrUnexpectedEOF", e)
	}
	// 4. Clean EOF after first record -> io.EOF
	c = newConn(wire[:firstEnd])
	buf := make([]byte, 16)
	if n, e := c.Read(buf); e != nil || string(buf[:n]) != "first" {
		t.Fatalf("first record: %q %v", buf[:n], e)
	}
	if _, e := c.Read(buf); !errors.Is(e, io.EOF) {
		t.Fatalf("clean EOF after first record: got %v want io.EOF", e)
	}
	// 5. Truncated second record length header -> ErrUnexpectedEOF
	c = newConn(wire[:firstEnd+7])
	_, _ = c.Read(buf)
	if _, e := c.Read(buf); !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated second header: got %v want ErrUnexpectedEOF", e)
	}
	// 6. Tampered second record payload tag -> errAuth, sticky rerr, nil pending/rbuf
	bad := append([]byte(nil), wire...)
	bad[len(bad)-1] ^= 0x80
	c = newConn(bad)
	_, _ = c.Read(buf)
	if _, e := c.Read(buf); !errors.Is(e, errAuth) {
		t.Fatalf("tampered payload: got %v want errAuth", e)
	}
	if c.pending != nil || c.rbuf != nil {
		t.Fatalf("buffers not cleared on error: pending=%v rbuf=%v", c.pending, c.rbuf)
	}
	if _, e := c.Read(buf); !errors.Is(e, errAuth) {
		t.Fatalf("sticky rerr: got %v want errAuth", e)
	}
	// 7. Swapped encrypted records (nonce mismatch) -> errAuth
	rec2HeaderAndPayload := wire[firstEnd:]
	dupWire := append(append([]byte(nil), wire...), rec2HeaderAndPayload...)
	c = newConn(dupWire)
	_, _ = c.Read(buf)
	_, _ = c.Read(buf)
	if _, e := c.Read(buf); !errors.Is(e, errAuth) {
		t.Fatalf("replayed record with wrong nonce: got %v want errAuth", e)
	}
	// 8. Nonce exhaustion -> errExhaust
	c = newConn(wire)
	c.rdead = true
	if _, e := c.open(make([]byte, tagSize)); !errors.Is(e, errExhaust) {
		t.Fatalf("rdead open: got %v want errExhaust", e)
	}
}

func BenchmarkTCP2022Read64K(b *testing.B) {
	s := testOutbound(&testing.T{}, "2022-blake3-aes-128-gcm")
	reqSalt := make([]byte, s.m.keySize)
	rand.Read(reqSalt)
	payload := make([]byte, maxChunk2022)
	rand.Read(payload)
	wire := buildSS2022ResponseStream(&testing.T{}, s, reqSalt, [][]byte{payload, payload, payload, payload})
	dst := make([]byte, 64<<10)

	b.SetBytes(int64(4 * maxChunk2022))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cc := &countingConn{readBuf: wire}
		c := &tcpConn{Conn: cc, s: s, sent: true, reqSalt: reqSalt, sentCh: make(chan struct{})}
		close(c.sentCh)
		for {
			_, e := c.Read(dst)
			if e == io.EOF {
				break
			}
			if e != nil {
				b.Fatal(e)
			}
		}
	}
}


// --- SS2022 64KiB upload boundary & record balancing verification ---

type writeTraceConn struct {
	net.Conn
	maxWrite    int
	failAtWrite int
	failErr     error
	deadlineErr error
	writeSizes  []int
	written     bytes.Buffer
	closed      bool
	closeWrites int
}

func (c *writeTraceConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	if c.deadlineErr != nil {
		return 0, c.deadlineErr
	}
	nextCall := len(c.writeSizes) + 1
	if c.failAtWrite > 0 && nextCall >= c.failAtWrite {
		err := c.failErr
		if err == nil {
			err = io.ErrClosedPipe
		}
		// Allow optional partial write before failing when maxWrite > 0.
		if c.maxWrite > 0 && len(p) > c.maxWrite {
			n := c.maxWrite
			c.writeSizes = append(c.writeSizes, n)
			_, _ = c.written.Write(p[:n])
			return n, err
		}
		c.writeSizes = append(c.writeSizes, 0)
		return 0, err
	}
	limit := len(p)
	if c.maxWrite > 0 && limit > c.maxWrite {
		limit = c.maxWrite
	}
	c.writeSizes = append(c.writeSizes, limit)
	_, _ = c.written.Write(p[:limit])
	return limit, nil
}

func (c *writeTraceConn) Close() error {
	c.closed = true
	return nil
}

func (c *writeTraceConn) CloseWrite() error {
	c.closeWrites++
	return nil
}

func (c *writeTraceConn) SetWriteDeadline(d time.Time) error {
	if !d.IsZero() && !d.After(time.Now()) {
		c.deadlineErr = context.DeadlineExceeded
	} else {
		c.deadlineErr = nil
	}
	return nil
}

type decodedSS2022Request struct {
	salt             []byte
	addr             outbound.Addr
	paddingLen       int
	plaintextRecords []int
	cipherRecords    []int
	sealCalls        int
	payload          []byte
}

func decodeSS2022RequestStream(t testing.TB, s *Outbound, wire []byte) decodedSS2022Request {
	t.Helper()
	if len(wire) < s.m.keySize+11+tagSize {
		t.Fatalf("wire too short: %d", len(wire))
	}
	var out decodedSS2022Request
	out.salt = append([]byte(nil), wire[:s.m.keySize]...)
	rest := wire[s.m.keySize:]
	a, e := sessionAEAD(s.m, s.key, out.salt)
	if e != nil {
		t.Fatal(e)
	}
	var n nonce
	_, n0 := n.next()
	fixed, e := a.Open(nil, n0, rest[:11+tagSize], nil)
	if e != nil {
		t.Fatalf("open fixed header: %v", e)
	}
	out.sealCalls++
	rest = rest[11+tagSize:]
	if fixed[0] != 0 {
		t.Fatalf("unexpected header type %d", fixed[0])
	}
	varLen := int(binary.BigEndian.Uint16(fixed[9:11]))
	if len(rest) < varLen+tagSize {
		t.Fatalf("truncated variable header: have %d need %d", len(rest), varLen+tagSize)
	}
	_, n1 := n.next()
	variable, e := a.Open(nil, n1, rest[:varLen+tagSize], nil)
	if e != nil {
		t.Fatalf("open variable header: %v", e)
	}
	out.sealCalls++
	rest = rest[varLen+tagSize:]
	addr, addrEnd, e := parseAddr(variable)
	if e != nil {
		t.Fatalf("parseAddr: %v", e)
	}
	out.addr = addr
	if len(variable) < addrEnd+2 {
		t.Fatalf("variable header missing padding length")
	}
	padLen := int(binary.BigEndian.Uint16(variable[addrEnd : addrEnd+2]))
	out.paddingLen = padLen
	payloadStart := addrEnd + 2 + padLen
	if len(variable) < payloadStart {
		t.Fatalf("variable header shorter than padding: %d < %d", len(variable), payloadStart)
	}
	firstPayload := variable[payloadStart:]
	out.plaintextRecords = append(out.plaintextRecords, len(firstPayload))
	out.cipherRecords = append(out.cipherRecords, len(out.salt)+(11+tagSize)+(varLen+tagSize))
	out.payload = append(out.payload, firstPayload...)

	for len(rest) > 0 {
		if len(rest) < 2+tagSize {
			t.Fatalf("truncated record length header: %d", len(rest))
		}
		_, nh := n.next()
		lh, e := a.Open(nil, nh, rest[:2+tagSize], nil)
		if e != nil {
			t.Fatalf("open record length header: %v", e)
		}
		out.sealCalls++
		rest = rest[2+tagSize:]
		recLen := int(binary.BigEndian.Uint16(lh))
		if len(rest) < recLen+tagSize {
			t.Fatalf("truncated record payload: have %d need %d", len(rest), recLen+tagSize)
		}
		_, np := n.next()
		p, e := a.Open(nil, np, rest[:recLen+tagSize], nil)
		if e != nil {
			t.Fatalf("open record payload: %v", e)
		}
		out.sealCalls++
		rest = rest[recLen+tagSize:]
		out.plaintextRecords = append(out.plaintextRecords, recLen)
		out.cipherRecords = append(out.cipherRecords, (2+tagSize)+(recLen+tagSize))
		out.payload = append(out.payload, p...)
	}
	return out
}

type decodedSS2017Request struct {
	salt             []byte
	addr             outbound.Addr
	plaintextRecords []int
	cipherRecords    []int
	sealCalls        int
	payload          []byte
}

func decodeSS2017RequestStream(t testing.TB, s *Outbound, wire []byte) decodedSS2017Request {
	t.Helper()
	if len(wire) < s.m.keySize {
		t.Fatalf("wire too short: %d", len(wire))
	}
	var out decodedSS2017Request
	out.salt = append([]byte(nil), wire[:s.m.keySize]...)
	rest := wire[s.m.keySize:]
	a, e := sessionAEAD(s.m, s.key, out.salt)
	if e != nil {
		t.Fatal(e)
	}
	var n nonce
	var stream []byte
	for len(rest) > 0 {
		if len(rest) < 2+tagSize {
			t.Fatalf("truncated 2017 length header: %d", len(rest))
		}
		_, nh := n.next()
		lh, e := a.Open(nil, nh, rest[:2+tagSize], nil)
		if e != nil {
			t.Fatalf("open 2017 length header: %v", e)
		}
		out.sealCalls++
		rest = rest[2+tagSize:]
		recLen := int(binary.BigEndian.Uint16(lh))
		if recLen > maxChunk2017 {
			t.Fatalf("2017 record length %d > maxChunk2017 %d", recLen, maxChunk2017)
		}
		if len(rest) < recLen+tagSize {
			t.Fatalf("truncated 2017 payload: have %d need %d", len(rest), recLen+tagSize)
		}
		_, np := n.next()
		p, e := a.Open(nil, np, rest[:recLen+tagSize], nil)
		if e != nil {
			t.Fatalf("open 2017 payload: %v", e)
		}
		out.sealCalls++
		rest = rest[recLen+tagSize:]
		out.plaintextRecords = append(out.plaintextRecords, recLen)
		out.cipherRecords = append(out.cipherRecords, (2+tagSize)+(recLen+tagSize))
		stream = append(stream, p...)
	}
	addr, end, e := parseAddr(stream)
	if e != nil {
		t.Fatalf("parseAddr 2017: %v", e)
	}
	out.addr = addr
	out.payload = stream[end:]
	return out
}

func formatSizeHist(sizes []int) string {
	counts := map[int]int{}
	var keys []int
	for _, sz := range sizes {
		if counts[sz] == 0 {
			keys = append(keys, sz)
		}
		counts[sz]++
	}
	sort.Sort(sort.Reverse(sort.IntSlice(keys)))
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%dB*%d", k, counts[k]))
	}
	return strings.Join(parts, ", ")
}

// simulateLegacySS2022Write reproduces the pre-fix (abcf996) Write loop where
// header(p) is flushed separately and subsequent chunks use batch = 4*maxChunk2017 (65532)
// and greedily seal min(len(p), maxChunk2022).
func simulateLegacySS2022Write(c *tcpConn, p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	total := 0
	if !c.sent {
		w, n, e := c.header(p)
		if e == nil {
			e = writeFull(c.Conn, w)
		}
		if e != nil {
			c.werr = e
			return 0, e
		}
		c.sent = true
		close(c.sentCh)
		total, p = n, p[n:]
	}
	const legacyBatch = 4 * maxChunk2017
	for len(p) > 0 {
		n := min(len(p), legacyBatch)
		need := n + (n/maxChunk2017+1)*(2+2*tagSize)
		if cap(c.wbuf) < need {
			c.wbuf = make([]byte, 0, need)
		}
		w := c.wbuf[:0]
		rem := p[:n]
		var e error
		for len(rem) > 0 {
			chunk := min(len(rem), c.maxChunk())
			if w, e = c.seal(w, []byte{byte(chunk >> 8), byte(chunk)}); e != nil {
				break
			}
			if w, e = c.seal(w, rem[:chunk]); e != nil {
				break
			}
			rem = rem[chunk:]
		}
		if e == nil {
			e = writeFull(c.Conn, w)
		}
		if e != nil {
			c.werr = e
			c.wbuf = nil
			return total, e
		}
		total += n
		p = p[n:]
	}
	return total, nil
}

func TestTCP2022Upload8MiBModelComparison(t *testing.T) {
	s := testOutbound(t, "2022-blake3-aes-256-gcm")
	const totalBytes = 8 << 20 // 8 MiB
	payload := make([]byte, totalBytes)
	for i := range payload {
		payload[i] = byte((i*131 + 17) & 0xff)
	}
	addr := []byte{1, 127, 0, 0, 1, 0, 80} // IPv4 127.0.0.1:80 (7B)

	// Model 1: Control 32KiB relay writes (256 x 32768B)
	conn32 := &writeTraceConn{}
	ss32 := &tcpConn{Conn: conn32, s: s, addr: addr, sentCh: make(chan struct{})}
	ss32Calls := 0
	for off := 0; off < len(payload); off += 32 << 10 {
		ss32Calls++
		n, e := simulateLegacySS2022Write(ss32, payload[off:off+(32<<10)])
		if e != nil || n != 32<<10 {
			t.Fatalf("32KiB model write failed at %d: n=%d err=%v", off, n, e)
		}
	}
	dec32 := decodeSS2022RequestStream(t, s, conn32.written.Bytes())

	// Model 2: First candidate (abcf996) 64KiB relay writes with legacy 65532 batch (128 x 65536B)
	connCand1 := &writeTraceConn{}
	ssCand1 := &tcpConn{Conn: connCand1, s: s, addr: addr, sentCh: make(chan struct{})}
	ssCand1Calls := 0
	for off := 0; off < len(payload); off += 64 << 10 {
		ssCand1Calls++
		n, e := simulateLegacySS2022Write(ssCand1, payload[off:off+(64<<10)])
		if e != nil || n != 64<<10 {
			t.Fatalf("cand1 64KiB model write failed at %d: n=%d err=%v", off, n, e)
		}
	}
	decCand1 := decodeSS2022RequestStream(t, s, connCand1.written.Bytes())

	// Model 3: Repaired SS2022 64KiB relay writes (128 x 65536B)
	connFixed := &writeTraceConn{}
	ssFixed := &tcpConn{Conn: connFixed, s: s, addr: addr, sentCh: make(chan struct{})}
	ssFixedCalls := 0
	for off := 0; off < len(payload); off += 64 << 10 {
		ssFixedCalls++
		n, e := ssFixed.Write(payload[off : off+(64<<10)])
		if e != nil || n != 64<<10 {
			t.Fatalf("fixed 64KiB model write failed at %d: n=%d err=%v", off, n, e)
		}
	}
	decFixed := decodeSS2022RequestStream(t, s, connFixed.written.Bytes())

	if !bytes.Equal(dec32.payload, payload) || !bytes.Equal(decCand1.payload, payload) || !bytes.Equal(decFixed.payload, payload) {
		t.Fatal("decrypted 8MiB payload mismatch across models")
	}

	t.Logf("8MiB Model 1 (Old 32KiB): ss.Write=%d, underlying Conn.Write=%d [%s], records=%d [%s], cipherRecords=[%s], seal=%d, wireBytes=%d",
		ss32Calls, len(conn32.writeSizes), formatSizeHist(conn32.writeSizes),
		len(dec32.plaintextRecords), formatSizeHist(dec32.plaintextRecords), formatSizeHist(dec32.cipherRecords),
		dec32.sealCalls, conn32.written.Len())
	t.Logf("8MiB Model 2 (Cand1 65536 pre-fix): ss.Write=%d, underlying Conn.Write=%d [%s], records=%d [%s], cipherRecords=[%s], seal=%d, wireBytes=%d",
		ssCand1Calls, len(connCand1.writeSizes), formatSizeHist(connCand1.writeSizes),
		len(decCand1.plaintextRecords), formatSizeHist(decCand1.plaintextRecords), formatSizeHist(decCand1.cipherRecords),
		decCand1.sealCalls, connCand1.written.Len())
	t.Logf("8MiB Model 3 (Fixed 65536): ss.Write=%d, underlying Conn.Write=%d [%s], records=%d [%s], cipherRecords=[%s], seal=%d, wireBytes=%d",
		ssFixedCalls, len(connFixed.writeSizes), formatSizeHist(connFixed.writeSizes),
		len(decFixed.plaintextRecords), formatSizeHist(decFixed.plaintextRecords), formatSizeHist(decFixed.cipherRecords),
		decFixed.sealCalls, connFixed.written.Len())

	// Verify exact counts and distributions
	if len(conn32.writeSizes) != 256 || len(dec32.plaintextRecords) != 256 {
		t.Fatalf("unexpected 32KiB model counts: writes=%d records=%d", len(conn32.writeSizes), len(dec32.plaintextRecords))
	}
	if len(connCand1.writeSizes) != 256 || len(decCand1.plaintextRecords) != 256 {
		t.Fatalf("unexpected cand1 model counts: writes=%d records=%d", len(connCand1.writeSizes), len(decCand1.plaintextRecords))
	}
	if len(connFixed.writeSizes) != 128 || len(decFixed.plaintextRecords) != 256 {
		t.Fatalf("unexpected fixed model counts: writes=%d (want 128) records=%d (want 256)", len(connFixed.writeSizes), len(decFixed.plaintextRecords))
	}
	// First underlying Conn.Write in fixed model merges header(65526B) + tail(10B) = 65610 + 44 = 65654B
	if connFixed.writeSizes[0] != 65654 {
		t.Fatalf("fixed first underlying Conn.Write = %d, want 65654", connFixed.writeSizes[0])
	}
	// All 127 steady-state Writes in fixed model are single 65604B Conn.Write containing two 32768B plaintext records (32802B ciphertext each)
	for i := 1; i < len(connFixed.writeSizes); i++ {
		if connFixed.writeSizes[i] != 65604 {
			t.Fatalf("fixed underlying Conn.Write[%d] = %d, want 65604", i, connFixed.writeSizes[i])
		}
	}
	for i := 2; i < len(decFixed.plaintextRecords); i++ {
		if decFixed.plaintextRecords[i] != 32768 || decFixed.cipherRecords[i] != 32802 {
			t.Fatalf("fixed record[%d] plaintext=%d cipher=%d, want 32768 / 32802",
				i, decFixed.plaintextRecords[i], decFixed.cipherRecords[i])
		}
	}
}

func TestTCP2022SingleStreamWriteSizesAndHeaderSemantics(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"} {
		t.Run(method, func(t *testing.T) {
			s := testOutbound(t, method)

			// 1. Header-only (ensureSent / CloseWrite before Write): must have random padding in [1, maxPadding]
			hc := &writeTraceConn{}
			c0 := &tcpConn{Conn: hc, s: s, addr: []byte{1, 10, 0, 0, 1, 1, 187}, sentCh: make(chan struct{})}
			if e := c0.CloseWrite(); e != nil {
				t.Fatalf("CloseWrite: %v", e)
			}
			dec0 := decodeSS2022RequestStream(t, s, hc.written.Bytes())
			if dec0.paddingLen < 1 || dec0.paddingLen > maxPadding || len(dec0.payload) != 0 || dec0.addr.Host != "10.0.0.1" || dec0.addr.Port != 443 {
				t.Fatalf("header-only semantics broken: pad=%d payload=%d addr=%v", dec0.paddingLen, len(dec0.payload), dec0.addr)
			}

			// 2. Single stream exercising 1B, 32KiB, 65535B, 65536B, and large Write (200000B)
			// across IPv4, IPv6, and domain target addresses.
			addrs := []outbound.Addr{
				{Host: "127.0.0.1", Port: 8080},
				{Host: "2001:db8::1", Port: 443},
				{Host: "sub.example.com", Port: 8443},
			}
			writeSizes := []int{1, 32 << 10, 65535, 65536, 200000}
			for _, dst := range addrs {
				rawAddr, e := appendAddr(nil, dst)
				if e != nil {
					t.Fatal(e)
				}
				// Log steady-state per-Write call & record sizes for 1B, 32KiB, 65535B, 65536B, 200000B
				if dst.Host == "127.0.0.1" && method == "2022-blake3-aes-256-gcm" {
					for _, sz := range writeSizes {
						tc1 := &writeTraceConn{}
						conn1 := &tcpConn{Conn: tc1, s: s, addr: rawAddr, sentCh: make(chan struct{})}
						b0 := make([]byte, sz)
						_, _ = conn1.Write(b0)
						w0 := append([]int(nil), tc1.writeSizes...)
						_, _ = conn1.Write(b0)
						w1 := append([]int(nil), tc1.writeSizes[len(w0):]...)
						dec1 := decodeSS2022RequestStream(t, s, tc1.written.Bytes())
						t.Logf("SS2022 Write(%dB) [IPv4]: 1st Write Conn.Write=%v, 2nd(steady) Write Conn.Write=%v; all plaintextRecords=%v cipherRecords=%v",
							sz, w0, w1, dec1.plaintextRecords, dec1.cipherRecords)
					}
				}
				// Test each write size as both first Write and steady-state Write on a single stream
				for _, firstSize := range writeSizes {
					tc := &writeTraceConn{}
					conn := &tcpConn{Conn: tc, s: s, addr: rawAddr, sentCh: make(chan struct{})}
					var want []byte
					seq := append([]int{firstSize}, writeSizes...)
					for step, sz := range seq {
						buf := make([]byte, sz)
						for i := range buf {
							buf[i] = byte((step*53 + i*19 + sz) & 0xff)
						}
						beforeWrites := len(tc.writeSizes)
						n, e := conn.Write(buf)
						if e != nil || n != sz {
							t.Fatalf("dst=%v first=%d step=%d sz=%d: n=%d err=%v", dst, firstSize, step, sz, n, e)
						}
						deltaWrites := len(tc.writeSizes) - beforeWrites
						// Any Write <= 64KiB (including first Write and steady-state 1B/32KiB/65535/65536)
						// must complete in exactly 1 underlying Conn.Write!
						if sz <= 64<<10 && deltaWrites != 1 {
							t.Fatalf("dst=%v first=%d step=%d sz=%d: deltaWrites=%d, want 1", dst, firstSize, step, sz, deltaWrites)
						}
						want = append(want, buf...)
					}
					dec := decodeSS2022RequestStream(t, s, tc.written.Bytes())
					if dec.addr != dst {
						t.Fatalf("decoded addr=%v, want %v", dec.addr, dst)
					}
					if dec.paddingLen != 0 {
						t.Fatalf("non-empty first write had padding=%d, want 0", dec.paddingLen)
					}
					if !bytes.Equal(dec.payload, want) {
						t.Fatalf("dst=%v first=%d: payload mismatch (got %d, want %d)", dst, firstSize, len(dec.payload), len(want))
					}
				}
			}
		})
	}
}

func TestTCP2017WriteCallsAndRecordsUnchanged(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		t.Run(method, func(t *testing.T) {
			s := testOutbound(t, method)
			addr := []byte{1, 127, 0, 0, 1, 0, 80} // 7B
			tc := &writeTraceConn{}
			conn := &tcpConn{Conn: tc, s: s, addr: addr, sentCh: make(chan struct{})}

			// 1st Write: 65536B -> header(p) packs salt + 5 records (4*16383 + 7 + 4 = 65543B) in 1 Conn.Write
			p1 := make([]byte, 65536)
			rand.Read(p1)
			if n, e := conn.Write(p1); e != nil || n != len(p1) {
				t.Fatalf("first 2017 Write: n=%d err=%v", n, e)
			}
			if len(tc.writeSizes) != 1 {
				t.Fatalf("first 2017 Write underlying calls = %d, want 1", len(tc.writeSizes))
			}

			// 2nd Write (steady-state): 65536B -> must still use writeBatch2017 = 4*16383 = 65532B:
			// batch 1: 4*16383B (4 records, 65668B wire) + batch 2: 4B (1 record, 38B wire)
			p2 := make([]byte, 65536)
			rand.Read(p2)
			if n, e := conn.Write(p2); e != nil || n != len(p2) {
				t.Fatalf("second 2017 Write: n=%d err=%v", n, e)
			}
			if len(tc.writeSizes) != 3 || tc.writeSizes[1] != 4*(maxChunk2017+2+2*tagSize) || tc.writeSizes[2] != 4+2+2*tagSize {
				t.Fatalf("2017 steady-state writeSizes = %v, want [first, 65668, 38]", tc.writeSizes)
			}

			// 3rd Write: 32768B -> 1 Conn.Write with records 16383, 16383, 2
			p3 := make([]byte, 32768)
			rand.Read(p3)
			if n, e := conn.Write(p3); e != nil || n != len(p3) {
				t.Fatalf("third 2017 Write: n=%d err=%v", n, e)
			}
			if len(tc.writeSizes) != 4 {
				t.Fatalf("third 2017 Write underlying calls = %d, want 4", len(tc.writeSizes))
			}

			dec := decodeSS2017RequestStream(t, s, tc.written.Bytes())
			wantPayload := append(append(append([]byte(nil), p1...), p2...), p3...)
			if !bytes.Equal(dec.payload, wantPayload) {
				t.Fatalf("2017 decoded payload mismatch")
			}
			wantRecs := []int{
				16383, 16383, 16383, 16383, 11, // 1st Write (7B addr + 65536B = 65543B)
				16383, 16383, 16383, 16383, 4,  // 2nd Write (65532B + 4B)
				16383, 16383, 2,                // 3rd Write (32768B)
			}
			if len(dec.plaintextRecords) != len(wantRecs) {
				t.Fatalf("2017 records = %v, want %v", dec.plaintextRecords, wantRecs)
			}
			for i := range wantRecs {
				if dec.plaintextRecords[i] != wantRecs[i] {
					t.Fatalf("2017 record[%d] = %d, want %d", i, dec.plaintextRecords[i], wantRecs[i])
				}
			}
			t.Logf("SS2017 (%s) preserved: Conn.Write sizes=%v, plaintextRecords=%v, cipherRecords=%v",
				method, tc.writeSizes, dec.plaintextRecords, dec.cipherRecords)
		})
	}
}

func TestTCP2022WriteShortWriteFailureCloseDeadlineAndNonceBoundaries(t *testing.T) {
	s := testOutbound(t, "2022-blake3-aes-256-gcm")
	addr := []byte{1, 127, 0, 0, 1, 0, 80}

	// 1. Short writes on underlying Conn across first 64KiB Write and subsequent 64KiB / large Writes
	shortUnderlying := &writeTraceConn{maxWrite: 1337}
	connShort := &tcpConn{Conn: shortUnderlying, s: s, addr: addr, sentCh: make(chan struct{})}
	p64 := make([]byte, 65536)
	rand.Read(p64)
	pLarge := make([]byte, 150000)
	rand.Read(pLarge)
	if n, e := connShort.Write(p64); e != nil || n != len(p64) {
		t.Fatalf("first 64KiB over short writer: n=%d err=%v", n, e)
	}
	if n, e := connShort.Write(p64); e != nil || n != len(p64) {
		t.Fatalf("second 64KiB over short writer: n=%d err=%v", n, e)
	}
	if n, e := connShort.Write(pLarge); e != nil || n != len(pLarge) {
		t.Fatalf("large write over short writer: n=%d err=%v", n, e)
	}
	decShort := decodeSS2022RequestStream(t, s, shortUnderlying.written.Bytes())
	wantShort := append(append(append([]byte(nil), p64...), p64...), pLarge...)
	if !bytes.Equal(decShort.payload, wantShort) {
		t.Fatal("short writer decrypted payload mismatch")
	}

	// 2. First Write failure returns (0, err), sets sticky werr, does not mark sent
	failFirst := &writeTraceConn{maxWrite: 1000, failAtWrite: 2, failErr: io.ErrClosedPipe}
	connFail1 := &tcpConn{Conn: failFirst, s: s, addr: addr, sentCh: make(chan struct{})}
	if n, e := connFail1.Write(p64); !errors.Is(e, io.ErrClosedPipe) || n != 0 {
		t.Fatalf("first Write failure: n=%d err=%v, want 0, ErrClosedPipe", n, e)
	}
	if connFail1.sent {
		t.Fatal("connFail1.sent should be false after failed first Write")
	}
	if n, e := connFail1.Write([]byte("retry")); !errors.Is(e, io.ErrClosedPipe) || n != 0 {
		t.Fatalf("sticky werr after first Write failure: n=%d err=%v", n, e)
	}

	// 3. Multi-batch large Write failure on 2nd batch returns (65536, err), sets sticky werr, clears wbuf
	failBatch2 := &writeTraceConn{failAtWrite: 3, failErr: io.ErrClosedPipe}
	connFail2 := &tcpConn{Conn: failBatch2, s: s, addr: addr, sentCh: make(chan struct{})}
	if n, e := connFail2.Write([]byte("init")); e != nil || n != 4 {
		t.Fatalf("init write: n=%d err=%v", n, e)
	}
	// Next Write of 150000B runs batch 1 (65536B -> Conn.Write #2 succeeds) then batch 2 (65536B -> Conn.Write #3 fails)
	if n, e := connFail2.Write(pLarge); !errors.Is(e, io.ErrClosedPipe) || n != 65536 {
		t.Fatalf("batch 2 failure: got n=%d err=%v, want n=65536 ErrClosedPipe", n, e)
	}
	if connFail2.wbuf != nil {
		t.Fatal("wbuf should be cleared on Write error")
	}
	if n, e := connFail2.Write([]byte("after")); !errors.Is(e, io.ErrClosedPipe) || n != 0 {
		t.Fatalf("sticky werr after batch 2 failure: n=%d err=%v", n, e)
	}

	// 4. Write deadline and Close propagation
	dlConn := &writeTraceConn{}
	connDL := &tcpConn{Conn: dlConn, s: s, addr: addr, sentCh: make(chan struct{})}
	_ = connDL.SetWriteDeadline(time.Now().Add(-time.Second))
	if n, e := connDL.Write([]byte("timeout")); !errors.Is(e, context.DeadlineExceeded) || n != 0 {
		t.Fatalf("expired deadline Write: n=%d err=%v", n, e)
	}
	clConn := &writeTraceConn{}
	connCL := &tcpConn{Conn: clConn, s: s, addr: addr, sentCh: make(chan struct{})}
	_ = connCL.Close()
	if n, e := connCL.Write([]byte("closed")); !errors.Is(e, net.ErrClosed) || n != 0 {
		t.Fatalf("closed Write: n=%d err=%v", n, e)
	}

	// 5. Nonce exhaustion boundary on Write path:
	// (a) Exhausting during first Write header+tail merge -> returns (0, errExhaust)
	nonceConn1 := &writeTraceConn{}
	connN1 := &tcpConn{Conn: nonceConn1, s: s, addr: addr, sentCh: make(chan struct{})}
	for i := range connN1.wn {
		connN1.wn[i] = 0xff
	}
	connN1.wn[0] = 0xfd // 3 nonces left: fixed(1), variable(2), tail length(3 -> exhausts), tail payload(4 -> fails with errExhaust)
	if n, e := connN1.Write(p64); !errors.Is(e, errExhaust) || n != 0 {
		t.Fatalf("nonce exhaustion in first 64KiB Write: n=%d err=%v, want 0, errExhaust", n, e)
	}
	if len(nonceConn1.writeSizes) != 0 {
		t.Fatalf("expected 0 underlying writes when seal fails in first Write, got %d", len(nonceConn1.writeSizes))
	}

	// (b) Exhausting on steady-state balanced 64KiB Write (requires 4 seal calls)
	nonceConn2 := &writeTraceConn{}
	connN2 := &tcpConn{Conn: nonceConn2, s: s, addr: addr, sentCh: make(chan struct{})}
	if _, e := connN2.Write([]byte("ok")); e != nil {
		t.Fatal(e)
	}
	for i := range connN2.wn {
		connN2.wn[i] = 0xff
	}
	connN2.wn[0] = 0xfd // 3 nonces left; 4th seal in balanced 64KiB Write must fail with errExhaust
	if n, e := connN2.Write(p64); !errors.Is(e, errExhaust) || n != 0 {
		t.Fatalf("nonce exhaustion in steady-state 64KiB Write: n=%d err=%v, want 0, errExhaust", n, e)
	}
}
