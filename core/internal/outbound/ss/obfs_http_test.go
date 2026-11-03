package ss

import (
	"bufio"
	"bytes"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type obfsMemory struct {
	net.Conn
	in    io.Reader
	out   bytes.Buffer
	chunk int
	fail  bool
	half  bool
}

func (m *obfsMemory) Write(p []byte) (int, error) {
	if m.fail {
		return 0, io.ErrClosedPipe
	}
	if m.chunk > 0 && len(p) > m.chunk {
		p = p[:m.chunk]
	}
	return m.out.Write(p)
}
func (m *obfsMemory) Read(p []byte) (int, error) { return m.in.Read(p) }
func (m *obfsMemory) CloseWrite() error          { m.half = true; return nil }
func TestObfsHTTPIndependentWire(t *testing.T) {
	// Independent net/http request parser enforces Content-Length (also required
	// by mihomo NewHTTPObfsServer); ciphertext bytes are NOT websocket frames.
	m := &obfsMemory{chunk: 3}
	c := &obfsHTTPConn{Conn: m, host: "example.com"}
	payload := []byte{0, 255, 2, 3, 0, 5}
	if n, e := c.Write(payload); e != nil || n != len(payload) {
		t.Fatal("first write")
	}
	if bytes.Count(m.out.Bytes(), []byte("Content-Length:")) != 1 {
		t.Fatal("duplicate content length")
	}
	r, e := http.ReadRequest(bufio.NewReader(bytes.NewReader(m.out.Bytes())))
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(r.Body)
	if e != nil || r.Method != "GET" || r.Host != "example.com" || r.Header.Get("Connection") != "Upgrade" || r.Header.Get("Upgrade") != "websocket" || !bytes.Equal(b, payload) {
		t.Fatal("independent wire mismatch")
	}
	before := m.out.Len()
	c.Write([]byte("next"))
	if m.out.String()[before:] != "nex" {
		t.Fatal("partial subsequent write")
	}
	if c.CloseWrite() != nil || !m.half {
		t.Fatal("half-close")
	}
	// Fragmented header followed by ciphertext in the same read; no swallowed bytes.
	m.in = io.MultiReader(strings.NewReader("HTTP/1.1 101 Switching Protocols\r\n"), strings.NewReader("Connection: Upgrade\r\n\r\n"), bytes.NewReader(payload))
	got := make([]byte, len(payload))
	if _, e := io.ReadFull(c, got); e != nil || !bytes.Equal(got, payload) {
		t.Fatal("read framing")
	}
	for _, head := range []string{"HTTP/1.1 101\r\n" + strings.Repeat("x", 8200), "garbage\r\n\r\n", "HTTP/1.1"} {
		x := &obfsHTTPConn{Conn: &obfsMemory{in: strings.NewReader(head)}}
		if _, e := x.Read(make([]byte, 1)); e == nil {
			t.Fatal("unsafe header")
		}
	}
	m = &obfsMemory{fail: true}
	c = &obfsHTTPConn{Conn: m, host: "example.com"}
	if _, e := c.Write(payload); e == nil {
		t.Fatal("failed write")
	}
	m.fail = false
	if _, e := c.Write(payload); !errors.Is(e, io.ErrClosedPipe) {
		t.Fatal("failed handshake retried")
	}
}
func TestObfsHTTPValidationAndDeadlines(t *testing.T) {
	o := outbound.Options{Name: "test", Type: "shadowsocks", Server: "127.0.0.1", Port: 1, Method: "aes-128-gcm", Password: "fixture", Obfs: &outbound.SSObfsOptions{Mode: "http", Host: "example.com"}}
	if Validate(o) != nil {
		t.Fatal("valid")
	}
	for _, h := range []string{"", "x\r\nInjected: bad", "x\x00", "https://example.com", "x:0", "x:65536"} {
		o.Obfs.Host = h
		if Validate(o) == nil {
			t.Fatal("host")
		}
	}
	o.Obfs.Host = "example.com"
	o.Obfs.Mode = "tls"
	if Validate(o) == nil {
		t.Fatal("mode")
	}
	o.Obfs.Mode = "http"
	o.Method = "aes-256-gcm"
	if Validate(o) == nil {
		t.Fatal("method")
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := &obfsHTTPConn{Conn: a}
	c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, e := c.Read(make([]byte, 1)); e == nil {
		t.Fatal("deadline swallowed")
	}
}
