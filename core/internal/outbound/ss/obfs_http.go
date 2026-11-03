package ss

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
)

func validObfsHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	host := h
	if x, p, e := net.SplitHostPort(h); e == nil {
		n, e := strconv.ParseUint(p, 10, 16)
		if e != nil || n == 0 {
			return false
		}
		host = x
	}
	return validServer(host)
}

var errObfsHTTP = errors.New("shadowsocks: invalid obfs HTTP transport")

// simple-obfs HTTP is a preface on ciphertext, not WebSocket framing/HTTP body.
type obfsHTTPConn struct {
	net.Conn
	host     string
	wm       sync.Mutex
	sent     bool
	werr     error
	rm       sync.Mutex
	received bool
	pending  []byte
	rerr     error
}

func (c *obfsHTTPConn) Write(p []byte) (int, error) {
	c.wm.Lock()
	defer c.wm.Unlock()
	if c.werr != nil {
		return 0, c.werr
	}
	if len(p) == 0 {
		return 0, nil
	}
	if c.sent {
		n, e := c.Conn.Write(p)
		if e != nil {
			c.werr = e
		}
		return n, e
	}
	var nonce [16]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		c.werr = e
		return 0, e
	}
	header := []byte("GET / HTTP/1.1\r\nHost: " + c.host + "\r\nContent-Length: " + strconv.Itoa(len(p)) + "\r\nUser-Agent: curl/7.47.0\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + base64.URLEncoding.EncodeToString(nonce[:]) + "\r\n\r\n")
	wire := append(header, p...)
	sent := 0
	for sent < len(wire) {
		n, e := c.Conn.Write(wire[sent:])
		sent += n
		if e == nil && n == 0 {
			e = io.ErrShortWrite
		}
		if e != nil {
			c.werr = e
			payload := sent - len(header)
			if payload < 0 {
				payload = 0
			}
			return payload, e
		}
	}

	c.sent = true
	return len(p), nil
}
func (c *obfsHTTPConn) Read(p []byte) (int, error) {
	c.rm.Lock()
	defer c.rm.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.rerr != nil {
		return 0, c.rerr
	}
	for !c.received {
		var b [1024]byte
		n, e := c.Conn.Read(b[:])
		c.pending = append(c.pending, b[:n]...)
		if i := bytes.Index(c.pending, []byte("\r\n\r\n")); i >= 0 {
			if i+4 > 8192 || !bytes.HasPrefix(c.pending, []byte("HTTP/1.")) {
				c.rerr = errObfsHTTP
				return 0, c.rerr
			}
			c.pending = c.pending[i+4:]
			c.received = true
			break
		}
		if len(c.pending) >= 8192 {
			c.rerr = errObfsHTTP
			return 0, c.rerr
		}
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				return 0, e
			}
			c.rerr = errObfsHTTP
			return 0, c.rerr
		}
	}
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
func (c *obfsHTTPConn) CloseWrite() error {
	c.wm.Lock()
	defer c.wm.Unlock()
	if x, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return x.CloseWrite()
	}
	return errors.New("shadowsocks: transport does not support CloseWrite")
}
