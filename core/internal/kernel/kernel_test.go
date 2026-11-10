package kernel

import (
	"bytes"
	"context"

	"crypto/tls"
	"crypto/x509"

	"encoding/binary"

	"io"

	"net"

	"sync"
	"testing"
	"time"
)

const testUUID = "4a86ae32-2235-4dc3-b103-42a2d162d73c"

func startTest(t *testing.T, in Inbound, modify func(*Config)) *Server {
	t.Helper()
	if in.Listen == "" {
		in.Listen = "127.0.0.1:0"
	}
	c := Config{UDPBindIPv4: "127.0.0.1", UDPBindIPv6: "::1", Inbounds: []Inbound{in}, Limits: Limits{Connections: 32, Handshakes: 16, Dials: 8, UDPAssociations: 8, UDPQueue: 4, UDPTargets: 4, PoolBuffers: 4, HandshakeTimeout: Duration(time.Second), DialTimeout: Duration(time.Second), DrainTimeout: Duration(2 * time.Second), UDPIdle: Duration(time.Second)}}
	// Unrelated protocol fixtures use system localhost resolution, not public DNS.
	c.DNS = &DNSOptions{Server: "system"}
	// Existing end-to-end tests use loopback echo targets: allow them explicitly.
	c.Security = &SecurityOptions{AllowLoopback: true}
	if modify != nil {
		modify(&c)
	}
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_ = s.Close(ctx)
		if got := s.Stats(); got.Active != 0 || got.Handshakes != 0 || got.Dials != 0 || got.UDP != 0 {
			t.Errorf("resource leak: %+v", got)
		}
	})
	return s
}
func waitFor(t *testing.T, f func() bool) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition did not settle")
}
func sinkTCP(t *testing.T, network, address string, handler func(net.Conn)) Address {
	t.Helper()
	ln, e := net.Listen(network, address)
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	active := map[net.Conn]bool{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			active[c] = true
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				defer func() { mu.Lock(); delete(active, c); mu.Unlock() }()
				c.SetDeadline(time.Now().Add(4 * time.Second))
				handler(c)
			}()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for c := range active {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return addrFromNet(ln.Addr())
}
func echoTCP(t *testing.T) Address {
	return sinkTCP(t, "tcp4", "127.0.0.1:0", func(c net.Conn) { _, _ = io.Copy(c, c) })
}
func echoUDP(t *testing.T) (Address, *net.UDPConn) {
	t.Helper()
	c, e := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if e != nil {
		t.Fatal(e)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 65535)
		for {
			n, a, e := c.ReadFromUDP(b)
			if e != nil {
				return
			}
			_, _ = c.WriteToUDP(b[:n], a)
		}
	}()
	t.Cleanup(func() { c.Close(); <-done })
	a := addrFromNet(c.LocalAddr())
	a.Host = "::1"
	return a, c
}
func dialPeer(t *testing.T, s *Server, pool *x509.CertPool) net.Conn {
	t.Helper()
	var c net.Conn
	var e error
	if pool != nil {
		c, e = tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", s.Addresses()[0].String(), &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12})
	} else {
		c, e = net.DialTimeout("tcp", s.Addresses()[0].String(), time.Second)
	}
	if e != nil {
		t.Fatal(e)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { c.Close() })
	return c
}

// These are independent literal wire fixtures, not server parser/encoder round trips.
func peerAddr(a Address, vl bool) []byte {
	var b []byte
	ip := net.ParseIP(a.Host)
	if ip == nil {
		typ := byte(3)
		if vl {
			typ = 2
		}
		b = []byte{typ, byte(len(a.Host))}
		b = append(b, a.Host...)
	} else if x := ip.To4(); x != nil {
		b = append([]byte{1}, x...)
	} else {
		typ := byte(4)
		if vl {
			typ = 3
		}
		b = append([]byte{typ}, ip.To16()...)
	}
	if !vl {
		b = binary.BigEndian.AppendUint16(b, a.Port)
	}
	return b
}

func socksGreeting(t *testing.T, c net.Conn, auth bool, pass string) {
	t.Helper()
	method := byte(0)
	if auth {
		method = 2
	}
	if e := writeAll(c, []byte{5, 1, method}); e != nil {
		t.Fatal(e)
	}
	b, e := readN(c, 2)
	if e != nil || !bytes.Equal(b, []byte{5, method}) {
		t.Fatalf("greeting %x %v", b, e)
	}
	if auth {
		b = append([]byte{1, 4}, []byte("user")...)
		b = append(b, byte(len(pass)))
		b = append(b, pass...)
		writeAll(c, b)
		b, e = readN(c, 2)
		if e != nil || !bytes.Equal(b, []byte{1, 0}) {
			t.Fatalf("auth %x %v", b, e)
		}
	}
}

func peerUDPFrame(p string, a Address, payload []byte) []byte {
	var b []byte
	if p == "trojan" {
		b = peerAddr(a, false)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))
	if p == "trojan" {
		b = append(b, 13, 10)
	}
	return append(b, payload...)
}

func socksUDPSend(t *testing.T, u *net.UDPConn, relay *net.UDPAddr, a Address, p []byte, frag byte) {
	t.Helper()
	b := append([]byte{0, 0, frag}, peerAddr(a, false)...)
	b = append(b, p...)
	if _, e := u.WriteToUDP(b, relay); e != nil {
		t.Fatal(e)
	}
}
func socksUDPRead(t *testing.T, u *net.UDPConn) []byte {
	t.Helper()
	u.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 65535)
	n, _, e := u.ReadFromUDP(b)
	if e != nil {
		t.Fatal(e)
	}
	r := bytes.NewReader(b[3:n])
	if _, e = readAddress(r); e != nil {
		t.Fatal(e)
	}
	p, _ := io.ReadAll(r)
	return p
}
