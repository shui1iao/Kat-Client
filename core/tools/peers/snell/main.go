// TEST ONLY: isolated module linking the fixed independent sing-snell client.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	sn "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"
)

func must(e error) {
	if e != nil {
		panic(e)
	}
}
func local(s string) M.Socksaddr {
	a := M.ParseSocksaddr(s)
	if !a.IsIP() || !a.Addr.IsLoopback() {
		panic("loopback only")
	}
	return a
}

type countDialer struct {
	N.Dialer
	count atomic.Int64
}

func (d *countDialer) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	d.count.Add(1)
	return d.Dialer.DialContext(ctx, network, dst)
}

type captureConn struct{ bytes.Buffer }

func (c *captureConn) Read(p []byte) (int, error)       { return 0, io.EOF }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }
func main() {
	server := flag.String("server", "", "")
	obfs := flag.String("obfs", "none", "")
	target1 := flag.String("target1", "", "")
	target2 := flag.String("target2", "", "")
	udp := flag.String("udp", "", "")
	capture := flag.String("capture", "", "capture independent raw request for negative integration tests")
	flag.Parse()
	if *capture != "" {
		client, e := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte("snell-core-fixture-psk")})
		must(e)
		wire := new(captureConn)
		stream := client.DialEarlyConn(wire, local(*target1))
		_, e = stream.Write([]byte("probe"))
		must(e)
		must(stream.(interface{ CloseWrite() error }).CloseWrite())
		must(os.WriteFile(*capture, wire.Bytes(), 0600))
		return
	}
	_ = local(*server)
	_ = local(*target1)
	_ = local(*target2)
	_ = local(*udp)
	mode := sn.ObfsModeNone
	if *obfs == "http" {
		mode = sn.ObfsModeHTTP
	}
	d := &countDialer{Dialer: N.SystemDialer}
	c, e := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte("snell-core-fixture-psk"), ObfsMode: mode, Reuse: true, Dialer: d, Server: local(*server)})
	must(e)
	defer c.Close()
	for _, target := range []string{*target1, *target2} {
		conn, e := c.DialContext(context.Background(), local(target))
		must(e)
		must(conn.SetDeadline(time.Now().Add(5 * time.Second)))
		payload := bytes.Repeat([]byte(target), 16000)
		done := make(chan error, 1)
		go func() {
			_, e := conn.Write(payload)
			if e == nil {
				e = conn.(interface{ CloseWrite() error }).CloseWrite()
			}
			done <- e
		}()
		got, e := io.ReadAll(conn)
		must(e)
		must(<-done)
		want := append([]byte("hello:"+target+":"), payload...)
		if !bytes.Equal(got, want) {
			panic(fmt.Sprintf("reuse payload mismatch target=%s got=%d want=%d", target, len(got), len(want)))
		}
		must(conn.Close())
		fmt.Println("TCP REUSE HALF-CLOSE PASS", target, len(got))
	}
	if d.count.Load() != 1 {
		panic(fmt.Sprintf("expected one TCP physical session for two requests, got %d", d.count.Load()))
	}
	fmt.Println("PHYSICAL TCP REUSE SESSIONS", d.count.Load())
	raw, e := net.DialTimeout("tcp", *server, time.Second)
	must(e)
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	pc, e := c.DialPacketConn(raw)
	must(e)
	defer pc.Close()
	for i := 0; i < 3; i++ {
		p := bytes.Repeat([]byte{byte(i)}, 137*(i+1))
		_, e = pc.WriteTo(p, local(*udp))
		must(e)
		b := make([]byte, 2048)
		n, source, e := pc.ReadFrom(b)
		must(e)
		if !bytes.Equal(p, b[:n]) || source.String() != *udp {
			panic("UDP payload/source mismatch")
		}
	}
	fmt.Fprintln(os.Stdout, "PEER PASS", *obfs, "sing-snell bc5a12ac736f235b2de2926ecd2791cc925e6b8c")
}
