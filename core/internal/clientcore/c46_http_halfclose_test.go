package clientcore

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/kernel"
)

// A normal TCP half-close finishes the request, not the response stream.
func TestC46HTTPConnectPreservesResponseAfterUploadEOF(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	request := []byte("request body complete")
	reply := bytes.Repeat([]byte("response after request EOF\n"), 4096)
	serverDone := make(chan error, 1)
	go func() {
		c, e := target.Accept()
		if e != nil {
			serverDone <- e
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		got, e := io.ReadAll(c)
		if e == nil && !bytes.Equal(got, request) {
			e = fmt.Errorf("request changed")
		}
		if e == nil {
			_, e = c.Write(reply)
		}
		serverDone <- e
	}()
	up, err := kernel.Start(kernel.Config{Inbounds: []kernel.Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0"}}, Security: &kernel.SecurityOptions{AllowLoopback: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close(context.Background())
	b, err := newHTTPBridge(0, up.Addresses()[0].(*net.TCPAddr).Port, func(e kernel.ClientLogEvent) {
		if d := e.Diagnostic; d != nil {
			t.Logf("bridge seq=%v action=%s direction=%s trigger=%s category=%s", d.ObservationSeq, d.Action, d.Direction, d.Trigger, d.Category)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	b.start()
	defer b.close()
	conn, err := net.Dial("tcp4", b.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	dst := target.Addr().String()
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dst, dst)
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("CONNECT: %v", err)
	}
	if _, err = conn.Write(request); err != nil {
		t.Fatal(err)
	}
	if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(br)
	serverErr := <-serverDone
	if readErr != nil || serverErr != nil || !bytes.Equal(got, reply) {
		t.Fatalf("half-close truncated response: got=%d want=%d read=%v target=%v", len(got), len(reply), readErr, serverErr)
	}
}

func TestC46HTTPBridgeCloseStillCancelsTunnel(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	ready := make(chan struct{})
	targetDone := make(chan error, 1)
	go func() {
		c, e := target.Accept()
		if e != nil {
			targetDone <- e
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		var one [1]byte
		_, e = io.ReadFull(c, one[:])
		if e == nil {
			close(ready)
			_, e = io.Copy(io.Discard, c)
		}
		targetDone <- e
	}()
	up, err := kernel.Start(kernel.Config{Inbounds: []kernel.Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0"}}, Security: &kernel.SecurityOptions{AllowLoopback: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close(context.Background())
	b, err := newHTTPBridge(0, up.Addresses()[0].(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	b.start()
	defer b.close()
	conn, err := net.Dial("tcp4", b.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	dst := target.Addr().String()
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dst, dst)
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("CONNECT: %v", err)
	}
	if _, err = conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("target did not receive ordinary payload")
	}
	closed := make(chan struct{})
	go func() { b.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("bridge shutdown did not cancel active tunnel")
	}
	if _, err = br.ReadByte(); err == nil {
		t.Fatal("tunnel remained open")
	}
	select {
	case <-targetDone:
	case <-time.After(3 * time.Second):
		t.Fatal("target side did not close")
	}
}
