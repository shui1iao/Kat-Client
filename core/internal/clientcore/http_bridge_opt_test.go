package clientcore

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/kernel"
)

func TestHTTPConnectDrainsPipelinedReaderAndStreams64KiB(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	payload := make([]byte, 512*1024+137)
	for i := range payload {
		payload[i] = byte((i*31 + 7) & 0xff)
	}
	done := make(chan error, 1)
	go func() {
		c, e := target.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		got := make([]byte, len(payload))
		if _, e := io.ReadFull(c, got); e != nil {
			done <- e
			return
		}
		if !bytes.Equal(got, payload) {
			done <- io.ErrUnexpectedEOF
			return
		}
		_, e = c.Write(got[:65537])
		done <- e
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

	c, err := net.Dial("tcp4", b.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	dst := target.Addr().String()
	// Pipeline first 100 bytes immediately with CONNECT header so rw.Reader buffers them!
	req := append([]byte("CONNECT "+dst+" HTTP/1.1\r\nHost: "+dst+"\r\n\r\n"), payload[:100]...)
	if _, err := c.Write(req); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v", err)
	}
	if _, err := c.Write(payload[100:]); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 65537)
	if _, err := io.ReadFull(br, echo); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(echo, payload[:65537]) {
		t.Fatal("echo mismatch")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
