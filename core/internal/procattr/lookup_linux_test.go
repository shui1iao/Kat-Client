//go:build linux

package procattr

import (
	"context"
	"net"
	"os"
	"testing"
)

func TestLinuxLookupLoopbackTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()

	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	srv := <-accepted
	defer srv.Close()

	q := Query{
		Network:     "tcp",
		Source:      Addr(cli.LocalAddr()),
		Destination: Addr(cli.RemoteAddr()),
	}
	id := lookupLocal(context.Background(), q)
	if id.Status != "known" {
		t.Fatalf("expected known identity, got %+v", id)
	}
	if id.PID != uint32(os.Getpid()) {
		t.Fatalf("expected self pid %d, got %d", os.Getpid(), id.PID)
	}
	if id.Name == "" || id.Stamp == 0 {
		t.Fatalf("expected non-empty name and stamp, got %+v", id)
	}
}

func TestLinuxLookupLoopbackUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	q := Query{
		Network: "udp",
		Source:  Addr(pc.LocalAddr()),
	}
	id := LookupTuple(context.Background(), q)
	if id.Status != "known" {
		t.Fatalf("expected known UDP identity, got %+v", id)
	}
	if id.PID != uint32(os.Getpid()) || id.Name == "" {
		t.Fatalf("unexpected UDP identity: %+v", id)
	}
	if cached, ok := cachedUDPTuple(q); !ok || cached.PID != id.PID {
		t.Fatalf("expected UDP tuple cache hit, got ok=%v cached=%+v", ok, cached)
	}
}

func TestLinuxLookupInvalidAndClosed(t *testing.T) {
	if id := Lookup(context.Background(), Query{Network: "tcp", Source: ap("0.0.0.0:1234"), Destination: ap("127.0.0.1:80")}); id.Status != "unsupported" {
		t.Fatalf("expected unsupported for unspecified source, got %+v", id)
	}
	if id := lookupLocal(context.Background(), Query{Network: "tcp", Source: ap("127.0.0.1:1"), Destination: ap("127.0.0.1:2")}); id.Status != "closed" {
		t.Fatalf("expected closed for nonexistent socket, got %+v", id)
	}
}
