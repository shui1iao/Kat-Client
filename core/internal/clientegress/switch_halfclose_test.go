package clientegress

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func switchSocketCount(s *Switch) int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.sockets) }

func TestSwitchTCPHalfCloseRoundTrip(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	reply := []byte("response-after-request-EOF")
	serverDone := make(chan error, 1)
	go func() {
		peer, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer peer.Close()
		peer.SetDeadline(time.Now().Add(3 * time.Second))
		got, err := io.ReadAll(peer)
		if err != nil {
			serverDone <- err
			return
		}
		if !bytes.Equal(got, []byte("request")) {
			serverDone <- io.ErrUnexpectedEOF
			return
		}
		_, err = peer.Write(reply)
		serverDone <- err
	}()
	var s Switch
	conn, err := s.DialContext(context.Background(), "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	half, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("transparent Switch hid TCP CloseWrite")
	}
	if _, err = conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err = half.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if switchSocketCount(&s) != 1 {
		t.Fatal("half-close released socket ownership")
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, reply) {
		t.Fatal("half-close truncated response")
	}
	if err = <-serverDone; err != nil {
		t.Fatal(err)
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	if switchSocketCount(&s) != 0 {
		t.Fatal("Close did not release original tracking entry")
	}
}

func TestSwitchOptionalCapabilityShape(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var s Switch
	conn, err := s.DialContext(context.Background(), "udp4", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, ok := conn.(interface{ CloseWrite() error }); ok {
		t.Fatal("Switch invented unsupported half-close capability")
	}
	if switchSocketCount(&s) != 1 {
		t.Fatal("socket not tracked")
	}
	if err = conn.Close(); err != nil {
		t.Fatal(err)
	}
	if switchSocketCount(&s) != 0 {
		t.Fatal("Close did not release original entry")
	}
}

func TestSwitchHalfCloseTrackingLifecycle(t *testing.T) {
	for _, action := range []string{"pause", "replace"} {
		t.Run(action, func(t *testing.T) {
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			var s Switch
			conn, err := s.DialContext(context.Background(), "tcp4", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			half, ok := conn.(interface{ CloseWrite() error })
			if !ok {
				t.Fatal("transparent Switch hid TCP CloseWrite")
			}
			if err = half.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if switchSocketCount(&s) != 1 {
				t.Fatal("half-close lost tracking")
			}
			if action == "pause" {
				s.Pause()
			} else {
				s.Replace(nil)
			}
			if switchSocketCount(&s) != 0 {
				t.Fatal("lifecycle retained tracking")
			}
			conn.SetReadDeadline(time.Now().Add(time.Second))
			var b [1]byte
			if _, err = conn.Read(b[:]); err == nil {
				t.Fatal("lifecycle did not close original socket")
			}
		})
	}
}
