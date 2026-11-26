package anytls

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

func TestPooledV2TCPAsyncSYNACKRefusalAndCarrierReuse(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client, peer := net.Pipe()
		o := &Outbound{idleMax: 1, idleTimeout: time.Hour}
		s := newSession(o, client, nil, nil, nil)
		s.peerVersion = 2
		s.verOnce.Do(func() { close(s.ver) })
		o.sessions = []*session{s}
		s.start()
		defer func() { peer.Close(); s.fail(net.ErrClosed); s.wg.Wait() }()
		dialDone := make(chan net.Conn, 1)
		go func() {
			c, e := o.DialTCP(context.Background(), outbound.Addr{Host: "127.0.0.1", Port: 80})
			if e != nil {
				t.Errorf("DialTCP failed: %v", e)
				dialDone <- nil
				return
			}
			dialDone <- c
		}()
		var id uint32
		for _, cmd := range []byte{cmdSYN, cmdPSH} {
			var h [headerSize]byte
			if _, e := io.ReadFull(peer, h[:]); e != nil || h[0] != cmd {
				t.Fatalf("frame: %v %v", h, e)
			}
			id = binary.BigEndian.Uint32(h[1:5])
			if _, e := io.CopyN(io.Discard, peer, int64(binary.BigEndian.Uint16(h[5:]))); e != nil {
				t.Fatal(e)
			}
		}
		// Non-blocking DialTCP returns as soon as SYN+target is flushed without
		// waiting an extra RTT for SYNACK.
		c := <-dialDone
		if c == nil {
			return
		}
		defer c.Close()
		// A heartbeat is still serviced while the stream awaits server frames.
		if _, err := peer.Write(appendFrame(nil, cmdHeartRequest, 17, nil)); err != nil {
			t.Fatal(err)
		}
		var h [headerSize]byte
		if _, err := io.ReadFull(peer, h[:]); err != nil || h[0] != cmdHeartResponse || binary.BigEndian.Uint32(h[1:5]) != 17 {
			t.Fatalf("heartbeat: %v %v", h, err)
		}
		// Start a blocked Read on the stream; a SYNACK for another stream must not
		// wake or fail it.
		readDone := make(chan error, 1)
		go func() {
			var buf [16]byte
			_, err := c.Read(buf[:])
			readDone <- err
		}()
		if _, err := peer.Write(appendFrame(nil, cmdSYNACK, id+1, nil)); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		select {
		case e := <-readDone:
			t.Fatalf("early read result: %v", e)
		default:
		}
		// Server refuses the stream via async SYNACK error; Read surfaces
		// errStreamRefused, Write also fails, and the healthy session returns to idle.
		if _, err := peer.Write(appendFrame(nil, cmdSYNACK, id, []byte("private peer diagnostic"))); err != nil {
			t.Fatal(err)
		}
		e := <-readDone
		if e != errStreamRefused || SafeFailure(fmt.Errorf("dial: %w", e)) != "rejected" {
			t.Fatalf("unexpected refusal on Read: %v", e)
		}
		if _, we := c.Write([]byte("x")); we != errStreamRefused {
			t.Fatalf("unexpected refusal on Write: %v", we)
		}
		synctest.Wait()
		if busy, idle := o.sessionCount(); busy != 0 || idle != 1 {
			t.Fatalf("refused stream retired healthy carrier: %d/%d", busy, idle)
		}
	})
}

func TestControlQueueAdmissionAndShutdown(t *testing.T) {
	for _, closeFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("close=%t", closeFirst), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				s := newSession(&Outbound{}, nil, nil, nil, nil)
				// Exercise FIFO admission directly, without a network traffic generator.
				for range responseHighWater {
					if err := s.enqueueResponse(1); err != nil {
						t.Fatal(err)
					}
				}
				next := make(chan error, 1)
				go func() { next <- s.enqueueResponse(2) }()
				synctest.Wait()
				select {
				case err := <-next:
					t.Fatalf("did not backpressure: %v", err)
				default:
				}
				if len(s.queue) != responseHighWater {
					t.Fatal("queue exceeded capacity")
				}
				if closeFirst {
					for len(s.queue) < maxQueuedWrites {
						if err := s.enqueue(&writeReq{done: make(chan error, 1)}); err != nil {
							t.Fatal(err)
						}
					}
					st := newStream(s, 1)
					s.streams[1] = st
					st.Close() // no room for FIN; retire instead of blocking Close
					if err := <-next; !errors.Is(err, errQueueFull) {
						t.Fatal(err)
					}
				} else {
					if !s.cancel(s.queue[0]) {
						t.Fatal("could not withdraw queued request")
					}
					if err := <-next; err != nil {
						t.Fatal(err)
					}
					if len(s.queue) != responseHighWater || binary.BigEndian.Uint32(s.queue[responseHighWater-1].wire[1:5]) != 2 {
						t.Fatal("resumed response out of order")
					}
					s.fail(net.ErrClosed)
				}
			})
		})
	}
}

func TestUoTDomainReply(t *testing.T) {
	addr := outbound.Addr{Host: "echo.test", Port: 5353}
	s := newSession(&Outbound{}, nil, nil, nil, nil)
	st := newStream(s, 1)
	wire, err := appendAddr(nil, addr, uotTypes)
	if err != nil {
		t.Fatal(err)
	}
	wire = binary.BigEndian.AppendUint16(wire, 3)
	st.push(append(wire, "abc"...))
	pc := &packetConn{st: st}
	var b [8]byte
	n, src, err := pc.ReadFrom(b[:])
	if err != nil || src != addr || string(b[:n]) != "abc" {
		t.Fatalf("reply: %s %q %v", src, b[:n], err)
	}
}
