package anytls

import (
	"io"
	"testing"

	"github.com/shui1iao/Kat/internal/outbound"
)

func TestStreamQueueReusesBackingCapacityAndClearsReferences(t *testing.T) {
	s := &session{
		o:       &Outbound{},
		streams: make(map[uint32]*stream),
		wake:    make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	st := newStream(s, 1)

	for round := 0; round < 5; round++ {
		for j := 0; j < 8; j++ {
			st.push([]byte{byte(round), byte(j), 1, 2})
		}
		if round == 0 {
			if cap(st.in) < 8 {
				t.Fatalf("expected cap >= 8, got %d", cap(st.in))
			}
		}
		buf := make([]byte, 4)
		for j := 0; j < 8; j++ {
			n, err := st.Read(buf)
			if err != nil || n != 4 {
				t.Fatalf("round %d frame %d: Read = (%d, %v)", round, j, n, err)
			}
		}
		if len(st.in) != 0 || st.inHead != 0 {
			t.Fatalf("round %d: expected drained queue (len=%d, head=%d)", round, len(st.in), st.inHead)
		}
		if cap(st.in) < 8 {
			t.Fatalf("round %d: backing capacity lost after drain: cap=%d", round, cap(st.in))
		}
		backing := st.in[:cap(st.in)]
		for idx, slot := range backing {
			if slot != nil {
				t.Fatalf("round %d slot %d still references payload", round, idx)
			}
		}
	}

	st.push([]byte("tail"))
	st.remoteClose(io.EOF)
	buf := make([]byte, 8)
	n, err := st.Read(buf)
	if err != nil || string(buf[:n]) != "tail" {
		t.Fatalf("Read tail = (%q, %v)", buf[:n], err)
	}
	if st.in != nil || st.inHead != 0 {
		t.Fatalf("expected st.in == nil after reading final frame post-EOF, got cap=%d", cap(st.in))
	}
}

func BenchmarkStreamPushRead(b *testing.B) {
	s := &session{done: make(chan struct{})}
	st := newStream(s, 1)
	chunk := make([]byte, 1024)
	buf := make([]byte, 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 4; j++ {
			st.push(chunk)
		}
		for j := 0; j < 4; j++ {
			if _, err := st.Read(buf); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkPacketConnWriteToIPv4(b *testing.B) {
	s := &session{
		wake: make(chan struct{}, 1),
		done: make(chan struct{}),
	}
	go func() {
		for {
			select {
			case <-s.wake:
				s.mu.Lock()
				q := s.queue
				s.queue = s.queue[:0]
				s.mu.Unlock()
				for _, req := range q {
					req.done <- nil
				}
			case <-s.done:
				return
			}
		}
	}()
	defer close(s.done)

	st := newStream(s, 1)
	pc := &packetConn{st: st, headerSent: true}
	payload := make([]byte, 512)
	dst := outbound.Addr{Host: "1.1.1.1", Port: 53}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pc.WriteTo(payload, dst); err != nil {
			b.Fatal(err)
		}
	}
}
