package katflow

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

type memory struct {
	b      []byte
	closed bool
}

func (m *memory) Write(b []byte) (int, error) { m.b = append(m.b, b...); return len(b), nil }
func (m *memory) Read(b []byte) (int, error)  { return 0, io.EOF }
func (m *memory) Close() error                { m.closed = true; return nil }

type socket struct {
	net.Conn
	closed bool
}

func (s *socket) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234} }
func (s *socket) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 7891} }
func (s *socket) Close() error         { s.closed = true; return nil }
func TestRegisterACKCloseBeforePortRelease(t *testing.T) {
	oldAck := acknowledge
	defer func() { acknowledge = oldAck; readHandle = 0; writeHandle = 0; session = "" }()
	readHandle = 1
	writeHandle = 2
	session = "s"
	w := &memory{}
	wire.read = &memory{}
	wire.write = w
	wire.dead = false
	wire.seq = 0
	c := &socket{}
	acknowledge = func(time.Time) error {
		if len(w.b) < 4 || c.closed {
			t.Fatal("ACK/order")
		}
		return nil
	}
	m := &M.Metadata{Network: M.TCP, SrcIP: netip.MustParseAddr("192.0.2.1"), SrcPort: 555, DstIP: netip.MustParseAddr("1.1.1.1"), DstPort: 443}
	closeFlow, err := Register(m, c, c.LocalAddr().String(), c.RemoteAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	n := binary.LittleEndian.Uint32(w.b)
	var f struct {
		Flow flow `json:"flow"`
	}
	if err := json.Unmarshal(w.b[4:4+n], &f); err != nil || f.Flow.Source != "192.0.2.1:555" || f.Flow.MidSource != "127.0.0.1:1234" {
		t.Fatal(f, err)
	}
	wrapped := Wrap(c, closeFlow)
	wrapped.Close()
	wrapped.Close()
	if !c.closed {
		t.Fatal("port not released")
	}
	rest := w.b[4+n:]
	n = binary.LittleEndian.Uint32(rest)
	var op struct {
		Op string `json:"op"`
		ID uint64 `json:"id"`
	}
	json.Unmarshal(rest[4:4+n], &op)
	if op.Op != "close" || op.ID != f.Flow.ID || len(rest) != int(4+n) {
		t.Fatal(op)
	}
}
func TestFailedACKInvalidatesChannel(t *testing.T) {
	old := acknowledge
	defer func() { acknowledge = old; readHandle = 0; writeHandle = 0; session = "" }()
	readHandle = 1
	writeHandle = 2
	session = "s"
	r, w := &memory{}, &memory{}
	wire.read = r
	wire.write = w
	wire.dead = false
	acknowledge = func(time.Time) error { return errors.New("timeout") }
	wire.Lock()
	err := exchangeLocked(map[string]int{"version": 1})
	wire.Unlock()
	if err == nil || !wire.dead || !r.closed || !w.closed {
		t.Fatal(err)
	}
}
