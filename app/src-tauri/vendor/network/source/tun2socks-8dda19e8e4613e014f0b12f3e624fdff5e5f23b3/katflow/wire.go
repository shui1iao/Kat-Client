// Package katflow is a Kat-only patch on the pinned upstream. It exposes no
// listener. Metadata is sent solely over explicit inherited anonymous handles.
package katflow

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	flag "github.com/spf13/pflag"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"io"
	"net"
	"sync"
	"time"
)

var readHandle, writeHandle uint64
var session string
var acknowledge = readACK
var wire struct {
	sync.Mutex
	seq         uint64
	read, write io.ReadWriteCloser
	dead        bool
}

func Flags() {
	flag.Uint64Var(&readHandle, "kat-flow-read", 0, "Kat inherited acknowledgement handle")
	flag.Uint64Var(&writeHandle, "kat-flow-write", 0, "Kat inherited registration handle")
	flag.StringVar(&session, "kat-flow-session", "", "Kat flow session")
	_ = flag.CommandLine.MarkHidden("kat-flow-read")
	_ = flag.CommandLine.MarkHidden("kat-flow-write")
	_ = flag.CommandLine.MarkHidden("kat-flow-session")
}
func Enabled() bool { return readHandle != 0 || writeHandle != 0 || session != "" }
func Start() error {
	if !Enabled() {
		return nil
	}
	if readHandle == 0 || writeHandle == 0 || readHandle == writeHandle || len(session) != 64 {
		return errors.New("invalid inherited flow handles")
	}
	return openHandles()
}
func Stop() { wire.Lock(); defer wire.Unlock(); failLocked() }
func failLocked() {
	wire.dead = true
	if wire.read != nil {
		wire.read.Close()
	}
	if wire.write != nil {
		wire.write.Close()
	}
}

type flow struct {
	ID                 uint64 `json:"id"`
	Network            string `json:"network"`
	Source             string `json:"source"`
	Destination        string `json:"destination"`
	MidSource          string `json:"mid_source"`
	MidDestination     string `json:"mid_destination"`
	ControlSource      string `json:"control_source"`
	ControlDestination string `json:"control_destination"`
}

func exchangeLocked(msg any) error {
	if wire.dead || wire.read == nil || wire.write == nil {
		return errors.New("original-flow channel closed")
	}
	b, err := json.Marshal(msg)
	if err != nil || len(b) > 2048 {
		return errors.New("invalid flow message")
	}
	frame := make([]byte, 4+len(b))
	binary.LittleEndian.PutUint32(frame, uint32(len(b)))
	copy(frame[4:], b)
	// One outstanding request, smaller than the inherited pipe buffer. The
	// preceding ACK proves the server consumed its entire preceding frame.
	if n, err := wire.write.Write(frame); err != nil || n != len(frame) {
		failLocked()
		return errors.New("flow registration write failed")
	}
	if err := acknowledge(time.Now().Add(2 * time.Second)); err != nil {
		failLocked()
		return err
	}
	return nil
}
func Register(m *M.Metadata, c net.Conn, midSource, midDestination string) (func(), error) {
	if !Enabled() {
		return func() {}, nil
	}
	wire.Lock()
	defer wire.Unlock()
	wire.seq++
	id := wire.seq
	f := flow{id, m.Network.String(), m.SourceAddress(), m.DestinationAddress(), midSource, midDestination, c.LocalAddr().String(), c.RemoteAddr().String()}
	if err := exchangeLocked(struct {
		Op      string `json:"op"`
		Version uint32 `json:"version"`
		Session string `json:"session"`
		Flow    flow   `json:"flow"`
	}{"register", 1, session, f}); err != nil {
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			wire.Lock()
			defer wire.Unlock()
			_ = exchangeLocked(struct {
				Op      string `json:"op"`
				Version uint32 `json:"version"`
				Session string `json:"session"`
				ID      uint64 `json:"id"`
			}{"close", 1, session, id})
		})
	}, nil
}

type registeredConn struct {
	net.Conn
	close func()
	once  sync.Once
	err   error
}

func Wrap(c net.Conn, close func()) net.Conn { return &registeredConn{Conn: c, close: close} }
func (c *registeredConn) Close() error {
	c.once.Do(func() { c.close(); c.err = c.Conn.Close() })
	return c.err
}

// Preserve the upstream TCP half-close contract across the registration wrapper.
func (c *registeredConn) CloseRead() error {
	if v, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return v.CloseRead()
	}
	return nil
}
func (c *registeredConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return nil
}
