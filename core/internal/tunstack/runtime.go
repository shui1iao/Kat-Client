// Package tunstack terminates the TUN IP stack via a pure-Go System Stack
// (zero gVisor) and delivers trusted original tuples directly to the kernel.
// It owns neither OS routing nor outbound policy.
package tunstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

const (
	MTU    = 60000
	UDPMTU = 1420
)
const maxHandlers = 4096

type Protocol uint8

const (
	TCP Protocol = 6
	UDP Protocol = 17
)

type Flow struct {
	Source, Destination netip.AddrPort
	Protocol            Protocol
	Epoch               uint64
}
type Device interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) error
	Close() error
}

// Optional batching interfaces implemented by high-throughput native TUN devices.
type PacketBatchReader interface {
	ReadPackets(dst [][]byte, sizes []int) (int, error)
}
type PacketBatchWriter interface {
	WritePackets(pkts [][]byte) (int, error)
}
type TCPConn interface {
	net.Conn
	CloseWrite() error
}
type ICMPEchoRequest struct {
	Source, Destination netip.Addr
	Ident, Sequence     uint16
	TTL, TOS            uint8
	DF                  bool
	Payload             []byte
	Epoch               uint64
}
type ICMPEchoReply struct {
	Payload []byte
	TTL     uint8
}
type Ingress interface {
	HandleTCP(context.Context, Flow, TCPConn) error
	HandleUDP(context.Context, Flow, net.Conn) error
}
type ICMPIngress interface {
	HandleICMP(context.Context, ICMPEchoRequest) (ICMPEchoReply, bool)
}
type Config struct {
	Device    Device
	Ingress   Ingress
	Admitting func() bool
	Epoch     func() uint64
	// Optional preferred local TUN addresses for the System Stack TCP listeners.
	// When unset, defaults to 198.18.0.1 / fd4b:6174::1 with wildcard fallback.
	LocalIPv4 netip.Addr
	LocalIPv6 netip.Addr
}

// Failure.Code is suitable for the existing safe health channel. Cause must
// remain in the private diagnostic boundary; it may contain arbitrary OS text.
type Failure struct {
	Code  string
	Cause error
}

func (e *Failure) Error() string { return e.Code } // safe health text; Cause remains private
func (e *Failure) Unwrap() error { return e.Cause }

type Runtime struct {
	cfg              Config
	ctx              context.Context
	cancel           context.CancelFunc
	tcpSys           *tcpSystemStack
	reasm            *ipReassembler
	hasICMP          bool
	mu               sync.Mutex // admission, Quiesce/Resume and shutdown linearization
	paused, stopping bool
	err, closeErr    error
	udpSources       map[sourceKey]*sourceConn
	udpQueuedBytes   int64
	udpHandlers      int
	udpDrained       chan struct{}
	writeMu          sync.Mutex
	packetID         atomic.Uint32
	active           map[net.Conn]struct{}
	pending          int
	icmpInFlight     int
	wg               sync.WaitGroup
	failed, done     chan struct{}
	dropped          atomic.Uint64
}

// StartReady takes exclusive Device closing responsibility even on failure.
// Success is stack/pump readiness, NOT OS route commit or reachability.
func StartReady(ctx context.Context, cfg Config) (*Runtime, error) {
	if cfg.Device == nil {
		return nil, errors.New("tunstack: nil device")
	}
	if ctx == nil || cfg.Ingress == nil || cfg.Admitting == nil || cfg.Epoch == nil {
		_ = cfg.Device.Close()
		return nil, errors.New("tunstack: missing lifecycle/ingress hooks")
	}
	if err := ctx.Err(); err != nil {
		_ = cfg.Device.Close()
		return nil, err
	}
	life, cancel := context.WithCancel(ctx)
	_, hasICMP := cfg.Ingress.(ICMPIngress)
	r := &Runtime{
		cfg:        cfg,
		ctx:        life,
		cancel:     cancel,
		reasm:      newIPReassembler(),
		hasICMP:    hasICMP,
		active:     make(map[net.Conn]struct{}),
		udpSources: make(map[sourceKey]*sourceConn),
		failed:     make(chan struct{}),
		done:       make(chan struct{}),
	}
	tcpSys, err := newTCPSystemStack(r)
	if err != nil {
		cancel()
		_ = cfg.Device.Close()
		return nil, err
	}
	r.tcpSys = tcpSys
	r.tcpSys.start()

	ready := make(chan struct{}, 1)
	r.wg.Add(1)
	go func() { defer r.wg.Done(); ready <- struct{}{}; r.readPackets() }()
	<-ready

	go func() {
		select {
		case <-life.Done():
			r.stop(nil)
		case <-r.done:
		}
	}()
	if err := r.Err(); err != nil {
		_ = r.Close(context.Background())
		return nil, err
	}
	if err := life.Err(); err != nil {
		_ = r.Close(context.Background())
		return nil, err
	}
	return r, nil
}

// MemoryStats returns live System Stack TCP NAT table entries, active UDP
// source endpoints, and queued UDP payload bytes for numeric diagnostics.
func (r *Runtime) MemoryStats() (tcpNATEntries, udpSources, udpQueuedBytes uint64) {
	if r == nil {
		return 0, 0, 0
	}
	r.mu.Lock()
	udpSources = uint64(len(r.udpSources))
	if r.udpQueuedBytes > 0 {
		udpQueuedBytes = uint64(r.udpQueuedBytes)
	}
	tcpSys := r.tcpSys
	r.mu.Unlock()
	tcpNATEntries = tcpSys.natCount()
	return tcpNATEntries, udpSources, udpQueuedBytes
}

// TCPListenPort4 returns the bound IPv4 System Stack TCP listener port (0 if closed).
func (r *Runtime) TCPListenPort4() uint16 {
	if r == nil || r.tcpSys == nil {
		return 0
	}
	return r.tcpSys.port4
}

// TCPListenPort6 returns the bound IPv6 System Stack TCP listener port (0 if unavailable).
func (r *Runtime) TCPListenPort6() uint16 {
	if r == nil || r.tcpSys == nil {
		return 0
	}
	return r.tcpSys.port6
}

func (r *Runtime) Quiesce() {
	r.mu.Lock()
	r.paused = true
	for _, c := range r.udpSources {
		c.cancel()
	}
	r.mu.Unlock()
}

// DrainUDP follows Quiesce. A source disappearing from udpSources means its
// ingress closed, not that its last outbound write (or DNS query) has joined.
func (r *Runtime) DrainUDP(ctx context.Context) error {
	r.mu.Lock()
	if !r.paused {
		r.mu.Unlock()
		return errors.New("tunstack: UDP not quiesced")
	}
	if r.udpHandlers == 0 {
		r.mu.Unlock()
		return nil
	}
	drained := r.udpDrained
	r.mu.Unlock()
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Runtime) Resume() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopping || r.err != nil || r.ctx.Err() != nil {
		return errors.New("tunstack: stopped")
	}
	// OS invokes Resume after verifying the owner, BEFORE committing routes.
	// Its gate may still be false; clearing our local fence cannot bypass it.
	r.paused = false
	return nil
}

func (r *Runtime) Failed() <-chan struct{} { return r.failed }
func (r *Runtime) Done() <-chan struct{}   { return r.done }
func (r *Runtime) Err() error              { r.mu.Lock(); defer r.mu.Unlock(); return r.err }

func (r *Runtime) Close(ctx context.Context) error {
	r.stop(nil)
	select {
	case <-r.done:
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.closeErr // cleanup result; the original fatal stays latched in Err/Failed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *Runtime) fatal(code string, err error) {
	if r.ctx.Err() != nil {
		r.stop(nil)
		return
	}
	r.stop(&Failure{Code: code, Cause: err})
}

func (r *Runtime) stop(cause error) {
	r.mu.Lock()
	if r.stopping {
		r.mu.Unlock()
		return
	}
	r.stopping = true
	r.paused = true
	if cause != nil {
		r.err = cause
		close(r.failed)
	}
	r.mu.Unlock()
	go func() {
		r.cancel()
		if r.tcpSys != nil {
			r.tcpSys.close()
		}
		e := r.cfg.Device.Close()
		r.mu.Lock()
		cs := make([]net.Conn, 0, len(r.active))
		for c := range r.active {
			cs = append(cs, c)
		}
		r.mu.Unlock()
		for _, c := range cs {
			_ = c.Close()
		}
		r.wg.Wait()
		r.mu.Lock()
		r.closeErr = e
		r.mu.Unlock()
		close(r.done)
	}()
}

// reserve bounds goroutines BEFORE entering TCP ingress.
// wg.Add and stopping share mu: no Add can race the shutdown Wait at zero.
func (r *Runtime) reserve() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopping || r.paused || r.ctx.Err() != nil || !r.cfg.Admitting() || r.pending >= maxHandlers {
		r.dropped.Add(1)
		return false
	}
	r.pending++
	r.wg.Add(1)
	return true
}

func (r *Runtime) release(c net.Conn) {
	if c != nil {
		_ = c.Close()
	}
	r.mu.Lock()
	delete(r.active, c)
	if _, udp := c.(*sourceConn); udp {
		r.udpHandlers--
		if r.udpHandlers == 0 {
			close(r.udpDrained)
		}
	}
	r.pending--
	r.mu.Unlock()
	r.wg.Done()
}

// enter commits callback admission under the SAME lock as Quiesce. A flow
// committed before the fence is an existing flow, not a queued new admission.
// Recheck after handshake: a SYN reserved before a fence cannot slip through it.
func (r *Runtime) enter(c net.Conn, f *Flow) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopping || r.paused || r.ctx.Err() != nil {
		return false
	}
	epoch := r.cfg.Epoch()
	if !r.cfg.Admitting() || epoch != r.cfg.Epoch() || !r.cfg.Admitting() {
		return false
	}
	f.Epoch = epoch
	r.active[c] = struct{}{}
	return true
}
