// Package tunstack terminates the TUN IP stack and delivers trusted original
// tuples directly to the kernel. It owns neither OS routing nor outbound policy.
package tunstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const MTU = 1420
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
type TCPConn interface {
	net.Conn
	CloseWrite() error
}
type Ingress interface {
	HandleTCP(context.Context, Flow, TCPConn) error
	HandleUDP(context.Context, Flow, net.Conn) error
}
type Config struct {
	Device    Device
	Ingress   Ingress
	Admitting func() bool
	Epoch     func() uint64
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
	stack            *stack.Stack
	link             *channel.Endpoint
	mu               sync.Mutex // admission, Quiesce/Resume and shutdown linearization
	paused, stopping bool
	err, closeErr    error
	udpSources       map[sourceKey]*sourceConn
	udpQueuedBytes   int64
	writeMu          sync.Mutex
	packetID         atomic.Uint32
	active           map[net.Conn]struct{}
	pending          int
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
	r := &Runtime{cfg: cfg, ctx: life, cancel: cancel, active: make(map[net.Conn]struct{}), udpSources: make(map[sourceKey]*sourceConn), failed: make(chan struct{}), done: make(chan struct{})}
	if err := r.initStack(); err != nil {
		cancel()
		_ = cfg.Device.Close()
		if r.stack != nil {
			r.stack.Destroy()
		}
		if r.link != nil {
			r.link.Close()
			r.link.Drain()
		}
		return nil, err
	}
	ready := make(chan struct{}, 2)
	r.wg.Add(2)
	go func() { defer r.wg.Done(); ready <- struct{}{}; r.readPackets() }()
	go func() { defer r.wg.Done(); ready <- struct{}{}; r.writePackets() }()
	<-ready
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
func (r *Runtime) Quiesce() { r.mu.Lock(); r.paused = true; r.mu.Unlock() }
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
		r.stack.Close()
		r.link.Close()
		r.wg.Wait()
		r.stack.Close() // abort endpoints created concurrently with the first Close
		r.stack.Wait()
		r.link.Drain()
		r.mu.Lock()
		r.closeErr = e
		r.mu.Unlock()
		close(r.done)
	}()
}

// reserve bounds goroutines BEFORE the potentially blocking TCP handshake.
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
