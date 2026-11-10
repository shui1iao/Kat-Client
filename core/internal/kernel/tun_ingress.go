package kernel

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/tunstack"
	"net"
	"time"
)

type tunFlowKey struct{}

func tunFlowOf(ctx context.Context) (tunstack.Flow, bool) {
	f, ok := ctx.Value(tunFlowKey{}).(tunstack.Flow)
	return f, ok
}

// TUNIngress borrows the existing process-wide kernel. No proxy listener,
// registry handshake, second route engine, resolver or outbound pool is made.
type TUNIngress struct{ server *Server }

var _ tunstack.Ingress = (*TUNIngress)(nil)

func (s *Server) NewTUNIngress() (*TUNIngress, error) {
	if s == nil || s.core == nil {
		return nil, ErrCoreNotRunning
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.ctx.Err() != nil {
		return nil, ErrCoreNotRunning
	}
	return &TUNIngress{server: s}, nil
}
func validTUNFlow(f tunstack.Flow, p tunstack.Protocol) bool {
	return f.Protocol == p && f.Source.IsValid() && f.Destination.IsValid() && f.Source.Port() != 0 && f.Destination.Port() != 0 && !f.Source.Addr().IsUnspecified() && !f.Destination.Addr().IsUnspecified() && f.Source.Addr().Is4() == f.Destination.Addr().Is4()
}
func (i *TUNIngress) begin(parent context.Context, t tunstack.Flow, c net.Conn, p tunstack.Protocol) (*Server, context.Context, func(), error) {
	if !validTUNFlow(t, p) {
		return nil, nil, nil, errors.New("invalid trusted TUN tuple")
	}
	s := i.server.current()
	if !s.tryRef() {
		return nil, nil, nil, ErrCoreNotRunning
	}
	slot := s.connSlots
	if p == tunstack.UDP {
		slot = s.udpSlots
	}
	if !slot.try() {
		s.unref()
		s.counters.Rejected.Add(1)
		return nil, nil, nil, errors.New("TUN flow budget exhausted")
	}
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		slot.release()
		s.unref()
		return nil, nil, nil, ErrCoreNotRunning
	}
	s.active[c] = &acceptedState{}
	s.wg.Add(1)
	s.mu.Unlock()
	s.counters.Accepted.Add(1)
	s.counters.Active.Add(1)
	if p == tunstack.UDP {
		s.counters.UDP.Add(1)
	}
	ctx, cancel := context.WithCancel(s.trafficContext())
	stopParent := context.AfterFunc(parent, cancel)
	stopIO := context.AfterFunc(ctx, func() { _ = c.Close() })
	ctx = context.WithValue(ctx, tunFlowKey{}, t)
	ctx = withInbound(ctx, -1)
	ctx = outbound.WithSource(ctx, t.Source.Addr())
	// The existing desktop document projects its one sniff policy into kat-client.
	// Borrow that policy only; identity is exclusively the trusted packet tuple.
	in := Inbound{Name: "tun", Protocol: "tun"}
	for _, v := range s.cfg.Inbounds {
		if v.Name == "kat-client" {
			in.Sniff = v.Sniff
			break
		}
	}
	ctx = withInboundMeta(ctx, &in, c.LocalAddr(), c.RemoteAddr())
	ctx = context.WithValue(ctx, inStatKey{}, inStat{c: s.reg.Inbound("tun"), key: "tun"})
	done := func() {
		cancel()
		stopParent()
		stopIO()
		_ = c.Close()
		s.mu.Lock()
		delete(s.active, c)
		s.mu.Unlock()
		s.counters.Active.Add(-1)
		if p == tunstack.UDP {
			s.counters.UDP.Add(-1)
		}
		slot.release()
		s.unref()
		s.wg.Done()
	}
	return s, ctx, done, nil
}
func (i *TUNIngress) HandleTCP(parent context.Context, t tunstack.Flow, c tunstack.TCPConn) (err error) {
	s, ctx, done, err := i.begin(parent, t, c, tunstack.TCP)
	if err != nil {
		return err
	}
	defer done()
	target := Address{t.Destination.Addr().String(), t.Destination.Port()}
	ctx = withOriginalTarget(ctx, target)
	if target.Port == 53 {
		return s.tunDNSTCP(ctx, c, target)
	}
	sctx, sc, first, _, err := s.sniffTCP(ctx, c, target, nil)
	if err != nil {
		return err
	}
	f, fctx := s.newFlow(sctx, "tcp", target)
	out, err := s.dial(fctx, target)
	if err != nil {
		f.end(dialResult(err))
		return err
	}
	defer out.Close()
	stage := "initial_write"
	defer func() {
		if !quietFailure(err) && stage != "relay" {
			f.setError(err)
			f.connectionOutcome(err, stage)
		}
		f.end("ok")
	}()
	if err = forwardSniffed(fctx, out, first); err != nil {
		return err
	}
	stage = "relay"
	return s.relay(fctx, sc, out)
}
func (i *TUNIngress) HandleUDP(parent context.Context, t tunstack.Flow, c net.Conn) error {
	s, ctx, done, e := i.begin(parent, t, c, tunstack.UDP)
	if e != nil {
		return e
	}
	defer done()
	return s.tunUDP(ctx, t, c)
}

func timeoutError(e error) bool     { var ne net.Error; return errors.As(e, &ne) && ne.Timeout() }
func maxActivity(a *udpAssociation) { a.touchActivity(time.Now()) } // monotonic activity across concurrent TUN send/return paths
