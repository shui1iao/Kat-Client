package tunstack

import (
	"context"
	"errors"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"net"
	"net/netip"
	"testing"
	"time"
)

type drainingIngress struct {
	entered  chan *sourceConn
	canceled chan struct{}
	release  chan struct{}
}

func (*drainingIngress) HandleTCP(context.Context, Flow, TCPConn) error { return nil }
func (h *drainingIngress) HandleUDP(ctx context.Context, _ Flow, c net.Conn) error {
	h.entered <- c.(*sourceConn)
	<-ctx.Done()
	c.Close()
	close(h.canceled)
	<-h.release
	return ctx.Err()
}
func TestQuiesceDrainsUDPWorkAfterSourceHasClosed(t *testing.T) {
	h := &drainingIngress{make(chan *sourceConn, 1), make(chan struct{}), make(chan struct{})}
	r := &Runtime{ctx: context.Background(), cfg: Config{Ingress: h, Admitting: func() bool { return true }, Epoch: func() uint64 { return 3 }}, active: map[net.Conn]struct{}{}, udpSources: map[sourceKey]*sourceConn{}}
	m2Input(t, netip.MustParseAddrPort("10.50.0.2:3456"), netip.MustParseAddrPort("203.0.113.1:4444"), func([]byte) {}, func(p *stack.PacketBuffer, id stack.TransportEndpointID) { r.udpPacket(id, p) })
	select {
	case c := <-h.entered:
		if !c.DatagramCurrent() {
			t.Fatal("initial source fenced")
		}
	case <-time.After(time.Second):
		t.Fatal("no admission")
	}
	r.Quiesce()
	select {
	case <-h.canceled:
	case <-time.After(time.Second):
		t.Fatal("quiesce did not cancel the sender")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.DrainUDP(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("pending work permitted owner replacement", err)
	}
	close(h.release)
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.DrainUDP(ctx); err != nil {
		t.Fatal(err)
	}
	r.wg.Wait()
	if len(r.udpSources) != 0 || r.udpQueuedBytes != 0 || r.udpHandlers != 0 {
		t.Fatal("source resources retained")
	}
}
