package kernel

import (
	"context"
	"encoding/json"
	"io"
	"net"

	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/group"
)

// End-to-end local only: actual HTTP warm/cold probes, SOCKS TCP/UDP and
// first-response observations through current kernel wiring. No simulated RTT.

type smartTraceHop struct {
	name   string
	slow   bool
	closed chan struct{}
}

func (h *smartTraceHop) Name() string { return h.name }
func (h *smartTraceHop) Type() string { return "fixture" }
func (h *smartTraceHop) Close() error { return nil }
func (h *smartTraceHop) UDP() bool    { return false }
func (h *smartTraceHop) ListenPacket(context.Context) (outbound.PacketConn, error) {
	return nil, outbound.ErrUDPUnsupported
}
func (h *smartTraceHop) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	if h.slow {
		<-ctx.Done()
		close(h.closed)
		return nil, ctx.Err()
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", dst.String())
}
func TestSmartRestoreAdaptiveWinnerTraceAndLoserRelease(t *testing.T) {
	dst := echoTCP(t)
	addr := outbound.Addr{Host: dst.Host, Port: dst.Port}
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			loser := &smartTraceHop{name: "slow", slow: true, closed: make(chan struct{})}
			winner := &smartTraceHop{name: "winner"}
			g, e := group.New(group.Options{Name: "smart", Type: "smart", Members: []string{"slow", "winner"}, Smart: &group.SmartOptions{AdaptiveDial: &enabled}, Probe: &group.ProbeOptions{URL: "http://127.0.0.1:9/"}}, []outbound.Outbound{member{loser}, member{winner}}, nil)
			if e != nil {
				t.Fatal(e)
			}
			defer g.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			h := &hops{}
			start := time.Now()
			conn, e := g.DialTCP(withHops(ctx, h), addr)
			if !enabled {
				if e == nil {
					conn.Close()
					t.Fatal("adaptive disabled unexpectedly hedged")
				}
				select {
				case <-loser.closed:
				case <-time.After(time.Second):
					t.Fatal("canceled primary leaked")
				}
				if len(h.names) != 0 {
					t.Fatal("failed trace committed")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			if time.Since(start) > 2800*time.Millisecond {
				t.Fatal("hedge waited caller timeout")
			}
			if !echoOnce(conn, "winner-only") {
				t.Fatal("winner payload")
			}
			select {
			case <-loser.closed:
			case <-time.After(time.Second):
				t.Fatal("loser not canceled")
			}
			if !reflect.DeepEqual(h.chain("smart"), []string{"smart", "winner"}) {
				t.Fatal("losing trace committed", h.chain("smart"))
			}
			b, _ := json.Marshal(g.(group.Snapshotter).Snapshot())
			if len(b) == 0 {
				t.Fatal("snapshot missing")
			}
			t.Log("only winning branch trace committed; loser canceled; application wrote once after winner")
		})
	}
}

type smartLateHop struct {
	*smartTraceHop
	pipe    net.Conn
	release <-chan struct{}
}

func (h *smartLateHop) DialTCP(context.Context, outbound.Addr) (net.Conn, error) {
	<-h.release
	return h.pipe, nil
}
func TestSmartRestoreLateLoserSocketClosed(t *testing.T) {
	dst := echoTCP(t)
	raw, peer := net.Pipe()
	defer raw.Close()
	defer peer.Close()
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	a := &smartLateHop{smartTraceHop: &smartTraceHop{name: "late"}, pipe: raw, release: release}
	b := &smartTraceHop{name: "winner"}
	g, e := group.New(group.Options{Name: "S", Type: "smart", Members: []string{"late", "winner"}, Probe: &group.ProbeOptions{URL: "http://127.0.0.1:9/"}}, []outbound.Outbound{member{a}, member{b}}, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer g.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	h := &hops{}
	c, e := g.DialTCP(withHops(ctx, h), outbound.Addr{Host: dst.Host, Port: dst.Port})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	if !echoOnce(c, "one-application-write") {
		t.Fatal("winner failed")
	}
	once.Do(func() { close(release) })
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if n, e := peer.Read(make([]byte, 1)); n != 0 || e != io.EOF {
		t.Fatal("late loser socket leaked or replayed data", n, e)
	}
	if !reflect.DeepEqual(h.chain("S"), []string{"S", "winner"}) {
		t.Fatal("late loser trace committed")
	}
	if g.(group.Snapshotter).Snapshot().Members[0].SampleCount != 0 {
		t.Fatal("loser learned success")
	}
}
