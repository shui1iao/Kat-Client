package group

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

type lazyOpenMember struct {
	*fakeOut
	open func(context.Context) (outbound.PacketConn, error)
}

func (m *lazyOpenMember) ListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	return m.open(ctx)
}

func TestLBLazyRetryCloseAndWriteDeadline(t *testing.T) {
	for _, closePacket := range []bool{false, true} {
		name := "deadline"
		if closePacket {
			name = "close"
		}
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				a := newFake("a")
				a.lpErr = errors.New("member unavailable")
				entered := make(chan struct{})
				late := &fakePC{closed: make(chan struct{})}
				b := &lazyOpenMember{newFake("b"), func(ctx context.Context) (outbound.PacketConn, error) { close(entered); <-ctx.Done(); return late, nil }}
				c := newFake("c")
				g := newAuto(t, Options{Type: TypeLoadBalance, Strategy: StrategyRoundRobin, Fixed: "a"}, members(a, b, c), newFakeClock(), nil, nil)
				setup, stop := context.WithCancel(context.Background())
				pc, e := g.ListenPacket(setup)
				if e != nil {
					t.Fatal(e)
				}
				stop()
				defer pc.Close()
				dst := outbound.Addr{Host: "example.test", Port: 53}
				result := make(chan error, 1)
				// The setup caller can return; opening lazy members belongs to the packet session.
				if err := pc.SetWriteDeadline(time.Now().Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
				go func() { _, err := pc.WriteTo([]byte("q"), dst); result <- err }()
				<-entered
				if err := pc.SetWriteDeadline(time.Time{}); err != nil {
					t.Fatal(err)
				}
				var want error = net.ErrClosed
				if closePacket {
					pc.Close()
				} else {
					want = os.ErrDeadlineExceeded
					pc.SetWriteDeadline(time.Now().Add(time.Millisecond))
					time.Sleep(2 * time.Millisecond)
				}
				select {
				case got := <-result:
					if !errors.Is(got, want) {
						t.Fatal(got)
					}
				case <-time.After(time.Second):
					t.Fatal("lazy open not interrupted")
				}
				select {
				case <-late.closed:
				default:
					t.Fatal("late member result not closed")
				}
				if c.lps != 0 || a.lps != 1 || g.st[1].consec != 0 {
					t.Fatal("cancellation retried or counted member failure", a.lps, c.lps, g.st[1].consec)
				}
				if !closePacket {
					if _, err := pc.WriteTo(nil, dst); !errors.Is(err, os.ErrDeadlineExceeded) || a.lps != 1 {
						t.Fatal("expired write opened a member", err)
					}
				}
			})
		})
	}
}

type pipeWritePacket struct {
	*fakePC
	carrier net.Conn
}

func (p *pipeWritePacket) WriteTo(b []byte, _ outbound.Addr) (int, error) { return p.carrier.Write(b) }
func (p *pipeWritePacket) SetWriteDeadline(t time.Time) error             { return p.carrier.SetWriteDeadline(t) }
func (p *pipeWritePacket) Close() error                                   { p.carrier.Close(); return p.fakePC.Close() }

func TestLBDeadlineReachesPendingMemberWrite(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		local, peer := net.Pipe()
		defer peer.Close()
		member := &lazyOpenMember{newFake("m"), func(context.Context) (outbound.PacketConn, error) {
			return &pipeWritePacket{&fakePC{closed: make(chan struct{})}, local}, nil
		}}
		g := newAuto(t, Options{Type: TypeLoadBalance, Strategy: StrategyRoundRobin}, members(member), newFakeClock(), nil, nil)
		pc, err := g.ListenPacket(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		result := make(chan error, 1)
		go func() { _, err := pc.WriteTo([]byte("q"), outbound.Addr{Host: "test", Port: 53}); result <- err }()
		synctest.Wait()
		pc.SetWriteDeadline(time.Now().Add(time.Millisecond))
		select {
		case got := <-result:
			if !errors.Is(got, os.ErrDeadlineExceeded) {
				t.Fatal(got)
			}
		case <-time.After(time.Second):
			t.Fatal("blocked write missed updated deadline")
		}
	})
}
