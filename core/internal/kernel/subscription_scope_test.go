package kernel

import (
	"context"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/procattr"
	"io"
	"net"
	"net/netip"
	"testing"
)

// The duplex socket is memory only: verify the private registration is captured
// before the library receives the greeting reply, not through SOCKS user input.
type scopePipe struct {
	net.Conn
	local, remote net.Addr
}

func (c scopePipe) LocalAddr() net.Addr  { return c.local }
func (c scopePipe) RemoteAddr() net.Addr { return c.remote }
func TestSubscriptionSOCKSRegistrationScope(t *testing.T) {
	for _, pub := range []bool{true, false} {
		l, r := net.Pipe()
		src := net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:40400"))
		dst := net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:40401"))
		c := net.Conn(scopePipe{l, src, dst})
		peer := scopePipe{r, dst, src}
		if pub {
			c = procattr.RegisterPublicTarget(c)
		}
		rc := make(chan struct {
			q request
			e error
		}, 1)
		go func() {
			q, e := parseSOCKS(peer, Inbound{})
			rc <- struct {
				q request
				e error
			}{q, e}
		}()
		c.Write([]byte{5, 1, 0})
		var reply [2]byte
		io.ReadFull(c, reply[:])
		c.Write([]byte{5, 1, 0, 1, 8, 8, 8, 8, 1, 187})
		c.Close()
		out := <-rc
		peer.Close()
		if out.e != nil || out.q.publicTarget != pub || procattr.PublicTargetSocket(peer) {
			t.Fatal("incorrect request/registration lifetime", out.e)
		}
	}
	ctx := outbound.WithPublicTarget(context.Background())
	if outbound.PublicTargetOnly(strip(ctx)) || !outbound.PublicTargetOnly(ctx) {
		t.Fatal("proxy carrier confused with resource target")
	}
}
