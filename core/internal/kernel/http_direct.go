package kernel

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/procattr"
	"net"
	"strconv"
	"sync"
)

type httpDirectOriginKey struct{}

type httpDirectOrigin struct {
	origin *procattr.Origin
	obs    *procattr.HTTPObservation
}

// HTTPDirectParams describes one local HTTP proxy connection or request to be
// routed directly by the current kernel generation without a loopback SOCKS5 hop.
type HTTPDirectParams struct {
	Local       net.Addr
	Remote      net.Addr
	Origin      *procattr.Origin
	Observation *procattr.HTTPObservation
}

func parseHostPortTarget(address string) (Address, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil || host == "" {
		return Address{}, errors.New("invalid target address")
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || p == 0 {
		return Address{}, errors.New("invalid target port")
	}
	return Address{Host: host, Port: uint16(p)}, nil
}

func (s *Server) beginHTTPDirect(c net.Conn, p HTTPDirectParams) (*Server, context.Context, func(), error) {
	if s == nil || s.core == nil {
		return nil, nil, nil, ErrCoreNotRunning
	}
	g := s.current()
	if !g.tryRef() {
		return nil, nil, nil, ErrCoreNotRunning
	}
	if !g.connSlots.try() {
		g.unref()
		g.counters.Rejected.Add(1)
		return nil, nil, nil, errors.New("connection budget exhausted")
	}
	g.mu.Lock()
	if g.closing {
		g.mu.Unlock()
		g.connSlots.release()
		g.unref()
		return nil, nil, nil, ErrCoreNotRunning
	}
	g.active[c] = &acceptedState{}
	g.wg.Add(1)
	g.mu.Unlock()
	g.counters.Accepted.Add(1)
	g.counters.Active.Add(1)

	in := Inbound{Name: "kat-client", Protocol: "http", logIndex: -1}
	statIdx := -1
	for idx, v := range g.cfg.Inbounds {
		if v.Name == "kat-client" {
			in.Sniff = v.Sniff
			statIdx = idx
			break
		}
	}
	remoteAddr := p.Remote
	if remoteAddr == nil && c != nil {
		remoteAddr = c.RemoteAddr()
	}
	localAddr := p.Local
	if localAddr == nil && c != nil {
		localAddr = c.LocalAddr()
	}
	ctx := withInboundMeta(withInbound(withSource(g.trafficContext(), remoteAddr), statIdx), &in, localAddr, remoteAddr)
	if statIdx >= 0 && g.keys != nil && statIdx < len(g.keys.inbound) {
		ctx = context.WithValue(ctx, inStatKey{}, inStat{c: g.keys.inbound[statIdx], key: g.keys.inKeys[statIdx]})
	}
	if p.Origin != nil || p.Observation != nil {
		ctx = context.WithValue(ctx, httpDirectOriginKey{}, &httpDirectOrigin{origin: p.Origin, obs: p.Observation})
	}
	var lifeStop func() bool
	if g.clientLife != nil && c != nil {
		lifeStop = context.AfterFunc(g.clientLife, func() { _ = c.Close() })
	}
	var once sync.Once
	done := func() {
		once.Do(func() {
			if lifeStop != nil {
				lifeStop()
			}
			if c != nil {
				_ = c.Close()
			}
			g.mu.Lock()
			delete(g.active, c)
			g.mu.Unlock()
			g.counters.Active.Add(-1)
			g.connSlots.release()
			g.unref()
			g.wg.Done()
		})
	}
	return g, ctx, done, nil
}

// ServeHTTPConnect routes an accepted HTTP CONNECT client socket directly through
// the kernel's sniff -> dial -> relay pipeline (zero loopback TCP/SOCKS5 hop).
// respond200 is called once the outbound connection succeeds (or earlier when
// sniffing requires the client's first payload bytes).
func (s *Server) ServeHTTPConnect(tunnelCtx context.Context, client net.Conn, targetAddr string, p HTTPDirectParams, respond200 func() error) (err error) {
	target, err := parseHostPortTarget(targetAddr)
	if err != nil {
		return err
	}
	g, ctx, done, err := s.beginHTTPDirect(client, p)
	if err != nil {
		return err
	}
	defer done()
	stopTunnel := context.AfterFunc(tunnelCtx, func() { _ = client.Close() })
	defer stopTunnel()

	ctx = withOriginalTarget(ctx, target)
	sctx, sc, first, responded, err := g.sniffTCP(ctx, client, target, respond200)
	if err != nil {
		return err
	}
	f, fctx := g.newFlow(sctx, "tcp", target)
	out, err := g.dial(fctx, target)
	if err != nil {
		f.end(dialResult(err))
		return err
	}
	stage := "response"
	defer func() {
		if !quietFailure(err) && stage != "relay" {
			f.setError(err)
			f.connectionOutcome(err, stage)
		}
		f.end("ok")
	}()
	defer out.Close()
	if !responded && respond200 != nil {
		if err = respond200(); err != nil {
			if !quietFailure(err) {
				g.failure(failTCPIO, "http", -1)
			}
			return err
		}
	}
	stage = "initial_write"
	if err = forwardSniffed(fctx, out, first); err != nil {
		return err
	}
	stage = "relay"
	err = g.relay(fctx, sc, out)
	if !quietFailure(err) {
		g.failure(failTCPIO, "http", -1)
	}
	return err
}

type directDialConn struct {
	net.Conn
	f       *flow
	up      meter
	down    meter
	done    func()
	endOnce sync.Once
}

func (c *directDialConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.down.add(n)
	return n, err
}

func (c *directDialConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.up.add(n)
	return n, err
}

func (c *directDialConn) CloseWrite() error {
	return closeWrite(c.Conn)
}

func (c *directDialConn) Close() error {
	err := c.Conn.Close()
	c.endOnce.Do(func() {
		if c.f != nil {
			c.f.end("ok")
		}
		if c.done != nil {
			c.done()
		}
	})
	return err
}

// DialHTTPDirect dials an outbound connection for plain HTTP proxy RoundTrip
// requests directly through the kernel without a loopback SOCKS5 socket.
func (s *Server) DialHTTPDirect(reqCtx context.Context, targetAddr string, p HTTPDirectParams) (net.Conn, error) {
	target, err := parseHostPortTarget(targetAddr)
	if err != nil {
		return nil, err
	}
	anchor, peer := net.Pipe()
	_ = peer.Close()
	g, ctx, done, err := s.beginHTTPDirect(anchor, p)
	if err != nil {
		_ = anchor.Close()
		return nil, err
	}
	ctx = withOriginalTarget(ctx, target)
	f, fctx := g.newFlow(ctx, "tcp", target)
	dialCtx, cancel := context.WithCancel(fctx)
	stopReq := context.AfterFunc(reqCtx, cancel)
	out, err := g.dial(dialCtx, target)
	stopReq()
	cancel()
	if err != nil {
		if f != nil {
			f.end(dialResult(err))
		}
		done()
		return nil, err
	}
	if f != nil {
		ctx = outbound.WithDialObserver(fctx, nil)
	}
	up, down := meters(fctx)
	dc := &directDialConn{Conn: out, f: f, up: up, down: down, done: done}
	if f != nil && f.cancel != nil {
		context.AfterFunc(fctx, func() { _ = dc.Close() })
	}
	if g.clientLife != nil {
		context.AfterFunc(g.clientLife, func() { _ = dc.Close() })
	}
	return dc, nil
}
