package clientcore

import (
	"context"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/procattr"
	"golang.org/x/net/proxy"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func portAddress(n int) string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(n)) }

type httpBridge struct {
	listener   net.Listener
	server     *http.Server
	transport  *http.Transport
	transports map[net.Conn]*http.Transport
	socks      atomic.Value
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.Mutex
	conns      int
	inFlight   int
	serveDone  bool
	retired    bool
	closed     bool
	wg         sync.WaitGroup
	log        func(kernel.ClientLogEvent)
}

func newHTTPBridge(hp, sp int, sinks ...func(kernel.ClientLogEvent)) (*httpBridge, error) {
	ln, e := net.Listen("tcp4", portAddress(hp))
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &httpBridge{listener: ln, ctx: ctx, cancel: cancel, transports: map[net.Conn]*http.Transport{}}
	if len(sinks) > 0 {
		b.log = sinks[0]
	}
	b.setSOCKSPort(sp)
	b.transport = &http.Transport{Proxy: nil, DialContext: b.dial, DisableCompression: true, MaxResponseHeaderBytes: 64 << 10, ResponseHeaderTimeout: 30 * time.Second}
	b.server = &http.Server{Handler: b, DisableGeneralOptionsHandler: true, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	b.server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		origin := procattr.NewOrigin(c.RemoteAddr(), c.LocalAddr())
		b.mu.Lock()
		b.conns++
		b.mu.Unlock()
		return context.WithValue(ctx, httpOriginKey{}, &httpOrigin{conn: c, origin: origin, bridgeID: nextHTTPObservationID.Add(1)})
	}
	b.server.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateClosed || state == http.StateHijacked {
			b.mu.Lock()
			t := b.transports[c]
			delete(b.transports, c)
			if state == http.StateClosed && b.conns > 0 {
				b.conns--
			}
			b.tryFinishRetireLocked()
			b.mu.Unlock()
			if t != nil {
				t.CloseIdleConnections()
			}
		}
	}

	return b, nil
}
func (b *httpBridge) setSOCKSPort(p int) {
	b.socks.Store(portAddress(p))
	b.mu.Lock()
	for _, t := range b.transports {
		t.CloseIdleConnections()
	}
	b.mu.Unlock()
	if b.transport != nil {
		b.transport.CloseIdleConnections()
	}
}
func (b *httpBridge) start() {
	go func() {
		_ = b.server.Serve(b.listener)
		b.mu.Lock()
		b.serveDone = true
		b.tryFinishRetireLocked()
		b.mu.Unlock()
	}()
}
func (b *httpBridge) close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		b.wg.Wait()
		return
	}
	b.closed = true
	b.cancel()
	b.mu.Unlock()
	b.listener.Close()
	b.server.Close()
	b.transport.CloseIdleConnections()
	b.wg.Wait()
}
func (b *httpBridge) dial(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var origin *procattr.Origin
	if v, _ := ctx.Value(httpOriginKey{}).(*httpOrigin); v != nil {
		origin = v.origin
	}
	forward := &httpForward{origin: origin, trace: httpTraceOf(ctx)}
	d, e := proxy.SOCKS5("tcp", b.socks.Load().(string), nil, forward)
	if e != nil {
		return nil, e
	}
	up, e := d.(proxy.ContextDialer).DialContext(ctx, network, address)
	if e != nil {
		return nil, e
	}
	// x/net's SOCKS Conn embeds only net.Conn, so its type hides the TCP
	// half-close supported by our registered local transport. Preserve that
	// capability instead of closing the response side at request EOF.
	if half, ok := forward.conn.(interface{ CloseWrite() error }); ok {
		return &httpSOCKSConn{Conn: up, writer: half}, nil
	}
	return up, nil
}
func stripHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, n := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(n))
		}
	}
	for _, k := range []string{"Connection", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(k)
	}
}
func (b *httpBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		http.Error(w, "Proxy stopped", 503)
		return
	}
	b.inFlight++
	b.wg.Add(1)
	b.mu.Unlock()
	defer func() {
		b.wg.Done()
		b.mu.Lock()
		b.inFlight--
		b.tryFinishRetireLocked()
		b.mu.Unlock()
	}()
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stop := context.AfterFunc(b.ctx, cancel)
	defer stop()
	// Reserved local protocol health check performs no physical egress.
	if r.Method == http.MethodOptions && r.RequestURI == "*" {
		w.Header().Set("Kat-Client-Proxy", "1")
		w.WriteHeader(204)
		return
	}
	trace := b.newTrace(ctx, r.Method == http.MethodConnect)
	ctx = context.WithValue(ctx, httpTraceKey{}, trace)
	if r.Method == http.MethodConnect {
		b.connect(ctx, w, r)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil {
		http.Error(w, "Absolute HTTP URL required", 400)
		return
	}
	req := r.Clone(ctx)
	req.RequestURI = ""
	stripHop(req.Header)
	transport := b.transport
	if v, _ := ctx.Value(httpOriginKey{}).(*httpOrigin); v != nil {
		transport = v.transportFor(b)
	}
	resp, e := transport.RoundTrip(req)
	trace.record("response_header", "none", "", e, 0)
	if e != nil {
		http.Error(w, "Kat outbound unavailable", 502)
		return
	}
	defer resp.Body.Close()
	stripHop(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, copyErr := io.Copy(w, resp.Body)
	trace.record("copy_end", "socks_to_client", "", copyErr, 0)
}
func (b *httpBridge) connect(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	host, port, e := net.SplitHostPort(r.Host)
	if e != nil || host == "" || port == "" {
		http.Error(w, "CONNECT host:port required", 400)
		return
	}
	trace := httpTraceOf(ctx)
	up, e := b.dial(ctx, "tcp", r.Host)
	trace.record("dial_end", "none", "", e, 0)
	if e != nil {
		http.Error(w, "Kat outbound unavailable", 502)
		return
	}
	defer trace.close("socks", "handler_return", 0, up.Close)
	hij, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT unavailable", 500)
		return
	}
	client, rw, e := hij.Hijack()
	if e != nil {
		return
	}
	b.mu.Lock()
	if b.conns > 0 {
		b.conns--
	}
	b.mu.Unlock()
	defer trace.close("client", "handler_return", 0, client.Close)
	// After Hijack, net/http's buffered reader may cancel the request context
	// on a normal upload EOF. The tunnel still owns the response direction.
	// Keep bridge shutdown cancellation, but not that HTTP request lifetime.
	tunnelCtx, cancelTunnel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelTunnel()
	stopBridge := context.AfterFunc(b.ctx, cancelTunnel)
	defer stopBridge()
	stop := context.AfterFunc(tunnelCtx, func() {
		trace.close("client", "context_done", 0, client.Close)
		trace.close("socks", "context_done", 0, up.Close)
	})
	defer stop()
	if _, e = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil {
		trace.record("response_header", "socks_to_client", "", e, 0)
		return
	}
	if flushErr := rw.Flush(); flushErr != nil {
		trace.record("response_header", "socks_to_client", "", flushErr, 0)
		return
	}
	done := make(chan struct{})
	go func() {
		_, copyErr := io.Copy(up, rw)
		observed := trace.record("copy_end", "client_to_socks", "", copyErr, 0)
		if copyErr != nil {
			trace.close("client", "upload_return", observed, client.Close)
			trace.close("socks", "upload_return", observed, up.Close)
			close(done)
			return
		}
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			trace.halfClose("socks", "upload_return", observed, cw.CloseWrite)
		} else {
			trace.close("socks", "upload_return", observed, up.Close)
		}
		close(done)
	}()
	_, copyErr := io.Copy(client, up)
	observed := trace.record("copy_end", "socks_to_client", "", copyErr, 0)
	trace.close("client", "download_return", observed, client.Close)
	trace.close("socks", "download_return", observed, up.Close)
	<-done
}

// retire closes only the old accepting socket. Existing CONNECT/HTTP bodies
// survive a normal document reload; EOF/Stop owns their final cancellation.
func (b *httpBridge) retire() {
	b.listener.Close()
	b.server.SetKeepAlivesEnabled(false)
	b.mu.Lock()
	if b.retired || b.closed {
		b.mu.Unlock()
		return
	}
	b.retired = true
	for _, t := range b.transports {
		t.CloseIdleConnections()
	}
	b.tryFinishRetireLocked()
	b.mu.Unlock()
	if b.transport != nil {
		b.transport.CloseIdleConnections()
	}
}

func (b *httpBridge) tryFinishRetireLocked() {
	if !b.retired || b.closed || !b.serveDone || b.conns != 0 || b.inFlight != 0 {
		return
	}
	b.closed = true
	b.cancel()
	if b.transport != nil {
		b.transport.CloseIdleConnections()
	}
}

func (b *httpBridge) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

type httpOriginKey struct{}
type httpOrigin struct {
	conn      net.Conn
	origin    *procattr.Origin
	transport *http.Transport
	bridgeID  uint64
}

func (o *httpOrigin) transportFor(b *httpBridge) *http.Transport {
	b.mu.Lock()
	defer b.mu.Unlock()
	if o.transport != nil {
		return o.transport
	}
	t := b.transport.Clone()
	o.transport = t
	if o.conn != nil && !b.closed {
		b.transports[o.conn] = t
	}
	return t
}

type httpSOCKSConn struct {
	net.Conn
	writer interface{ CloseWrite() error }
}

func (c *httpSOCKSConn) CloseWrite() error { return c.writer.CloseWrite() }

type httpForward struct {
	origin *procattr.Origin
	trace  *httpTrace
	conn   net.Conn
}

func (f *httpForward) Dial(network, address string) (net.Conn, error) {
	return f.DialContext(context.Background(), network, address)
}
func (f *httpForward) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	f.conn = procattr.RegisterHTTP(c, f.origin, f.trace.registration())
	return f.conn, nil
}
