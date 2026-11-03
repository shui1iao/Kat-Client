package clientcore

import (
	"context"
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
	closed     bool
	wg         sync.WaitGroup
}

func newHTTPBridge(hp, sp int) (*httpBridge, error) {
	ln, e := net.Listen("tcp4", portAddress(hp))
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &httpBridge{listener: ln, ctx: ctx, cancel: cancel, transports: map[net.Conn]*http.Transport{}}
	b.setSOCKSPort(sp)
	b.transport = &http.Transport{Proxy: nil, DialContext: b.dial, DisableCompression: true, MaxResponseHeaderBytes: 64 << 10, ResponseHeaderTimeout: 30 * time.Second}
	b.server = &http.Server{Handler: b, DisableGeneralOptionsHandler: true, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 64 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	b.server.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		t := b.transport.Clone()
		origin := procattr.NewOrigin(c.RemoteAddr(), c.LocalAddr())
		b.mu.Lock()
		b.transports[c] = t
		b.mu.Unlock()
		return context.WithValue(ctx, httpOriginKey{}, &httpOrigin{origin: origin, transport: t})
	}
	b.server.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateClosed || state == http.StateHijacked {
			b.mu.Lock()
			t := b.transports[c]
			delete(b.transports, c)
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
func (b *httpBridge) start() { go func() { _ = b.server.Serve(b.listener) }() }
func (b *httpBridge) close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
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
	d, e := proxy.SOCKS5("tcp", b.socks.Load().(string), nil, &httpForward{origin: origin})
	if e != nil {
		return nil, e
	}
	return d.(proxy.ContextDialer).DialContext(ctx, network, address)
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
	b.wg.Add(1)
	b.mu.Unlock()
	defer b.wg.Done()
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
		transport = v.transport
	}
	resp, e := transport.RoundTrip(req)
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
	_, _ = io.Copy(w, resp.Body)
}
func (b *httpBridge) connect(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	host, port, e := net.SplitHostPort(r.Host)
	if e != nil || host == "" || port == "" {
		http.Error(w, "CONNECT host:port required", 400)
		return
	}
	up, e := b.dial(ctx, "tcp", r.Host)
	if e != nil {
		http.Error(w, "Kat outbound unavailable", 502)
		return
	}
	defer up.Close()
	hij, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "CONNECT unavailable", 500)
		return
	}
	client, rw, e := hij.Hijack()
	if e != nil {
		return
	}
	defer client.Close()
	stop := context.AfterFunc(ctx, func() { client.Close(); up.Close() })
	defer stop()
	if _, e = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil {
		return
	}
	if rw.Flush() != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(up, rw)
		if cw, ok := up.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = up.Close()
		}
		close(done)
	}()
	_, _ = io.Copy(client, up)
	client.Close()
	up.Close()
	<-done
}

// retire closes only the old accepting socket. Existing CONNECT/HTTP bodies
// survive a normal document reload; EOF/Stop owns their final cancellation.
func (b *httpBridge) retire() { b.listener.Close(); b.server.SetKeepAlivesEnabled(false) }

type httpOriginKey struct{}
type httpOrigin struct {
	origin    *procattr.Origin
	transport *http.Transport
}
type httpForward struct{ origin *procattr.Origin }

func (f *httpForward) Dial(network, address string) (net.Conn, error) {
	return f.DialContext(context.Background(), network, address)
}
func (f *httpForward) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return procattr.RegisterHTTP(c, f.origin), nil
}
