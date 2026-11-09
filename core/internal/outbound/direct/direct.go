// Package direct is Kat's built-in first-hop dialer. It does not consult
// routing rules: callers (kernel, proxy outbounds) have already decided that
// the destination is to be reached directly.
package direct

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
)

// Options configures the direct dialer. All fields may be zero.
type Options struct {
	DisableIPv6 bool
	// PacketSource selects the local source BEFORE net.ListenUDP binds a remote
	// socket. It must not bind itself. nil keeps the configured/default source;
	// errors abort creation without falling back to a wildcard socket.
	PacketSource func(network string, configured netip.Addr) (netip.Addr, error)
	// PacketControl is client-only physical binding for REMOTE datagrams.
	// Literal loopback continues to use separate ordinary local sockets.
	PacketControl func(network string, c *net.UDPConn) error
	PacketRelease func(*net.UDPConn)
	DialContext   func(context.Context, string, string) (net.Conn, error)
	PacketFailure func()
	// Resolve resolves a domain name (kernel-injected, uses Kat's dns settings).
	// nil uses the system resolver.
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// BindIPv4/BindIPv6 are the local UDP bind addresses (udp_bind_ipv4/ipv6).
	BindIPv4, BindIPv6 netip.Addr
	// Timeout bounds one DialTCP (resolution plus all candidate attempts) and
	// one WriteTo domain resolution. Zero means only the caller's ctx applies
	// (resolution inside WriteTo then uses a 5s bound).
	Timeout time.Duration
	// Guard, when set, is asked for every resolved destination address of a
	// DialTCP and of every datagram of a PacketConn (with the ctx given to
	// DialTCP / ListenPacket). Returning true refuses that address with
	// ErrBlocked. The kernel uses it to keep proxied client traffic away from
	// local addresses; Kat's own traffic (probes, downloads) is never refused.
	Guard func(ctx context.Context, ip netip.Addr) bool
	// Control, when set, is the net.Dialer ControlContext of TCP dials (the
	// kernel uses it for TCP Fast Open).
	Control func(ctx context.Context, network, address string, c syscall.RawConn) error
}

// Outbound implements outbound.Outbound for direct connections.
type Outbound struct{ o Options }

var _ outbound.Outbound = (*Outbound)(nil)

// New returns a direct outbound. It performs no I/O.
func New(o Options) *Outbound { return &Outbound{o: o} }

func (d *Outbound) Name() string { return "direct" }
func (d *Outbound) Type() string { return "direct" }
func (d *Outbound) UDP() bool    { return true }
func (d *Outbound) Close() error { return nil }

// ErrBlocked: every address of the destination was refused by Options.Guard.
var ErrIPv6Disabled = errors.New("ipv6_disabled")

var ErrBlocked = errors.New("direct: destination address not allowed")

var (
	errZeroPort   = errors.New("direct: zero destination port")
	errNoAddress  = errors.New("direct: no usable address")
	errDialFailed = errors.New("direct: all candidate addresses failed")
)

func (d *Outbound) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.Zone() != "" {
			return nil, errNoAddress
		}
		if d.o.DisableIPv6 && ip.Unmap().Is6() {
			return nil, ErrIPv6Disabled
		}
		return []netip.Addr{ip.Unmap()}, nil
	}
	var ips []netip.Addr
	var e error
	if d.o.Resolve != nil {
		ips, e = d.o.Resolve(ctx, host)
	} else {
		ips, e = net.DefaultResolver.LookupNetIP(ctx, map[bool]string{true: "ip4", false: "ip"}[d.o.DisableIPv6], host)
	}
	if e != nil {
		return nil, e
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.IsValid() && ip.Zone() == "" && (!d.o.DisableIPv6 || ip.Unmap().Is4()) {
			out = append(out, ip.Unmap())
		}
	}
	if len(out) == 0 {
		return nil, errNoAddress
	}
	return out, nil
}

// DialTCP resolves dst (when it is a name) and dials the candidates in order.
func (d *Outbound) DialTCP(ctx context.Context, dst outbound.Addr) (net.Conn, error) {
	started := time.Now()
	if dst.Port == 0 {
		return nil, errZeroPort
	}
	if d.o.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.o.Timeout)
		defer cancel()
	}
	ips, e := d.resolve(ctx, dst.Host)
	if e != nil {
		outbound.ReportError(ctx, "direct", "dns_lookup", e, started)
		return nil, e
	}
	if d.o.Guard != nil {
		allowed := ips[:0:0]
		for _, ip := range ips {
			if !d.o.Guard(ctx, ip) {
				allowed = append(allowed, ip)
			}
		}
		if len(allowed) == 0 {
			return nil, ErrBlocked
		}
		ips = allowed
	}
	outbound.ObserveDial(ctx, ips, netip.Addr{})
	var last error
	for _, ip := range ips {
		dial := (&net.Dialer{ControlContext: d.o.Control}).DialContext
		if d.o.DialContext != nil {
			dial = d.o.DialContext
		}
		c, e := dial(ctx, "tcp", netip.AddrPortFrom(ip, dst.Port).String())
		if e == nil {
			outbound.ObserveDial(ctx, ips, ip)
			return c, nil
		}
		outbound.ReportError(ctx, "direct", "connect", e, started)
		last = e
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if last == nil {
		last = errDialFailed
	}
	return nil, last
}

// ListenPacket returns a PacketConn that can send to IPv4 and IPv6 targets.
// Ordinary callers accept exact previously written peers. The trusted TUN
// adapter explicitly requests EIF; every outbound datagram still passes Guard.
func (d *Outbound) ListenPacket(ctx context.Context) (outbound.PacketConn, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	p := &packetConn{eif: outbound.EndpointIndependent(ctx), observe: func(ips []netip.Addr, ip netip.Addr) { outbound.ObserveDial(ctx, ips, ip) }, d: d, sent: map[netip.AddrPort]struct{}{}, names: map[string]netip.Addr{}, in: make(chan datagram, inboxSize), closed: make(chan struct{}), failure: make(chan error, 1)}
	if g := d.o.Guard; g != nil {
		p.guard = func(ip netip.Addr) bool { return g(ctx, ip) }
	}
	bind4 := d.o.BindIPv4
	if !bind4.IsValid() {
		bind4 = netip.IPv4Unspecified()
	}
	bind6 := d.o.BindIPv6
	if !bind6.IsValid() {
		bind6 = netip.IPv6Unspecified()
	}
	// In controlled EIF mode, unused ordinary sockets must not expose a
	// wildcard/unbound ingress alongside the actual physical-owner socket.
	// Keep only the existing narrow loopback exemption on these sockets.
	if p.eif && d.o.PacketControl != nil {
		bind4, bind6 = netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()
	}
	var e4, e6 error
	p.v4, e4 = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(bind4.Unmap(), 0)))
	if !d.o.DisableIPv6 {
		p.v6, e6 = net.ListenUDP("udp6", net.UDPAddrFromAddrPort(netip.AddrPortFrom(bind6, 0)))
	}
	// An explicitly configured bind address must work; a missing default
	// family (e.g. IPv6 disabled) only removes that family.
	if e4 != nil && (d.o.BindIPv4.IsValid() || e6 != nil) || e6 != nil && d.o.BindIPv6.IsValid() {
		if p.v4 != nil {
			p.v4.Close()
		}
		if p.v6 != nil {
			p.v6.Close()
		}
		if e4 != nil {
			return nil, e4
		}
		return nil, e6
	}
	for _, s := range []*net.UDPConn{p.v4, p.v6} {
		if s != nil {
			p.wg.Add(1)
			go p.reader(s)
		}
	}
	return p, nil
}

const (
	inboxSize         = 64
	maxSent           = 4096
	maxNames          = 64
	maxDatagram       = 65535
	maxEIFQueuedBytes = 256 << 10
)

type datagram struct {
	b   []byte
	src netip.AddrPort
}

type packetConn struct {
	failure          chan error
	eif              bool
	d                *Outbound
	observe          func([]netip.Addr, netip.Addr)
	candidates       []netip.Addr
	remote4, remote6 *net.UDPConn
	wdeadline        time.Time
	v4, v6           *net.UDPConn
	guard            func(netip.Addr) bool

	queuedBytes int // mu; EIF payload budget in addition to inbox slot limit
	mu          sync.Mutex
	sent        map[netip.AddrPort]struct{}
	order       []netip.AddrPort
	names       map[string]netip.Addr
	rdeadline   time.Time
	rchanged    chan struct{}

	in        chan datagram
	closed    chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

func (p *packetConn) allowed(src netip.AddrPort) bool {
	if p.eif {
		return true
	}
	p.mu.Lock()
	_, ok := p.sent[src]
	p.mu.Unlock()
	return ok
}

func (p *packetConn) reader(s *net.UDPConn) {
	defer p.wg.Done()
	buf := make([]byte, maxDatagram)
	for {
		n, src, e := s.ReadFromUDPAddrPort(buf)
		if e != nil {
			var ne net.Error
			if errors.As(e, &ne) && ne.Timeout() {
				continue
			}
			select {
			case <-p.closed:
				return
			default:
			}
			// Transient errors (e.g. ICMP-induced) must not end the session.
			if errors.Is(e, net.ErrClosed) {
				select {
				case p.failure <- e:
				default:
				}
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
		if !p.allowed(src) {
			continue
		}
		p.enqueue(buf[:n], src)
	}
}

// Reserve bytes before copying: a full inbox never retains another large
// datagram. Both slot and payload bounds apply to the trusted EIF adapter.
func (p *packetConn) enqueue(payload []byte, src netip.AddrPort) bool {
	n := len(payload)
	p.mu.Lock()
	if p.eif && n > maxEIFQueuedBytes-p.queuedBytes {
		p.mu.Unlock()
		return false
	}
	p.queuedBytes += n
	p.mu.Unlock()
	b := append([]byte(nil), payload...)
	select {
	case p.in <- datagram{b, src}:
		return true
	case <-p.closed:
	default:
	}
	p.mu.Lock()
	p.queuedBytes -= n
	p.mu.Unlock()
	return false
}

func (p *packetConn) ReadFrom(b []byte) (int, outbound.Addr, error) {
	for {
		p.mu.Lock()
		deadline := p.rdeadline
		if p.rchanged == nil {
			p.rchanged = make(chan struct{})
		}
		changed := p.rchanged
		p.mu.Unlock()
		var timer <-chan time.Time
		var t *time.Timer
		if !deadline.IsZero() {
			d := time.Until(deadline)
			if d <= 0 {
				return 0, outbound.Addr{}, os.ErrDeadlineExceeded
			}
			t = time.NewTimer(d)
			timer = t.C
		}
		select {
		case <-p.closed:
			stopTimer(t)
			return 0, outbound.Addr{}, net.ErrClosed
		case e := <-p.failure:
			stopTimer(t)
			return 0, outbound.Addr{}, e
		case g := <-p.in:
			stopTimer(t)
			p.mu.Lock()
			p.queuedBytes -= len(g.b)
			p.mu.Unlock()
			n := copy(b, g.b)
			return n, outbound.Addr{Host: g.src.Addr().String(), Port: g.src.Port()}, nil
		case <-timer:
			return 0, outbound.Addr{}, os.ErrDeadlineExceeded
		case <-changed:
			stopTimer(t)
		}
	}
}

func stopTimer(t *time.Timer) {
	if t != nil {
		t.Stop()
	}
}

func (p *packetConn) target(dst outbound.Addr) (netip.AddrPort, error) {
	if dst.Port == 0 {
		return netip.AddrPort{}, errZeroPort
	}
	if ip, ok := dst.IP(); ok {
		if p.d.o.DisableIPv6 && ip.Unmap().Is6() {
			return netip.AddrPort{}, ErrIPv6Disabled
		}
		return netip.AddrPortFrom(ip, dst.Port), nil
	}
	p.mu.Lock()
	ip, ok := p.names[dst.Host]
	p.mu.Unlock()
	if ok {
		return netip.AddrPortFrom(ip, dst.Port), nil
	}
	timeout := p.d.o.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	go func() {
		select {
		case <-p.closed:
			cancel()
		case <-ctx.Done():
		}
	}()
	ips, e := p.d.resolve(ctx, dst.Host)
	if e != nil {
		return netip.AddrPort{}, e
	}
	p.mu.Lock()
	p.candidates = append([]netip.Addr(nil), ips...)
	p.mu.Unlock()
	for _, ip := range ips {
		if ip.Is4() && p.v4 != nil || ip.Is6() && p.v6 != nil {
			if p.d.o.PacketControl != nil && !ip.IsLoopback() {
				if _, e := p.remoteSocket(ip.Is6()); e != nil {
					continue
				}
			}
			p.mu.Lock()
			if len(p.names) >= maxNames {
				clear(p.names)
			}
			p.names[dst.Host] = ip
			p.mu.Unlock()
			return netip.AddrPortFrom(ip, dst.Port), nil
		}
	}
	return netip.AddrPort{}, errNoAddress
}

func (p *packetConn) WriteTo(b []byte, dst outbound.Addr) (int, error) {
	select {
	case <-p.closed:
		return 0, net.ErrClosed
	default:
	}
	if len(b) > maxDatagram {
		return 0, errors.New("direct: datagram too large")
	}
	t, e := p.target(dst)
	if e != nil {
		return 0, e
	}
	if p.guard != nil && p.guard(t.Addr()) {
		return 0, ErrBlocked
	}
	s := p.v4
	if t.Addr().Is6() {
		s = p.v6
	}
	if p.d.o.PacketControl != nil && !t.Addr().IsLoopback() {
		s, e = p.remoteSocket(t.Addr().Is6())
		if e != nil {
			if p.d.o.PacketFailure != nil && !errors.Is(e, net.ErrClosed) && e.Error() != "physical family unavailable" && e.Error() != "no controlled physical interface for address family" && e.Error() != "ipv6_disabled" {
				p.d.o.PacketFailure()
			}
			return 0, e
		}
	}
	if s == nil {
		return 0, errNoAddress
	}
	p.mu.Lock()
	if _, ok := p.sent[t]; !ok {
		if len(p.order) >= maxSent {
			delete(p.sent, p.order[0])
			p.order = p.order[1:]
		}
		p.sent[t] = struct{}{}
		p.order = append(p.order, t)
	}
	p.mu.Unlock()
	n, err := s.WriteToUDPAddrPort(b, t)
	if err == nil && p.observe != nil {
		p.mu.Lock()
		ips := append([]netip.Addr(nil), p.candidates...)
		p.mu.Unlock()
		p.observe(ips, t.Addr())
	}
	return n, err
}

func (p *packetConn) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		close(p.closed)
		if p.remote4 != nil {
			p.remote4.Close()
			if p.d.o.PacketRelease != nil {
				p.d.o.PacketRelease(p.remote4)
			}
		}
		if p.remote6 != nil {
			p.remote6.Close()
			if p.d.o.PacketRelease != nil {
				p.d.o.PacketRelease(p.remote6)
			}
		}
		p.mu.Unlock()
		if p.v4 != nil {
			p.v4.Close()
		}
		if p.v6 != nil {
			p.v6.Close()
		}
	})
	p.wg.Wait()
	for {
		select {
		case g := <-p.in:
			p.mu.Lock()
			p.queuedBytes -= len(g.b)
			p.mu.Unlock()
		default:
			return nil
		}
	}
}

func (p *packetConn) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.rdeadline = t
	if p.rchanged != nil {
		close(p.rchanged)
		p.rchanged = nil
	}
	p.mu.Unlock()
	return nil
}

func (p *packetConn) SetWriteDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.wdeadline = t
	for _, s := range []*net.UDPConn{p.v4, p.v6, p.remote4, p.remote6} {
		if s != nil {
			if e := s.SetWriteDeadline(t); e != nil {
				return e
			}
		}
	}
	return nil
}

func (p *packetConn) remoteSocket(ipv6 bool) (*net.UDPConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.closed:
		return nil, net.ErrClosed
	default:
	}
	slot, network, bind := &p.remote4, "udp4", p.d.o.BindIPv4
	if ipv6 {
		slot, network, bind = &p.remote6, "udp6", p.d.o.BindIPv6
	}
	if *slot != nil {
		return *slot, nil
	}
	if source := p.d.o.PacketSource; source != nil {
		selected, err := source(network, bind)
		if err != nil {
			return nil, err
		}
		bind = selected
	}
	if !bind.IsValid() {
		if ipv6 {
			bind = netip.IPv6Unspecified()
		} else {
			bind = netip.IPv4Unspecified()
		}
	}
	c, e := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(bind, 0)))
	if e != nil {
		return nil, e
	}
	if e = p.d.o.PacketControl(network, c); e != nil {
		c.Close()
		return nil, e
	}
	_ = c.SetWriteDeadline(p.wdeadline)
	*slot = c
	p.wg.Add(1)
	go p.reader(c)
	return c, nil
}

// LocalEndpoints is exact socket metadata, NOT an Internet-observed NAT port.
func (p *packetConn) LocalEndpoints() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var a []string
	for _, c := range []*net.UDPConn{p.remote4, p.remote6} {
		if c != nil {
			a = append(a, c.LocalAddr().String())
		}
	}
	if len(a) == 0 {
		for _, c := range []*net.UDPConn{p.v4, p.v6} {
			if c != nil {
				a = append(a, c.LocalAddr().String())
			}
		}
	}
	return a
}
