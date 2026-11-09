package clientegress

// One wire transport for system lookup/bootstrap and the TUN raw DNS gateway.
// It is not a DNS listener, a public fallback, or a general interface dial API.
import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const maxDNSWire = 65535

var oldPool4 = netip.MustParsePrefix("198.19.0.0/16")
var oldPool6 = netip.MustParsePrefix("fd4b:6174:6661::/112")
var tun4 = netip.MustParsePrefix("198.18.0.0/30")
var tun6 = netip.MustParsePrefix("fd4b:6174::/126")

func dnsAddressAllowed(ip netip.Addr) bool {
	return ip.IsValid() && !ip.Is4In6() && !ip.IsLoopback() && !ip.IsUnspecified() && !ip.IsMulticast() && !oldPool4.Contains(ip) && !oldPool6.Contains(ip) && !tun4.Contains(ip) && !tun6.Contains(ip)
}
func (d DNSEndpoint) socket() string {
	ip, _ := netip.ParseAddr(d.Address)
	if d.Scope != 0 {
		ip = ip.WithZone(strconv.FormatUint(uint64(d.Scope), 10))
	}
	return net.JoinHostPort(ip.String(), "53")
}

// Only a registered endpoint can obtain the narrow IPv6 DNS exception. Ordinary
// Policy.Control still rejects all non-loopback IPv6 when business IPv6 is off.
func (p *Policy) dnsDial(ctx context.Context, network string, d DNSEndpoint, state *dnsRevision) (net.Conn, error) {
	if state.life.Err() != nil {
		return nil, context.Canceled
	}
	if !p.Ready() {
		return nil, errors.New("physical lease unavailable")
	}
	registered := false
	for _, ep := range state.options.DNS {
		if ep == d {
			registered = true
			break
		}
	}
	if !registered || network != "udp" && network != "tcp" {
		p.Fail()
		return nil, errors.New("unregistered DNS dial refused")
	}
	ip, _ := netip.ParseAddr(d.Address)
	o := Options{}
	family := network + "4"
	index := d.IfIndex
	if ip.Is6() {
		o.IPv6 = &index
		family = network + "6"
	} else {
		o.IPv4 = &index
	}
	bind := platformBind(o)
	control := func(ctx context.Context, n, address string, raw syscall.RawConn) error {
		if !p.Ready() {
			return errors.New("physical lease unavailable")
		}
		if address != d.socket() || n != family {
			p.Fail()
			return errors.New("DNS endpoint identity mismatch")
		}
		if e := p.owner(d); e != nil {
			p.Fail()
			return errors.New("system DNS owner changed")
		}
		if e := bind(n, raw); e != nil {
			p.Fail()
			return errors.New("system DNS socket binding failed")
		}
		return nil
	}
	return p.dnsConnect(ctx, family, d.socket(), control)
}
func systemQuestion(w []byte) (dnsmessage.Message, error) {
	var m dnsmessage.Message
	if len(w) < 12 || len(w) > maxDNSWire || m.Unpack(w) != nil || m.Response || m.OpCode != 0 || len(m.Questions) != 1 || m.Questions[0].Class != dnsmessage.ClassINET || len(m.Answers) != 0 || len(m.Authorities) != 0 {
		return m, errors.New("invalid DNS request")
	}
	return m, nil
}
func systemReply(w []byte, q dnsmessage.Message) (bool, error) {
	var parser dnsmessage.Parser
	h, e := parser.Start(w)
	if e != nil || len(w) > maxDNSWire || !h.Response || h.ID != q.ID || h.OpCode != 0 {
		return false, errors.New("invalid DNS reply")
	}
	qs, e := parser.AllQuestions()
	if e != nil || len(qs) != 1 {
		return false, errors.New("invalid DNS question")
	}
	a, b := qs[0], q.Questions[0]
	if !strings.EqualFold(a.Name.String(), b.Name.String()) || a.Type != b.Type || a.Class != b.Class {
		return false, errors.New("DNS reply question mismatch")
	}
	if h.Truncated {
		return true, nil
	}
	var m dnsmessage.Message
	if m.Unpack(w) != nil {
		return false, errors.New("invalid DNS reply body")
	}
	if m.RCode != dnsmessage.RCodeSuccess && m.RCode != dnsmessage.RCodeNameError {
		return false, errors.New("transient DNS reply")
	}
	for _, sec := range [][]dnsmessage.Resource{m.Answers, m.Additionals} {
		for _, rr := range sec {
			var ip netip.Addr
			switch v := rr.Body.(type) {
			case *dnsmessage.AResource:
				ip = netip.AddrFrom4(v.A)
			case *dnsmessage.AAAAResource:
				ip = netip.AddrFrom16(v.AAAA)
			}
			if ip.IsValid() && (oldPool4.Contains(ip.Unmap()) || oldPool6.Contains(ip.Unmap())) {
				return false, errors.New("legacy synthetic DNS answer refused")
			}
		}
	}
	return false, nil
}
func writeDNS(c net.Conn, b []byte) error {
	for len(b) > 0 {
		n, e := c.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func (p *Policy) endpointQuery(ctx context.Context, d DNSEndpoint, wire []byte, q dnsmessage.Message, state *dnsRevision) ([]byte, error) {
	exchange := func(network string) ([]byte, error) {
		c, e := p.dnsDial(ctx, network, d, state)
		if e != nil {
			return nil, e
		}
		defer c.Close()
		if end, ok := ctx.Deadline(); ok {
			_ = c.SetDeadline(end)
		}
		stop := context.AfterFunc(ctx, func() { c.Close() })
		defer stop()
		if network == "tcp" {
			frame := binary.BigEndian.AppendUint16(nil, uint16(len(wire)))
			frame = append(frame, wire...)
			if e = writeDNS(c, frame); e != nil {
				return nil, e
			}
			var size [2]byte
			if _, e = io.ReadFull(c, size[:]); e != nil {
				return nil, e
			}
			n := int(binary.BigEndian.Uint16(size[:]))
			if n < 12 {
				return nil, errors.New("short DNS reply")
			}
			b := make([]byte, n)
			_, e = io.ReadFull(c, b)
			return b, e
		}
		if _, e = c.Write(wire); e != nil {
			return nil, e
		}
		// Connected UDP accepts replies from this endpoint only. ID/question are
		// checked below; never switch to an unbound socket on errors.
		b := make([]byte, maxDNSWire+1)
		n, e := c.Read(b)
		if e != nil || n > maxDNSWire {
			return nil, errors.New("invalid DNS datagram")
		}
		return b[:n], nil
	}
	b, e := exchange("udp")
	if e != nil {
		return nil, e
	}
	tc, e := systemReply(b, q)
	if e != nil {
		return nil, e
	}
	if tc {
		b, e = exchange("tcp")
		if e != nil {
			return nil, e
		}
		tc, e = systemReply(b, q)
		if e != nil {
			return nil, e
		}
		if tc {
			return nil, errors.New("truncated DNS TCP reply")
		}
	}
	return b, nil
}
func (p *Policy) SystemQuery(ctx context.Context, wire []byte) ([]byte, error) {
	if !p.Ready() {
		return nil, errors.New("physical lease unavailable")
	}
	state := p.dns.Load()
	ctx, cancelRevision := context.WithCancel(ctx)
	stopRevision := context.AfterFunc(state.life, cancelRevision)
	defer func() { stopRevision(); cancelRevision() }()
	if state.life.Err() != nil {
		return nil, context.Canceled
	}
	q, e := systemQuestion(wire)
	if e != nil {
		return nil, e
	}
	if _, ok := ctx.Deadline(); !ok {
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, 5*time.Second)
		defer stop()
	}
	select {
	case p.dnsSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-p.dnsSlots }()
	var groups [][]DNSEndpoint
	// Same authorized adapter only: at most four concurrent requests. Different
	// owners are tried sequentially in default IPv4 -> IPv6 egress priority.
	seen := map[uint64]bool{}
	for _, owner := range []*uint64{state.options.LUID4, state.options.LUID6} {
		if owner == nil || seen[*owner] {
			continue
		}
		seen[*owner] = true
		var g []DNSEndpoint
		for _, d := range state.options.DNS {
			if d.Owner == *owner {
				g = append(g, d)
			}
		}
		if len(g) > 0 {
			groups = append(groups, g)
		}
	}
	for i, g := range groups {
		if !p.Ready() {
			return nil, errors.New("physical lease unavailable")
		}
		end, _ := ctx.Deadline()
		budget := time.Until(end) / time.Duration(len(groups)-i)
		if budget <= 0 {
			break
		}
		attempt, cancel := context.WithTimeout(ctx, budget)
		jobs := make(chan DNSEndpoint, len(g))
		for _, d := range g {
			jobs <- d
		}
		close(jobs)
		results := make(chan []byte, len(g))
		var wg sync.WaitGroup
		for j := 0; j < len(g) && j < 4; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for d := range jobs {
					if attempt.Err() != nil {
						return
					}
					b, e := p.endpointQuery(attempt, d, wire, q, state)
					if e == nil {
						results <- b
					}
				}
			}()
		}
		done := make(chan struct{})
		go func() { wg.Wait(); close(results); close(done) }()
		var answer []byte
		for b := range results {
			if answer == nil {
				answer = b
				cancel()
			}
		}
		<-done
		cancel()
		// A binding/lease failure is terminal, even if a concurrent candidate replied.
		if !p.Ready() {
			return nil, errors.New("system DNS control failed")
		}
		if answer != nil {
			if state.life.Err() != nil {
				return nil, context.Canceled
			}
			return answer, nil
		}
	}
	return nil, &net.DNSError{Err: "controlled system DNS unavailable", Name: q.Questions[0].Name.String(), IsTimeout: errors.Is(ctx.Err(), context.DeadlineExceeded), IsTemporary: true}
}

// A private in-memory stream adapter lets Go retain its established resolver
// semantics without dialing OS-selected DNS sockets. It has no listener/port.
// Go resolver's non-PacketConn path uses the two-byte DNS stream framing.
type resolverStream struct {
	net.Conn
	result <-chan error
}

func (c resolverStream) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if e != nil {
		if err := <-c.result; err != nil {
			return n, err
		}
	}
	return n, e
}
func (p *Policy) resolverConn(ctx context.Context, _, _ string) (net.Conn, error) {
	if !p.Ready() {
		return nil, errors.New("physical lease unavailable")
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		client, err := p.resolverConn(ctx, "", "")
		if err != nil {
			cancel()
			return nil, err
		}
		return resolverCancel{client, cancel}, nil
	}
	client, server := net.Pipe()
	result := make(chan error, 1)
	go func() {
		var err error
		defer func() { result <- err; close(result); server.Close() }()
		if end, ok := ctx.Deadline(); ok {
			_ = server.SetDeadline(end)
		}
		stop := context.AfterFunc(ctx, func() { server.Close() })
		defer stop()
		var size [2]byte
		if _, err = io.ReadFull(server, size[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(size[:]))
		if n < 12 {
			err = errors.New("short resolver question")
			return
		}
		wire := make([]byte, n)
		if _, err = io.ReadFull(server, wire); err != nil {
			return
		}
		var reply []byte
		reply, err = p.SystemQuery(ctx, wire)
		if err != nil {
			return
		}
		out := binary.BigEndian.AppendUint16(nil, uint16(len(reply)))
		out = append(out, reply...)
		err = writeDNS(server, out)
	}()
	return resolverStream{client, result}, nil
}

type resolverCancel struct {
	net.Conn
	cancel context.CancelFunc
}

func (c resolverCancel) Close() error { c.cancel(); return c.Conn.Close() }

func connectDNS(ctx context.Context, network, address string, control func(context.Context, string, string, syscall.RawConn) error) (net.Conn, error) {
	d := net.Dialer{ControlContext: control}
	return d.DialContext(ctx, network, address)
}
