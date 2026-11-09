package kernel

import (
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"time"
)

// tunDNSQuery uses the real gateway unchanged. Only client payload is metered;
// retries, cache work and TCP length prefixes are not business/direct traffic.
func (s *Server) tunDNSQuery(ctx context.Context, f *flow, target Address, p []byte, tcp bool, output func([]byte) error) error {
	f.udpUp(nil, len(p))
	tunDNSMeta(f, target)
	var query dnsmessage.Parser
	if _, err := query.Start(p); err == nil {
		if q, err := query.Question(); err == nil {
			f.mu.Lock()
			f.details.DNSQueryType = uint16(q.Type)
			f.mu.Unlock()
		}
	}
	qctx, cancel := context.WithTimeout(ctx, s.cfg.Limits.DialTimeout.value())
	reply, e := s.answerDNS(qctx, p, tcp)
	cancel()
	if e != nil {
		f.udpDNS(target, "dns_query_failed", e)
		s.counters.Dropped.Add(1)
		return e
	}
	var parser dnsmessage.Parser
	h, e := parser.Start(reply)
	if e == nil {
		code := uint16(h.RCode)
		f.mu.Lock()
		f.details.DNSRCode = &code
		f.mu.Unlock()
	}
	var outcomeErr error
	if e != nil || !h.Response || (h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError) {
		outcomeErr = errors.New("DNS upstream returned a failure response")
		f.udpDNS(target, "dns_query_failed", errors.New("DNS upstream returned a failure response"))
	}
	if e = output(reply); e != nil {
		f.udpDNS(target, "dns_response_failed", e)
		s.counters.Dropped.Add(1)
		return e
	}
	f.udpDown(nil, len(reply))
	if outcomeErr == nil {
		f.emitConnection(target.String(), "dns", []string{"dns"}, "ok", "")
	}
	return outcomeErr
}
func tunDNSMeta(f *flow, target Address) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.target = target.String()
	f.ruleKey = "dns"
	f.chain = []string{"dns"}
	f.mu.Unlock()
}

// TCP owns transport framing only. Each query owns its own real record and
// payload meter; an empty transport does not manufacture an empty "ok" flow.
func (s *Server) tunDNSTCP(ctx context.Context, c net.Conn, target Address) error {
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	for {
		_ = c.SetReadDeadline(time.Now().Add(s.cfg.Limits.UDPIdle.value()))
		var size [2]byte
		n, e := io.ReadFull(c, size[:])
		if e != nil && n == 0 && (errors.Is(e, io.EOF) || ctx.Err() != nil || timeoutError(e)) {
			return e
		}
		f, fctx := s.newFlow(ctx, "tcp", Address{})
		tunDNSMeta(f, target)
		if e != nil {
			f.udpDNS(target, "dns_query_failed", e)
			f.end("dns_query_failed")
			return e
		}
		p := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		n, e = io.ReadFull(c, p)
		if e != nil {
			f.udpUp(nil, n)
			f.udpDNS(target, "dns_query_failed", e)
			f.end("dns_query_failed")
			return e
		}
		var writeErr error
		e = s.tunDNSQuery(fctx, f, target, p, true, func(reply []byte) error {
			_ = c.SetWriteDeadline(time.Now().Add(s.cfg.Limits.DialTimeout.value()))
			wire := binary.BigEndian.AppendUint16(nil, uint16(len(reply)))
			wire = append(wire, reply...)
			writeErr = writeAll(c, wire)
			return writeErr
		})
		if e != nil {
			f.end("dns_query_failed")
			if writeErr != nil || f.down.Load() == 0 {
				return e
			}
			continue
		}
		f.end("ok")
	}
}
