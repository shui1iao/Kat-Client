package kernel

import (
	"context"
	"github.com/shui1iao/Kat/internal/outbound"
	oa "github.com/shui1iao/Kat/internal/outbound/anytls"
	osk "github.com/shui1iao/Kat/internal/outbound/socks5"
	oss "github.com/shui1iao/Kat/internal/outbound/ss"
	"time"
)

func (s *Server) runtimeDiagnostic(ctx context.Context, d outbound.Diagnostic) {
	if s.cfg.clientLog == nil || !d.Valid() {
		return
	}
	if f := flowOf(ctx); f != nil {
		d.FlowID = outbound.Known(f.id)
		if f.httpObservation != nil && f.httpObservation.Decorate != nil {
			f.httpObservation.Decorate(&d)
		}
	}
	s.cfg.clientLog(ClientLogEvent{Time: time.Now(), Level: func() string {
		if d.Category == "ok" || d.Category == "nodata" || d.Category == "nxdomain" || d.Category == "canceled" || d.Category == "closed" || d.Stage == "relay" {
			return "debug"
		}
		return "warn"
	}(), Event: "runtime.observation", Diagnostic: &d})
}
func (s *Server) diagnosticContext(ctx context.Context) context.Context {
	return outbound.WithDiagnostic(ctx, func(d outbound.Diagnostic) { s.runtimeDiagnostic(ctx, d) })
}
func (s *Server) runtimeFailure(ctx context.Context, stage, protocol string, e error, start time.Time) {
	if e == nil {
		return
	}
	category, native := outbound.Category(e)
	if c := oss.SafeFailure(e); c != "" {
		category, protocol = c, "shadowsocks"
	}
	if c := oa.SafeFailure(e); c != "" {
		category, protocol = c, "anytls"
	}
	if c := osk.SafeFailure(e); c != "" {
		category, protocol = c, "socks5"
	}
	s.runtimeDiagnostic(ctx, outbound.Diagnostic{Stage: stage, Category: category, Protocol: protocol, Native: native, ElapsedMS: outbound.Known(uint64(time.Since(start).Milliseconds()))})
}
func (r *internalDNS) observe(ctx context.Context, d outbound.Diagnostic) {
	d.Revision = outbound.Known(r.dnsEpoch())
	if r.diagnostic != nil {
		r.diagnostic(ctx, d)
	}
}
func (r *internalDNS) observeError(ctx context.Context, stage, protocol string, e error, start time.Time) {
	if e == nil {
		return
	}
	c, n := outbound.Category(e)
	r.observe(ctx, outbound.Diagnostic{Stage: stage, Category: c, Protocol: protocol, Native: n, ElapsedMS: func() *uint64 {
		if start.IsZero() {
			return nil
		}
		return outbound.Known(uint64(time.Since(start).Milliseconds()))
	}()})
}
func (r *internalDNS) setDiagnostic(fn func(context.Context, outbound.Diagnostic)) {
	r.diagnostic = fn
	for _, p := range r.rules {
		p.resolver.setDiagnostic(fn)
	}
	if r.local != nil {
		r.local.setDiagnostic(fn)
	}
}
