package kernel

import (
	"context"
	"github.com/shui1iao/Kat/internal/outbound"
	oa "github.com/shui1iao/Kat/internal/outbound/anytls"
	osk "github.com/shui1iao/Kat/internal/outbound/socks5"
	oss "github.com/shui1iao/Kat/internal/outbound/ss"
	"sync/atomic"
	"time"
)

type runtimeDiagBucket struct {
	keyHash    atomic.Uint64
	nextNano   atomic.Int64
	suppressed atomic.Uint64
}

func hashStageCategory(stage, category string) uint64 {
	// FNV-1a 64-bit over (stage, ':', category) with zero heap allocations.
	const offset64 = 14695981039346656037
	const prime64 = 1099511628211
	h := uint64(offset64)
	for i := 0; i < len(stage); i++ {
		h ^= uint64(stage[i])
		h *= prime64
	}
	h ^= uint64(':')
	h *= prime64
	for i := 0; i < len(category); i++ {
		h ^= uint64(category[i])
		h *= prime64
	}
	if h == 0 {
		h = 1
	}
	return h
}

func (s *Server) allowRuntimeFailure(stage, category string, nowNano int64) (bool, uint64) {
	if s.core == nil {
		return true, 0
	}
	h := hashStageCategory(stage, category)
	b := &s.core.runtimeDiagGate[h&63]
	if b.keyHash.Load() == h {
		old := b.nextNano.Load()
		if nowNano < old || !b.nextNano.CompareAndSwap(old, nowNano+int64(10*time.Second)) {
			b.suppressed.Add(1)
			return false, 0
		}
		return true, b.suppressed.Swap(0)
	}
	b.keyHash.Store(h)
	b.nextNano.Store(nowNano + int64(10*time.Second))
	return true, b.suppressed.Swap(0)
}

func (s *Server) runtimeDiagnostic(ctx context.Context, d outbound.Diagnostic) {
	s.runtimeDiagnosticWithSuppressed(ctx, d, 0)
}

func (s *Server) runtimeDiagnosticWithSuppressed(ctx context.Context, d outbound.Diagnostic, suppressed uint64) {
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
	}(), Event: "runtime.observation", Diagnostic: &d, Suppressed: suppressed})
}
func (s *Server) diagnosticContext(ctx context.Context) context.Context {
	return outbound.WithDiagnostic(ctx, func(d outbound.Diagnostic) { s.runtimeDiagnostic(ctx, d) })
}
func (s *Server) runtimeFailure(ctx context.Context, stage, protocol string, e error, start time.Time) {
	if e == nil || s.cfg.clientLog == nil {
		return
	}
	category, native := outbound.Category(e)
	if c := oss.SafeFailure(e); c != "" {
		category, protocol = c, "shadowsocks"
	} else if c := oa.SafeFailure(e); c != "" {
		category, protocol = c, "anytls"
	} else if c := osk.SafeFailure(e); c != "" {
		category, protocol = c, "socks5"
	}
	now := time.Now()
	allowed, suppressed := s.allowRuntimeFailure(stage, category, now.UnixNano())
	if !allowed {
		return
	}
	if !diagnosticValidFast(stage, category, protocol) {
		return
	}
	s.runtimeDiagnosticWithSuppressed(ctx, outbound.Diagnostic{Stage: stage, Category: category, Protocol: protocol, Native: native, ElapsedMS: outbound.Known(uint64(now.Sub(start).Milliseconds()))}, suppressed)
}

func diagnosticValidFast(stage, category, protocol string) bool {
	return (outbound.Diagnostic{Stage: stage, Category: category, Protocol: protocol}).Valid()
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
