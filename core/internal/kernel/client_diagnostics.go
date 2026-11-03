package kernel

import (
	"errors"
	"net/netip"
	"sync"
)

// ClientDiagnostic observes the precise local SOCKS connection, even when
// procattr correctly reports the core's own process as unknown. No IP/hostname
// heuristic can confuse concurrent app flows with a diagnostic.
type ClientDiagnostic struct {
	group string
	mu    sync.Mutex
	info  ConnInfo
}

func (d *ClientDiagnostic) set(ci ConnInfo) { d.mu.Lock(); defer d.mu.Unlock(); d.info = ci }
func (d *ClientDiagnostic) Snapshot() ConnInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	ci := d.info
	ci.Chain = append([]string{}, ci.Chain...)
	if d.group != "" {
		ci.Rule = "指定组 → " + d.group
	}
	return ci
}

// Caller must own the open source socket and unregister on close; the tuple is
// not supplied over IPC. Group overrides are only for Cloudflare exit trace.
func (s *Server) RegisterClientDiagnostic(source netip.AddrPort, group string) (*ClientDiagnostic, func(), error) {
	if !source.IsValid() || !source.Addr().IsLoopback() {
		return nil, nil, errors.New("diagnostic requires loopback")
	}
	if group != "" {
		g := s.current()
		found := false
		for _, v := range g.cfg.Groups {
			if v.Name == group {
				found = true
			}
		}
		if !found {
			return nil, nil, errors.New("unknown diagnostic group")
		}
	}
	d := &ClientDiagnostic{group: group}
	if _, loaded := s.clientDiagnostics.LoadOrStore(source, d); loaded {
		return nil, nil, errors.New("diagnostic tuple busy")
	}
	return d, func() { s.clientDiagnostics.CompareAndDelete(source, d) }, nil
}
