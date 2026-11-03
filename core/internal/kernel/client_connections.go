package kernel

import (
	"context"
	"golang.org/x/net/publicsuffix"
	"time"
)

// ConnectionEvent is a private, memory-only client hook. It is deliberately
// separate from ClientLogEvent: logs.get keeps its existing privacy boundary.
type ConnectionEvent struct {
	FlowDetails
	Start      time.Time  `json:"start"`
	End        *time.Time `json:"end,omitempty"`
	Up         uint64     `json:"up"`
	Down       uint64     `json:"down"`
	DurationMS int64      `json:"duration_ms"`
	Ended      bool       `json:"ended,omitempty"`
	Time       time.Time  `json:"time"`
	Network    string     `json:"network"`
	Source     string     `json:"source"`
	Target     string     `json:"target"`
	Host       string     `json:"host,omitempty"`
	Rule       string     `json:"rule"`
	Chain      []string   `json:"chain"`
	Outcome    string     `json:"outcome"`
	Code       string     `json:"code,omitempty"`
}

func (c *Config) SetConnectionSink(sink func(ConnectionEvent)) { c.clientConnections = sink }

type ClosedConn struct {
	ConnInfo
	End time.Time `json:"end"`
}

func (f *flow) info(now time.Time) ConnInfo {
	f.mu.Lock()
	details := f.details
	// PSL eTLD+1, never a hand-maintained suffix list in the UI.
	details.DomainSuffix, _ = publicsuffix.EffectiveTLDPlusOne(details.DestHost)
	details.DestIPs = append([]string(nil), details.DestIPs...)
	ci := ConnInfo{FlowDetails: details, ID: f.id, Network: f.network, Inbound: f.inKey, Source: truncateSource(f.src), Target: f.target, Host: f.host, Rule: f.ruleKey, Chain: append([]string{}, f.chain...), Start: f.start, DurationMS: now.Sub(f.start).Milliseconds()}
	f.mu.Unlock()
	ci.Up, ci.Down = f.up.Load(), f.down.Load()
	if f.diagnostic != nil {
		f.diagnostic.set(ci)
	}
	return ci
}

// TotalConnections counts logical proxied flows (TCP and UDP), not inbound
// transport sockets (Accepted also includes SOCKS handshakes and multiplexers).
func (s *Server) TotalConnections() uint64 { return s.flowID.Load() }
func (s *Server) ClientConnections(limit int) ([]ConnInfo, []ClosedConn) {
	active := s.connections()
	s.flowMu.Lock()
	defer s.flowMu.Unlock()
	closed := make([]ClosedConn, 0, min(limit, s.closedSize))
	for i := 0; i < min(limit, s.closedSize); i++ {
		v := s.closed[(s.closedNext-1-i+len(s.closed))%len(s.closed)]
		v.DestIPs = append([]string(nil), v.DestIPs...)
		v.Chain = append([]string{}, v.Chain...)
		closed = append(closed, v)
	}
	return active, closed
}
func (f *flow) emitConnection(target, rule string, chain []string, outcome, code string) {
	if f == nil || f.s.connectionSink == nil {
		return
	}
	f.mu.Lock()
	host, source := f.host, truncateSource(f.src)
	f.eventRecorded = true
	f.lastOutcome, f.lastCode = outcome, code
	f.mu.Unlock()
	ci := f.info(time.Now())
	f.s.connectionSink(ConnectionEvent{FlowDetails: ci.FlowDetails, Start: ci.Start, Up: ci.Up, Down: ci.Down, DurationMS: ci.DurationMS, Time: time.Now(), Network: f.network, Source: source, Target: target, Host: host, Rule: rule, Chain: append([]string{}, chain...), Outcome: outcome, Code: code})
}
func (f *flow) connectionOutcome(err error) {
	if f == nil {
		return
	}
	f.setError(err)
	f.mu.Lock()
	if len(f.chain) > 0 && f.chain[len(f.chain)-1] != "direct" && f.details.DestHost != "" && f.details.DestIP == "" {
		f.details.RemoteDNS = true
	}
	f.mu.Unlock()
	ci := f.info(time.Now())
	outcome, code := "ok", ""
	if err != nil {
		code = dialResult(err)
		outcome = "error"
		if code == "rejected" || code == "blocked" {
			outcome = "rejected"
		}
	}
	f.emitConnection(ci.Target, ci.Rule, ci.Chain, outcome, code)
}
func (f *flow) sniffHost(ctx context.Context) {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.host = ""
	if sn := sniffOf(ctx); sn != nil {
		f.host = sn.host
		f.details.Sniffed = sn.host != ""
		if sn.host != "" {
			f.details.DestHost = sn.host
		}
	}
	f.mu.Unlock()
}

func (f *flow) udpFailure(target Address, rule int, chain []string, code string, errs ...error) {
	if len(errs) > 0 {
		f.setError(errs[0])
	}
	if f == nil {
		return
	}
	_, key := f.s.ruleCounter(rule)
	outcome := "error"
	if code == "blocked" || code == "rejected" {
		outcome = "rejected"
	}
	f.emitConnection(target.String(), key, chain, outcome, code)
}

// ClientCloseConnections cancels only the captured logical flows. The same
// cancellation path already owns TCP relay ends, UDP associations and TUN flows.
// Duplicate, ended and already requested ids never inflate the actual count.
func (s *Server) ClientCloseConnections(ids []uint64) int {
	s.flowMu.Lock()
	list := make([]*flow, 0, len(ids))
	for _, id := range ids {
		if f := s.flows[id]; f != nil && !f.ended.Load() && !f.killed.Swap(true) {
			list = append(list, f)
		}
	}
	s.flowMu.Unlock()
	for _, f := range list {
		f.cancel()
	}
	return len(list)
}

// Capture once before publishing a user selection; new connections created
// during/after commit are not accidentally closed. Matching includes nested
// strategy chains, not just their first group, and never closes other groups.
func (s *Server) ClientGroupConnectionIDs(groups []string) []uint64 {
	wanted := map[string]bool{}
	for _, g := range groups {
		wanted[g] = true
	}
	s.flowMu.Lock()
	defer s.flowMu.Unlock()
	ids := []uint64{}
	for id, f := range s.flows {
		f.mu.Lock()
		match := false
		for _, g := range f.chain {
			if wanted[g] {
				match = true
				break
			}
		}
		f.mu.Unlock()
		if match && !f.ended.Load() {
			ids = append(ids, id)
		}
	}
	return ids
}
