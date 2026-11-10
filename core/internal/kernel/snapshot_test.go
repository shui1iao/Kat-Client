package kernel

import (
	"github.com/shui1iao/Kat/internal/stats"
	"time"
)

type StatsView struct {
	Version     string         `json:"version"`
	UptimeMS    int64          `json:"uptime_ms"`
	Rate        RateView       `json:"rate"`
	Connections ConnCounts     `json:"connections"`
	Persist     PersistView    `json:"persist"`
	Details     bool           `json:"details_enabled"`
	Cumulative  stats.Snapshot `json:"cumulative"`
	Providers   []ProviderView `json:"providers,omitempty"`
	Reload      ReloadView     `json:"reload"`
}

// RateView is the recent throughput in bytes per second.
type RateView struct {
	Up       float64 `json:"up_bytes_per_sec"`
	Down     float64 `json:"down_bytes_per_sec"`
	WindowMS int64   `json:"window_ms"`
}

// ConnCounts are the current counts: proxied TCP connections, UDP
// associations and accepted inbound transport connections; Rejected counts
// inbound connections refused by the connection/handshake budgets since start.
type ConnCounts struct {
	TCP      int64 `json:"tcp"`
	UDP      int64 `json:"udp"`
	Accepted int64 `json:"accepted"`
	Rejected int64 `json:"rejected_since_start"`
}

// PersistView reports the persistence state.
type PersistView struct {
	File       string    `json:"file,omitempty"`
	Enabled    bool      `json:"enabled"`
	LastSave   time.Time `json:"last_save,omitzero"`
	SaveErrors int64     `json:"save_errors"`
}

func (s *Server) StatsView() StatsView { return s.core.statsView() }

func (s *core) statsView() StatsView {
	up, down, w := s.reg.Rate()
	path := s.persistedPath()
	v := StatsView{Version: Version, UptimeMS: time.Since(s.started).Milliseconds(), Rate: RateView{up, down, w.Milliseconds()},
		Connections: ConnCounts{TCP: s.tcpFlows.Load(), UDP: s.counters.UDP.Load(), Accepted: s.counters.Active.Load(), Rejected: s.counters.Rejected.Load()},
		Persist:     PersistView{File: path, Enabled: path != "", SaveErrors: s.saveErrors.Load()},
		Details:     s.detailsOn.Load(), Cumulative: s.reg.Snapshot(), Reload: s.reloadView(), Providers: s.providerViews()}
	if t := s.lastSave.Load(); t != 0 {
		v.Persist.LastSave = time.Unix(0, t)
	}
	return v
}
