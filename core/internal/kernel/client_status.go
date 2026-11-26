package kernel

import (
	"github.com/shui1iao/Kat/internal/stats"
	"net"
	"net/netip"
	"sort"
	"strings"
)

type domainStat struct {
	direct stats.Counter
	proxy  stats.Counter
}

type DomainTrafficView struct {
	Name       string `json:"name"`
	Up         uint64 `json:"up"`
	Down       uint64 `json:"down"`
	DirectUp   uint64 `json:"direct_up"`
	DirectDown uint64 `json:"direct_down"`
	ProxyUp    uint64 `json:"proxy_up"`
	ProxyDown  uint64 `json:"proxy_down"`
}

const maxTrackedDomains = 4096

func normalizeDomainKey(raw string) string {
	h := strings.TrimSpace(raw)
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	if h == "" || h == "localhost" || h == "dns" || h == "-" {
		return ""
	}
	if ip, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
			return ""
		}
		return ip.String()
	}
	return h
}

func (f *flow) domainKey() string {
	if f == nil {
		return ""
	}
	f.mu.Lock()
	h := f.details.DestHost
	if h == "" {
		h = f.host
	}
	if h == "" {
		h = f.target
	}
	f.mu.Unlock()
	return normalizeDomainKey(h)
}

func (f *flow) domainMeter(isDirect bool) *stats.Counter {
	if f == nil || f.s == nil || f.s.core == nil {
		return nil
	}
	h := f.domainKey()
	if h == "" {
		return nil
	}
	k := f.s.core
	v, ok := k.domainStats.Load(h)
	if !ok {
		if k.domainCount.Load() >= maxTrackedDomains {
			return nil
		}
		actual, loaded := k.domainStats.LoadOrStore(h, &domainStat{})
		if !loaded {
			k.domainCount.Add(1)
		}
		v = actual
	}
	ds := v.(*domainStat)
	if isDirect {
		return &ds.direct
	}
	return &ds.proxy
}

// TrafficTotals reads the same process-wide atomic cumulative counters used by
// StatsView, without building provider, rule or group snapshots.
func (s *Server) TrafficTotals() (up, down uint64) {
	t := s.core.reg.Total.Load()
	return t.Up, t.Down
}

// TrafficBreakdown returns cumulative total and direct traffic counters.
func (s *Server) TrafficBreakdown() (up, down, directUp, directDown uint64) {
	t := s.core.reg.Total.Load()
	var d stats.Traffic
	if dc := s.core.reg.Outbound("direct"); dc != nil {
		d = dc.Load()
	}
	return t.Up, t.Down, d.Up, d.Down
}

// DomainTraffic returns cumulative per-domain traffic counters for the running core.
func (s *Server) DomainTraffic() []DomainTrafficView {
	out := []DomainTrafficView{}
	s.core.domainStats.Range(func(key, value any) bool {
		name, _ := key.(string)
		ds, _ := value.(*domainStat)
		if name == "" || ds == nil {
			return true
		}
		d := ds.direct.Load()
		p := ds.proxy.Load()
		up := d.Up + p.Up
		down := d.Down + p.Down
		if up == 0 && down == 0 {
			return true
		}
		out = append(out, DomainTrafficView{
			Name:       name,
			Up:         up,
			Down:       down,
			DirectUp:   d.Up,
			DirectDown: d.Down,
			ProxyUp:    p.Up,
			ProxyDown:  p.Down,
		})
		return true
	})
	sort.Slice(out, func(i, j int) bool {
		iSum := out[i].Up + out[i].Down
		jSum := out[j].Up + out[j].Down
		if iSum != jSum {
			return iSum > jSum
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// MemoryStats summarizes runtime routing-index and kernel cache counts for
// numeric diagnostics (never contains paths, domains, or secrets).
type MemoryStats struct {
	RouteMmapSets   uint64
	RouteHeapSets   uint64
	LiveGenerations uint64
	RelayPoolBytes  uint64
	DNSHostEntries  uint64
	TrackedHosts    uint64
}

// MemoryStats returns live numeric counts for the current generation and core.
func (s *Server) MemoryStats() MemoryStats {
	var ms MemoryStats
	if s == nil {
		return ms
	}
	if cur := s.current(); cur != nil {
		if cur.rt != nil && cur.rt.engine != nil {
			rs := cur.rt.engine.MemoryStats()
			ms.RouteMmapSets = rs.MmapSets
			ms.RouteHeapSets = rs.HeapSets
		}
		if cur.pool != nil {
			ms.RelayPoolBytes = cur.pool.bytes()
		}
	}
	if s.core != nil {
		if g := s.core.liveGens.Load(); g > 0 {
			ms.LiveGenerations = uint64(g)
		}
		ms.DNSHostEntries = s.core.dnsHosts.count()
		if n := s.core.domainCount.Load(); n > 0 {
			ms.TrackedHosts = uint64(n)
		}
	}
	return ms
}

// GenerationID reads the current generation at this call, including when s is
// an older Server handle. It does not cache a generation across status requests.
func (s *Server) GenerationID() uint64 {
	if g := s.core.gen.Load(); g != nil {
		return g.id
	}
	return 0
}
