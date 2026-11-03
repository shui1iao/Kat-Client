package clientcore

import (
	"bufio"
	"github.com/shui1iao/Kat/internal/kernel"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

// Protocol-level loopback checks, never a bare connect or a remote test.
func (h *Host) checkLocal() bool {
	c, e := net.DialTimeout("tcp", portAddress(h.doc.client.SOCKSPort), time.Second)
	if e != nil {
		return false
	}
	c.SetDeadline(time.Now().Add(time.Second))
	_, e = c.Write([]byte{5, 1, 0})
	var b [2]byte
	if e == nil {
		_, e = io.ReadFull(c, b[:])
	}
	c.Close()
	if e != nil || b != [2]byte{5, 0} {
		return false
	}
	c, e = net.DialTimeout("tcp", portAddress(h.doc.client.HTTPPort), time.Second)
	if e != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	_, e = io.WriteString(c, "OPTIONS * HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	if e != nil {
		return false
	}
	r, e := http.ReadResponse(bufio.NewReader(c), nil)
	if e != nil {
		return false
	}
	r.Body.Close()
	return r.StatusCode == 204 && r.Header.Get("Kat-Client-Proxy") == "1"
}
func (h *Host) Status() any { h.mu.Lock(); defer h.mu.Unlock(); return h.statusLocked() }
func (h *Host) statusLocked() any {
	h.sampleLocked(time.Now())
	currentRound := h.allRound
	if currentRound != nil && (currentRound.server != h.server || currentRound.epoch != h.manualCtx || currentRound.epoch.Err() != nil || h.server.GenerationID() != currentRound.generation) {
		currentRound = nil
	}
	progress, liveProbes := currentRound.projection()
	if liveProbes == nil {
		liveProbes = map[string]kernel.ProbeResult{}
	}
	groupProgress := map[string]any{}
	for name, round := range h.groupRounds {
		if round.server != h.server || round.epoch != h.manualCtx || round.epoch.Err() != nil || h.server.GenerationID() != round.generation {
			continue
		}
		p, probes := round.projection()
		groupProgress[name] = p
		for n, r := range probes {
			if !r.At.Before(liveProbes[n].At) {
				liveProbes[n] = r
			}
		}
	}
	groups := []any{}
	trafficGroups := []any{}
	trafficRules := any([]any{})
	policyHits := []map[string]any{}
	var rulesSince, total, tcp, udp any
	nodes := []any{}
	providers := []kernel.ProviderView{}
	items := any([]any{})
	active := int64(0)
	uptime := int64(0)
	var pid any
	var memory any
	upRate, downRate := float64(0), float64(0)
	if h.server != nil {
		v := h.server.StatsView()
		trafficRules = v.Cumulative.Rules
		byTarget := map[string]uint64{}
		order := []string{}
		targets := h.server.RuleTargets()
		for _, rr := range v.Cumulative.Rules {
			dest := targets[rr.Name]
			if dest == "" {
				continue
			}
			if _, ok := byTarget[dest]; !ok {
				order = append(order, dest)
			}
			byTarget[dest] += rr.Hits
		}
		for _, dest := range order {
			policyHits = append(policyHits, map[string]any{"name": dest, "hits": byTarget[dest]})
		}
		if !v.Cumulative.Since.IsZero() {
			rulesSince = v.Cumulative.Since
		}
		total = h.server.TotalConnections()
		for _, g := range v.Cumulative.Groups {
			trafficGroups = append(trafficGroups, map[string]any{"name": g.Name, "up": g.Up, "down": g.Down})
		}
		uptime = v.UptimeMS
		pid = os.Getpid()
		if mem, ok := processMemoryBytes(); ok {
			memory = mem
		}
		upRate, downRate = v.Rate.Up, v.Rate.Down
		active = v.Connections.TCP + v.Connections.UDP
		tcp, udp = v.Connections.TCP, v.Connections.UDP
		providers = v.Providers
		for i := range providers {
			if providers[i].LastErr != "" {
				providers[i].LastErr = "Provider update failed; previous nodes retained"
			}
		}
		items = h.server.ConnectionDetails()
		cfg := h.server.CurrentConfig()
		types := map[string]string{"direct": "direct", "reject": "reject"}
		// Preserve real automatic failures (not merely available=false), and
		// never let an older manual record overwrite newer health evidence.
		latest := map[string]kernel.ProbeResult{}
		for name, p := range h.probes {
			latest[name] = p
		}
		for name, p := range liveProbes {
			if p.At.After(latest[name].At) {
				latest[name] = p
			}
		}
		groupSnapshots := h.server.GroupSnapshots()
		for _, snap := range groupSnapshots {
			for _, m := range snap.Members {
				if !m.Probed || m.ProbeAt.IsZero() || !m.ProbeAt.After(latest[m.Name].At) {
					continue
				}
				p := kernel.ProbeResult{Name: m.Name, At: m.ProbeAt}
				if m.ProbeOK {
					x := float64(m.ProbeLatency) / float64(time.Millisecond)
					p.ProbeMS = &x
				} else {
					p.ErrorCode = "PROBE_FAILED"
				}
				latest[m.Name] = p
			}
		}

		for _, o := range cfg.Outbounds {
			types[o.Name] = o.Type
			var ms *float64
			var at any
			p, ok := latest[o.Name]
			if live, yes := liveProbes[o.Name]; yes && !live.At.Before(p.At) {
				p, ok = live, true
			}
			if ok {
				ms = p.ProbeMS
				if !p.At.IsZero() {
					at = p.At
				}
			}
			nodes = append(nodes, map[string]any{"name": o.Name, "type": o.Type, "probe_ms": ms, "probe_at": at, "probe_error": p.ErrorCode})
		}
		for _, g := range cfg.Groups {
			types[g.Name] = g.Type
		}
		for _, g := range groupSnapshots {
			members := []any{}
			for _, m := range g.Members {
				var ms *float64
				if m.Probed && m.ProbeOK {
					x := float64(m.ProbeLatency) / float64(time.Millisecond)
					ms = &x
				}
				weight := m.Priority
				if weight == 0 {
					weight = 1
				}
				var available any
				if m.Probed {
					available = m.ProbeOK
				}
				member := map[string]any{"name": m.Name, "protocol": types[m.Name], "probe_ms": ms, "weight": weight, "available": available, "selected": m.Name == g.Current}
				if !m.ProbeAt.IsZero() {
					member["probe_at"] = m.ProbeAt
				}
				p, ok := latest[m.Name]
				if live, yes := liveProbes[m.Name]; yes && !live.At.Before(p.At) {
					p, ok = live, true
				}
				if ok && !p.At.IsZero() {
					member["probe_ms"] = p.ProbeMS
					member["probe_at"] = p.At
					member["probe_error"] = p.ErrorCode
					member["available"] = p.ErrorCode == ""
				}
				if g.Type == "smart" {
					if m.DecisionKnown {
						member["decision_score_ms"] = float64(m.Score) / float64(time.Millisecond)
					} else {
						member["decision_score_ms"] = nil
					}
					member["score_parts"] = m.ScoreParts
					member["effective_samples"] = m.EffectiveSamples
					member["sample_count"] = m.SampleCount
					member["success_rate"] = m.SuccessRate
					member["health_state"] = m.HealthState
					if m.HealthState == "open" || m.HealthState == "recovering" {
						member["available"] = false
					}
					if !m.CooldownUntil.IsZero() {
						member["cooldown_until"] = m.CooldownUntil
					}
					if m.DialLatency > 0 {
						member["dial_ms"] = float64(m.DialLatency) / float64(time.Millisecond)
					}
				}
				if m.Name == g.Candidate {
					member["confirm_progress"] = g.ConfirmProgress
					member["confirm_required"] = g.ConfirmRequired
				}
				members = append(members, member)
			}
			gv := map[string]any{"name": g.Name, "type": g.Type, "current": g.Current, "members": members}
			gv["selection_reason"] = g.Reason
			gv["candidate"] = g.Candidate
			gv["confirm_progress"] = g.ConfirmProgress
			gv["confirm_required"] = g.ConfirmRequired
			gv["remaining_dwell_ms"] = g.RemainingDwell.Milliseconds()
			if g.Type == "smart" {
				gv["selection_mode"] = g.SelectionMode
				gv["algorithm_version"] = 2
				gv["default_member"] = g.Current
				gv["most_used_member"] = g.MostUsedMember
				gv["learned_sites"] = g.LearnedSites
			}
			if g.Fixed != "" {
				gv["fixed"] = g.Fixed
			}
			groups = append(groups, gv)
		}
	}
	todayUp, todayDown := uint64(0), uint64(0)
	date := time.Now().Format("2006-01-02")
	for _, d := range h.history.Daily {
		if d.Date == date {
			todayUp += d.Up
			todayDown += d.Down
		}
	}
	return map[string]any{"probe_round": progress, "probe_group_rounds": groupProgress, "probe_round_result": h.allProbeOutcome, "probe_group_results": h.groupProbeOutcomes, "runtime": map[string]any{"state": h.state, "core_version": kernel.Version, "uptime_ms": uptime, "pid": pid, "memory_bytes": memory}, "mode": h.doc.client.Mode, "groups": groups, "nodes": nodes, "traffic": map[string]any{"up_rate": upRate, "down_rate": downRate, "total_up": h.history.TotalUp, "total_down": h.history.TotalDown, "today_up": todayUp, "today_down": todayDown, "daily": h.history.Daily, "groups": trafficGroups, "rules": trafficRules, "rule_targets": policyHits, "rules_since": rulesSince}, "connections": map[string]any{"active": active, "items": items, "total": total, "tcp": tcp, "udp": udp}, "providers": providers, "local": map[string]any{"http": map[string]any{"host": "127.0.0.1", "port": h.doc.client.HTTPPort, "ready": h.server != nil && h.localReady}, "socks": map[string]any{"host": "127.0.0.1", "port": h.doc.client.SOCKSPort, "ready": h.server != nil && h.localReady}}}
}
