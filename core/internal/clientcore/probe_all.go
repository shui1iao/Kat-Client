package clientcore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/kernel"
	"sync"
	"time"
)

type probeOutcome struct {
	ID     string `json:"id"`
	Failed int    `json:"failed"`
	Error  string `json:"error,omitempty"`
}
type probeRound struct {
	id          string
	ctx         context.Context
	cancel      context.CancelFunc
	server      *kernel.Server
	epoch       context.Context
	generation  uint64
	mu          sync.Mutex
	done, total int
	pending     map[string]bool
	results     map[string]kernel.ProbeResult
	finished    chan struct{}
}

func (r *probeRound) projection() (map[string]any, map[string]kernel.ProbeResult) {
	if r == nil {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	names := []string{}
	for n := range r.pending {
		names = append(names, n)
	}
	results := map[string]kernel.ProbeResult{}
	for n, v := range r.results {
		results[n] = v
	}
	return map[string]any{"id": r.id, "done": r.done, "total": r.total, "names": names}, results
}

// probe.all admits a Host-owned batch, then returns immediately. No IPC or
// whole-batch deadline may turn queued, not-yet-measured nodes into failures.
// Stop/Apply/Close still cancel and drain the original manual epoch.
func (h *Host) probeAll(ctx context.Context, raw json.RawMessage) (any, *Error) {
	if e := decodeParams(raw, &struct{}{}); e != nil {
		return nil, e
	}
	return h.startProbeBatch(ctx, "", "")
}
func (h *Host) startProbeBatch(ctx context.Context, groupName, overrideURL string) (any, *Error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ctx.Err() != nil {
		return nil, requestCanceled()
	}
	s := h.server
	if s == nil {
		return nil, fail("core_not_running", "runtime", "Core is stopped")
	}
	// Only probe.all is globally exclusive. Individual groups share the
	// existing policy permits; the same group cannot own two manual rounds.
	if h.allRound != nil || (groupName == "" && (len(h.groupRounds) != 0 || h.activeManualProbes != 0)) {
		return nil, fail("probe_busy", "", "全节点测速与其它手动测速不能同时运行")
	}
	if groupName != "" && h.groupRounds[groupName] != nil {
		return nil, fail("probe_busy", "params.name", "该策略组正在测速")
	}
	names := []string{}
	for _, o := range s.CurrentConfig().Outbounds {
		if o.Name != "direct" && o.Name != "reject" && o.Type != "direct" && o.Type != "reject" {
			names = append(names, o.Name)
		}
	}
	if groupName != "" {
		names = nil
		found := false
		for _, g := range s.GroupSnapshots() {
			if g.Name == groupName {
				found = true
				for _, m := range g.Members {
					names = append(names, m.Name)
				}
			}
		}
		if !found {
			return nil, fail("probe_failed", "params.name", "Unknown group")
		}
	}
	epoch, policy := h.manualCtx, h.manualPolicy
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fail("probe_failed", "", "无法创建测速轮次标识")
	}
	roundCtx, cancel := context.WithCancel(epoch)
	round := &probeRound{id: hex.EncodeToString(id[:]), ctx: roundCtx, cancel: cancel, server: s, epoch: epoch, generation: s.GenerationID(), total: len(names), pending: map[string]bool{}, results: map[string]kernel.ProbeResult{}, finished: make(chan struct{})}
	for _, n := range names {
		round.pending[n] = true
	}
	if groupName == "" {
		h.allRound = round
		h.allProbeOutcome = nil
	} else {
		if h.groupRounds == nil {
			h.groupRounds = map[string]*probeRound{}
		}
		if h.groupProbeOutcomes == nil {
			h.groupProbeOutcomes = map[string]probeOutcome{}
		}
		h.groupRounds[groupName] = round
		delete(h.groupProbeOutcomes, groupName)
	}
	url, workers, budget := h.doc.client.ProbeURL, h.doc.client.ProbeConcurrency, time.Duration(h.doc.client.ProbeRoundTimeout)
	if overrideURL != "" {
		url = overrideURL
	} else if groupName != "" {
		for _, g := range s.CurrentConfig().Groups {
			if g.Name == groupName && g.Probe != nil && g.Probe.URL != "" {
				url = g.Probe.URL
			}
		}
	}
	h.manualWG.Add(1)
	go func() {
		progress := func(r kernel.ProbeResult) {
			round.mu.Lock()
			round.results[r.Name] = r
			delete(round.pending, r.Name)
			round.done++
			round.mu.Unlock()
		}
		var results []kernel.ProbeResult
		var err error
		if groupName != "" {
			results, err = s.ProbeGroupRoundWithPolicy(roundCtx, groupName, url, policy, budget, progress)
		} else {
			results, err = s.ProbeNodesWithPolicy(roundCtx, names, url, policy, workers, budget, progress)
		}
		outcome := probeOutcome{ID: round.id}
		for _, r := range results {
			if r.ErrorCode != "" || r.Error != "" || r.ProbeMS == nil {
				outcome.Failed++
			}
		}
		if roundCtx.Err() != nil {
			outcome.Error = "测速已取消"
		} else if err != nil {
			outcome.Error = "测速失败，目标节点或策略组已不可用"
		}

		// Stop/Apply waits under h.mu. Release the WG before reacquiring it, then
		// verify captured ownership before publishing; no old epoch can overwrite.
		h.manualWG.Done()
		h.mu.Lock()
		if epoch.Err() == nil && h.server == s && h.manualCtx == epoch && s.GenerationID() == round.generation {
			if roundCtx.Err() == nil {
				for _, r := range results {
					if !r.At.IsZero() && !r.At.Before(h.probes[r.Name].At) {
						h.probes[r.Name] = r
					}
				}
			}
			if groupName == "" {
				h.allProbeOutcome = &outcome
			} else {
				h.groupProbeOutcomes[groupName] = outcome
			}
		}
		if groupName == "" && h.allRound == round {
			h.allRound = nil
		}
		if groupName != "" && h.groupRounds[groupName] == round {
			delete(h.groupRounds, groupName)
		}
		h.mu.Unlock()
		cancel()
		close(round.finished)
	}()
	return map[string]any{"started": true, "id": round.id, "total": len(names)}, nil
}

func (h *Host) probeGroupBatch(ctx context.Context, raw json.RawMessage) (any, *Error) {
	var p struct {
		Name     string `json:"name"`
		URL      string `json:"url"`
		CancelID string `json:"cancel_id,omitempty"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	if p.Name == "" {
		return nil, fail("invalid_params", "params.name", "Name required")
	}
	if p.CancelID != "" {
		if p.URL != "" {
			return nil, fail("invalid_params", "params.url", "取消测速不能同时更改URL")
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		round := h.groupRounds[p.Name]
		if round == nil || round.id != p.CancelID {
			return nil, fail("probe_round_expired", "params.cancel_id", "该组测速已结束或已被新一轮替代")
		}
		round.cancel()
		return map[string]any{"canceled": true, "id": round.id}, nil
	}
	return h.startProbeBatch(ctx, p.Name, p.URL)
}
