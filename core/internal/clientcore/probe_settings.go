package clientcore

import (
	"context"
	"encoding/json"
	"time"

	"github.com/shui1iao/Kat/internal/kernel"
)

// Defaults are applied only to the runtime projection, never the source bytes.
// The round timeout bounds queueing, Via readiness and all target probes. The
// per-node timeout applies only after dependency preparation, not to cold Via
// url-test health rounds. Background group timeouts remain group-owned.
func validateProbeSettings(raw []byte, c *Client) *Error {
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	for _, k := range []string{"probe_timeout", "probe_round_timeout", "probe_concurrency", "unified_delay"} {
		if b, ok := fields[k]; ok && string(b) == "null" {
			return fail("invalid_document", "client."+k, "Null probe setting is not supported")
		}
	}
	if _, ok := fields["probe_timeout"]; !ok {
		c.ProbeTimeout = kernel.Duration(5 * time.Second)
	}
	if _, ok := fields["probe_round_timeout"]; !ok {
		c.ProbeRoundTimeout = kernel.Duration(10 * time.Second)
	}
	if _, ok := fields["probe_concurrency"]; !ok {
		c.ProbeConcurrency = 50
	}
	timeout, round := time.Duration(c.ProbeTimeout), time.Duration(c.ProbeRoundTimeout)
	if timeout < 100*time.Millisecond || timeout > 60*time.Second {
		return fail("invalid_document", "client.probe_timeout", "Expected duration in 100ms..60s")
	}
	if round < 100*time.Millisecond || round > 300*time.Second || round < timeout {
		return fail("invalid_document", "client.probe_round_timeout", "Expected duration in 100ms..300s and at least probe_timeout")
	}
	if c.ProbeConcurrency < 1 || c.ProbeConcurrency > 50 {
		return fail("invalid_document", "client.probe_concurrency", "Expected integer in 1..50")
	}
	return nil
}

// Drain canceled old manual requests before installing a new instance permit
// set. Done occurs before their result writers reacquire h.mu, so this cannot
// deadlock Stop/Apply and cannot temporarily exceed the new concurrency bound.
func (h *Host) resetManualLocked() {
	if h.manualCancel != nil {
		h.manualCancel()
		h.manualWG.Wait()
		h.allRound = nil
	}
	h.groupRounds = nil
	h.groupProbeOutcomes = nil
	h.allProbeOutcome = nil
	h.manualNodes = nil
	h.manualCtx, h.manualCancel = context.WithCancel(h.probeCtx)
	h.manualPolicy, _ = kernel.NewManualProbePolicy(time.Duration(h.doc.client.ProbeTimeout), h.doc.client.ProbeConcurrency)
	h.manualPolicy.SetEpoch(h.manualCtx)
	h.manualPolicy.SetUnifiedDelay(h.doc.client.UnifiedDelay == nil || *h.doc.client.UnifiedDelay)
}

func providerRefreshContext(ctx context.Context, s *kernel.Server, name string) (context.Context, context.CancelFunc, error) {
	timeout, e := s.ProviderRefreshTimeout(name)
	if e != nil {
		return nil, nil, e
	}
	// The provider owns the actual fetch deadline; the wrapper allows a small
	// bounded margin for parse/cache/reload rather than truncating it at 30s.
	c, cancel := context.WithTimeout(ctx, timeout+time.Second)
	return c, cancel, nil
}
