package tunplatform

import (
	"context"
	"errors"
	"time"
)

// No alias, packet, endpoint or lease is carried by these fixed observations.
// LUID is decimal text so the GUI cannot round a 64-bit native identity.
type GoneRow struct {
	GUID       string `json:"guid"`
	LUID       string `json:"luid"`
	OperStatus uint32 `json:"oper_status"`
}
type GoneRead struct {
	Gone        bool
	RC          *uint32
	Rows        []GoneRow
	Compartment uint32
}
type RemovalObservation struct {
	Branch      string    `json:"branch"`
	ElapsedMS   uint64    `json:"elapsed_ms"`
	RC          *uint32   `json:"get_if_table2_rc"`
	Compartment uint32    `json:"compartment"`
	Rows        []GoneRow `json:"rows"`
}

var errNativePending = errors.New("native removal pending")

const removalWait = 3 * time.Second
const removalPoll = 200 * time.Millisecond

func (m *Manager) observeRemoval(r GoneRead, branch string) {
	if m.cleanupStarted.IsZero() {
		m.cleanupStarted = time.Now()
	}
	d := Diagnostic{Stage: "cleanup_gone", Code: "TUN_CLEANUP_OBSERVATION", Changes: []string{"unknown"}, Removal: &RemovalObservation{Branch: branch, ElapsedMS: uint64(time.Since(m.cleanupStarted).Milliseconds()), RC: r.RC, Compartment: r.Compartment, Rows: r.Rows}}
	if d.Removal.Rows == nil {
		d.Removal.Rows = []GoneRow{}
	}
	if m.config.Observe != nil {
		m.config.Observe(d)
	}
}
func (m *Manager) inspectRemoval(ctx context.Context, a Adapter) (GoneRead, error) {
	if m.cleanupStarted.IsZero() {
		m.cleanupStarted = time.Now()
	}
	r, e := m.os.InspectGone(ctx, a)
	if !m.removalFirst {
		m.removalFirst = true
		m.observeRemoval(r, "first")
	}
	if e == nil && r.Gone && !m.removalFinal {
		m.removalFinal = true
		m.observeRemoval(r, "final")
	}
	if e != nil {
		d := Describe("cleanup_gone", e)
		d.Removal = &RemovalObservation{Branch: "query_error", ElapsedMS: uint64(time.Since(m.cleanupStarted).Milliseconds()), RC: r.RC, Compartment: r.Compartment, Rows: r.Rows}
		e = &Failure{Detail: d, cause: e}
	}
	return r, e
}
func (m *Manager) waitAdapterGone(ctx context.Context, a Adapter) error {
	return m.waitAdapterGoneWithin(ctx, a, removalWait)
}
func (m *Manager) waitAdapterGoneWithin(ctx context.Context, a Adapter, budget time.Duration) error {
	if budget <= 0 {
		r, e := m.inspectRemoval(ctx, a)
		if e != nil {
			return At("cleanup_gone", "", e)
		}
		if r.Gone {
			return nil
		}
		if !m.removalPending {
			m.removalPending = true
			m.observeRemoval(r, "wait_timeout")
		}
		return errNativePending
	}
	wait, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	tick := time.NewTicker(removalPoll)
	defer tick.Stop()
	for {
		r, e := m.inspectRemoval(ctx, a)
		if e != nil {
			return At("cleanup_gone", "", e)
		}
		if r.Gone {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wait.Done():
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// Last known row really existed. This is not an absent/API-error claim.
			if !m.removalPending {
				m.removalPending = true
				m.observeRemoval(r, "wait_timeout")
			}
			return errNativePending
		case <-tick.C:
			// A deadline reached between ticks is not a failed native query.
			if wait.Err() != nil && ctx.Err() == nil {
				if !m.removalPending {
					m.removalPending = true
					m.observeRemoval(r, "wait_timeout")
				}
				return errNativePending
			}
		}
	}
}
func (m *Manager) finishOwnedLocked(ctx context.Context) error {
	s, e := m.config.Broker.Finish(ctx, m.journal.Seq)
	if e != nil {
		return e
	}
	if e = m.accept(s); e != nil {
		return e
	}
	if !s.CleanupComplete {
		return errors.New("RECOVERY_PENDING")
	}
	m.journal = nil
	return nil
}

// Called only after the original withdrawal committed. One goroutine, same
// launch/journal/lease; no new WAL, adapter open, PnP write or new capability.
func (m *Manager) startCleanupWorkerLocked() {
	if m.cleanupWorker || m.closed {
		return
	}
	m.cleanupWorker = true
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-m.life.Done():
				m.mu.Lock()
				m.cleanupWorker = false
				m.mu.Unlock()
				return
			case <-tick.C:
			}
			m.mu.Lock()
			if m.closed || !m.state.CleanupPending || m.journal == nil {
				m.cleanupWorker = false
				m.mu.Unlock()
				return
			}
			ctx, cancel := context.WithTimeout(m.life, 12*time.Second)
			e := m.validateWithdrawal()
			var r GoneRead
			if e == nil {
				r, e = m.inspectRemoval(ctx, m.journal.Adapter)
			}
			if e == nil && !r.Gone {
				cancel()
				m.mu.Unlock()
				continue
			}
			if e == nil {
				e = m.verifyNetworkClear(ctx)
			}
			if e != nil && (e.Error() == "RECOVERY_PENDING" || e.Error() == "ADAPTER_REMAINS") {
				cancel()
				m.mu.Unlock()
				continue
			} // exact owned route still present: remain fenced
			if e == nil {
				e = m.finishOwnedLocked(ctx)
			} // original service re-verifies caller + lease + every resource
			cancel()
			if e != nil {
				// Real query/identity/Finish failure is retained, never mapped to clean.
				// Stop this owner rather than hammering a terminal failure every two sec.
				d := Describe("cleanup_gone", e)
				m.state.Failure = &d
				m.state.Code = d.Code
				m.state.State = "error"
				if m.config.Observe != nil {
					m.config.Observe(d)
				}
				m.state.NetworkClear = false
			} else {
				m.pendingRequiresFinish = false
				m.state.CleanupPending = false
				m.state.CleanupComplete = true
				m.state.NetworkClear = true
				m.state.State = "off"
				m.state.Code = ""
				m.state.Failure = nil
				if m.config.Egress != nil {
					m.config.Egress.ReleasePhysical()
				}
			}
			m.publish()
			m.cleanupWorker = false
			m.mu.Unlock()
			return
		}
	}()
}

// Enable must wait for the sole existing cleanup owner, never create a second
// adapter or rebind a lease while its account is pending.
func (m *Manager) awaitPending(ctx context.Context) error {
	wait, cancel := context.WithTimeout(ctx, removalWait)
	defer cancel()
	tick := time.NewTicker(removalPoll)
	defer tick.Stop()
	for {
		m.mu.Lock()
		pending := m.state.CleanupPending
		failed := m.state.Failure
		worker := m.cleanupWorker
		m.mu.Unlock()
		if !pending {
			return nil
		}
		if failed != nil && !worker {
			return &Failure{Detail: *failed, cause: errors.New(failed.Code)}
		}
		select {
		case <-wait.Done():
			return At("prepare_guard", "RECOVERY_PENDING", errors.New("RECOVERY_PENDING"))
		case <-tick.C:
		}
	}
}
