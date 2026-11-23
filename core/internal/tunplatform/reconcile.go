package tunplatform

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/clientegress"
	"time"
)

const stableWindow = 750 * time.Millisecond
const reviewInterval = 15 * time.Second

func egressSnapshot(p Physical, generation, epoch uint64) clientegress.EgressSnapshot {
	out := clientegress.EgressSnapshot{Generation: generation, Epoch: epoch, Options: p.Options}
	for _, o := range p.Owners {
		v := clientegress.OwnerState{LUID: o.LUID, IfIndex: o.IfIndex, Family: o.Family, Up: o.Up, Safe: o.Up}
		for _, s := range o.Sources {
			v.Sources = append(v.Sources, clientegress.SourceState{Address: s.Address, Scope: s.Scope, Usable: s.Usable})
		}
		out.Owners = append(out.Owners, v)
	}
	return out
}
func (m *Manager) startWatch() error {
	dirty, e := m.os.Watch(m.life)
	if e != nil {
		return e
	}
	m.watchStarted = true
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		review := time.NewTicker(reviewInterval)
		defer review.Stop()
		var timer *time.Timer
		var due <-chan time.Time
		for {
			// Wake on a live binding failure even when Windows reports no row change.
			m.mu.Lock()
			var failed <-chan struct{}
			if m.committed && m.state.Enabled && m.egress != nil {
				p, _, _ := m.egress.PolicySnapshot()
				if p != nil {
					failed = p.Failed()
				}
			}
			m.mu.Unlock()
			select {
			case <-m.life.Done():
				if timer != nil {
					timer.Stop()
				}
				return
			case <-failed:
			case <-m.watchWake:
				continue // resubscribe after Commit; it just reread the OS
			case <-dirty:
			case <-review.C:
			case <-due:
				due = nil
			}
			m.mu.Lock()
			if m.committed && m.journal != nil && m.plane != nil && m.state.Intent && !m.closed {
				ctx, cancel := context.WithTimeout(m.life, 3*time.Second)
				p, err := m.os.Snapshot(ctx, m.journal.Adapter.LUID)
				retry := m.reconcileObserved(ctx, p, err, time.Now())
				cancel()
				if retry {
					if timer == nil {
						timer = time.NewTimer(stableWindow)
					} else {
						if !timer.Stop() {
							select {
							case <-timer.C:
							default:
							}
						}
						timer.Reset(stableWindow)
					}
					due = timer.C
				}
			}
			m.mu.Unlock()
		}
	}()
	return nil
}

func (m *Manager) egressReady() bool {
	if m.egress == nil {
		return true // data-plane-only test fixture
	}
	p, _, frozen := m.egress.PolicySnapshot()
	return !frozen && p.Ready()
}
func (m *Manager) admissionHealth() error {
	if !m.egressReady() {
		return errors.New("EGRESS_BIND_UNSAFE")
	}
	return m.healthy()
}

// Called only by the manager's serial loop under mu. Notifications are hints:
// no callback row or missing field is accepted as an OS observation.
func (m *Manager) reconcileObserved(ctx context.Context, next Physical, readErr error, now time.Time) bool {
	// Observation never grants initial route authority, even after repeated
	// stable observations or a failed observation while Prepare holds a token.
	if !m.committed {
		return false
	}
	failedBind := m.state.Enabled && !m.egressReady()
	if failedBind {
		m.rebindRequired = true
	}
	if readErr != nil {
		m.candidate = nil
		m.suspend(ctx, "WAITING_NETWORK")
		return false
	}
	proof := egressSnapshot(next, m.state.Generation+1, m.epoch.Load())
	if m.egress != nil {
		m.egress.RetireObserved(proof.Owners)
	}
	if e := physicalSafe(next); e != nil {
		m.candidate = nil
		m.suspend(ctx, e.Error())
		return false
	}
	if failedBind {
		m.candidate = nil
		m.suspend(ctx, "EGRESS_BIND_UNSAFE")
	}
	changed := next.Options.Fingerprint != m.physical.Options.Fingerprint || m.state.State == "waiting_network" || m.state.State == "egress_bind_unsafe"
	if !changed {
		m.candidate = nil
		return false
	}
	if m.candidate == nil || m.candidate.Options.Fingerprint != next.Options.Fingerprint {
		copy := next
		m.candidate = &copy
		m.candidateSince = now
		return true
	}
	if now.Sub(m.candidateSince) < stableWindow {
		return true
	}
	ownerChanged := next.Options.Identity != m.physical.Options.Identity
	if ownerChanged {
		m.admission.Store(false)
		if m.egress != nil {
			m.egress.FreezeNew()
		}
		m.plane.Quiesce()
	}
	// A lazy PacketConn may bind on first WriteTo. Do not publish the next
	// owner until even pre-fence sends and DNS work have left the old handler.
	if ownerChanged || !m.state.Enabled {
		if err := m.plane.DrainUDP(ctx); err != nil {
			m.suspend(ctx, "EGRESS_BIND_UNSAFE")
			return true
		}
	}
	if ownerChanged {
		m.epoch.Add(1)
	}
	m.state.Generation++
	proof.Generation = m.state.Generation
	proof.Epoch = m.epoch.Load()
	if m.egress != nil {
		if e := m.egress.Reconcile(proof); e != nil {
			m.rebindRequired = true
			m.suspend(ctx, e.Error())
			return false
		}
	}
	if e := m.admissionHealth(); e != nil {
		if !m.egressReady() {
			m.rebindRequired = true
		}
		m.suspend(ctx, e.Error())
		return false
	}
	// Safe resume precedes route commit; callbacks still observe OS gate=false.
	if !m.state.Enabled {
		if e := m.plane.Resume(); e != nil {
			m.suspend(ctx, e.Error())
			return false
		}
		if e := m.install(ctx, routeChanges()); e != nil {
			m.suspend(ctx, e.Error())
			return false
		}
	}
	if ownerChanged && m.state.Enabled {
		if e := m.plane.Resume(); e != nil {
			m.suspend(ctx, e.Error())
			return false
		}
	}
	if e := m.admissionHealth(); e != nil {
		if !m.egressReady() {
			m.rebindRequired = true
		}
		m.suspend(ctx, e.Error())
		return false
	}
	m.rebindRequired = false
	m.physical = next
	m.candidate = nil
	m.admission.Store(true)
	m.state.Enabled = true
	m.state.State = "on"
	m.state.Code = ""
	m.publish()
	return false
}
func (m *Manager) suspend(ctx context.Context, code string) {
	m.admission.Store(false)
	if m.plane != nil {
		m.plane.Quiesce()
	}
	if m.egress != nil {
		m.egress.FreezeNew()
	}
	m.state.Enabled = false
	m.state.Intent = true
	m.state.CleanupComplete = false
	// Retain own interface/virtual DNS and DATA Runtime for bounded recovery, but
	// remove all owned interception rows before reporting waiting/unsafe.
	routesCleared := true
	if m.journal != nil {
		all := append([]Change(nil), m.journal.Changes...)
		for i := range all {
			if all[i].Installed.Route != nil {
				all[i].Desired = false
			}
		}
		if e := m.transact(ctx, all); e != nil {
			routesCleared = false
			code += "; RECOVERY_PENDING: " + e.Error()
		}
	}
	if routesCleared && !m.rebindRequired && m.egress != nil && (m.plane == nil || m.plane.DrainUDP(ctx) == nil) {
		m.egress.ReleasePhysical()
	}
	m.state.Code = code
	m.state.State = "waiting_network"
	if code == "EGRESS_BIND_UNSAFE" {
		m.state.State = "egress_bind_unsafe"
	}
	m.publish()
}
