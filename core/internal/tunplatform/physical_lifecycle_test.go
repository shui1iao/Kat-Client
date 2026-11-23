package tunplatform

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/clientegress"
	"testing"
	"time"
)

func TestPreparedObservationCannotInstallRoutes(t *testing.T) {
	m, o, _ := fixtureManager(t, false)
	defer m.Close()
	ctx := context.Background()
	p, err := m.Prepare(ctx)
	if err != nil {
		t.Fatal(err)
	}
	next, _ := o.Snapshot(ctx, 7)
	next.Options.Fingerprint = "changed"
	now := time.Now()
	func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		for i, e := range []error{nil, errors.New("transient"), nil, nil} {
			if m.reconcileObserved(ctx, next, e, now.Add(time.Duration(i)*stableWindow)) || m.state.State != "prepared" || m.state.Enabled || m.admission.Load() {
				t.Fatal("untokened transition", m.state)
			}
		}
		for _, c := range routeChanges() {
			if o.rows[c.ID] != nil {
				t.Fatal("watcher installed", c.ID)
			}
		}
	}()
	o.snapshotQuery = func(context.Context, uint64) (Physical, error) { return next, nil }
	if s, err := m.Commit(ctx, p.Token); err != nil || !s.Enabled || m.physical.Options.Fingerprint != "changed" {
		t.Fatal("tokened reread/commit", s, err)
	}
}

// Keep the real Switch fence. Only native socket validation is injected here.
type validatingEgress struct {
	clientegress.Switch
	attempts []clientegress.EgressSnapshot
	deny     bool
	released int
}

func (s *validatingEgress) Reconcile(proof clientegress.EgressSnapshot) error {
	s.attempts = append(s.attempts, proof)
	if s.deny {
		return errors.New("native bind still unavailable")
	}
	s.Replace(&clientegress.Policy{Options: proof.Options})
	return nil
}
func (s *validatingEgress) ReleasePhysical() { s.released++; s.Switch.ReleasePhysical() }

func TestBindFailureSameFingerprintNeedsFreshProof(t *testing.T) {
	m, _, _ := fixtureManager(t, false)
	sw := &validatingEgress{}
	m.egress = sw
	defer m.Close()
	ctx := context.Background()
	prepared, err := m.Prepare(ctx)
	if err != nil {
		t.Fatal(err)
	}
	old, _, _ := sw.PolicySnapshot()
	old.Fail() // even the initial Commit must revalidate
	if state, err := m.Commit(ctx, prepared.Token); err != nil || !state.Enabled || len(sw.attempts) != 2 {
		t.Fatal(state, err, len(sw.attempts))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old, _, _ = sw.PolicySnapshot()
	old.Fail()
	proof := m.physical
	now := time.Now()
	sw.deny = true
	if !m.reconcileObserved(ctx, proof, nil, now) {
		t.Fatal("no stable retry")
	}
	checkFenced := func() {
		t.Helper()
		p, _, frozen := sw.PolicySnapshot()
		if p != old || !frozen || sw.released != 0 || m.state.Enabled || m.admission.Load() {
			t.Fatal("failed policy became ordinary", m.state)
		}
		if err := sw.Control(ctx, "tcp", "127.0.0.1:9", nil); err == nil {
			t.Fatal("socket control bypassed failed lease")
		}
		for _, c := range m.journal.Changes {
			if c.Installed.Route != nil && (c.Desired || c.State != "restored") {
				t.Fatal("dirty split route", c)
			}
		}
	}
	checkFenced()
	m.reconcileObserved(ctx, proof, nil, now.Add(stableWindow))
	checkFenced()
	if len(sw.attempts) != 3 {
		t.Fatal("unchanged fingerprint skipped validation")
	}
	sw.deny = false
	m.reconcileObserved(ctx, proof, nil, now.Add(2*stableWindow))
	fresh, _, frozen := sw.PolicySnapshot()
	if !old.Ready() && fresh != nil && fresh != old && fresh.Ready() && !frozen && m.state.Enabled && m.admission.Load() && len(sw.attempts) == 4 && sw.attempts[3].Generation > sw.attempts[1].Generation {
		return
	}
	t.Fatal("fresh proof not committed", m.state)
}
