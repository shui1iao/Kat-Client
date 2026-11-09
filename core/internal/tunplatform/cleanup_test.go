package tunplatform

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/clientegress"
	"net"
	"reflect"
	"testing"
	"time"
)

func cleanupFixture(t *testing.T) (*Manager, *fakeOS, *fakeBroker, *clientegress.Switch) {
	t.Helper()
	m, o, b := fixtureManager(t, false)
	p, e := m.Prepare(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Commit(context.Background(), p.Token); e != nil {
		t.Fatal(e)
	}
	b.rejectAbsentWAL = true
	sw := &clientegress.Switch{}
	m.config.Egress = sw
	t.Cleanup(func() { m.cancel(); m.wg.Wait() })
	return m, o, b, sw
}
func TestCleanupWaitsExactMIBDisappearanceThenRestoresSameCoreOrdinaryDial(t *testing.T) {
	m, o, b, sw := cleanupFixture(t)
	defer m.Close()
	a := m.journal.Adapter
	reads := 0
	o.goneQuery = func(ctx context.Context, got Adapter) (bool, error) {
		if !reflect.DeepEqual(got, a) {
			t.Fatal("changed adapter identity", got)
		}
		if o.dev.closes == 0 {
			return o.gone, nil
		}
		reads++
		if reads < 3 {
			if _, _, frozen := sw.PolicySnapshot(); !frozen {
				t.Fatal("egress released before removal proof")
			}
			if b.j.Phase == "complete" {
				t.Fatal("Finish before MIB absence")
			}
			return false, nil
		}
		return true, nil
	}
	s, e := m.Disable(context.Background())
	if e != nil || !s.CleanupComplete || s.Intent || s.State != "off" || m.journal != nil || b.j.Phase != "complete" || reads < 3 || o.dev.closes != 1 {
		t.Fatal(s, e, reads, o.dev.closes)
	}
	if p, g, f := sw.PolicySnapshot(); p != nil || g != 0 || f {
		t.Fatal("ordinary egress stranded", g, f)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, e := sw.DialContext(ctx, "tcp", listener.Addr().String())
	if e != nil {
		t.Fatal("same Switch ordinary new dial failed", e)
	}
	c.Close()
}
func TestCleanupDeadlineRetainsActiveJournalAndEgressFenceThenSafeRetry(t *testing.T) {
	m, o, b, sw := cleanupFixture(t)
	defer m.Close()
	o.goneQuery = func(context.Context, Adapter) (bool, error) {
		if o.dev.closes > 0 {
			return false, nil
		}
		return o.gone, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	started := time.Now()
	s, e := m.Disable(ctx)
	if !errors.Is(e, context.DeadlineExceeded) || s.CleanupComplete || s.Intent || b.j.Phase == "complete" || m.journal == nil || time.Since(started) > time.Second {
		t.Fatal("deadline or pending hidden", s, e)
	}
	if _, _, f := sw.PolicySnapshot(); !f {
		t.Fatal("unresolved cleanup released egress")
	}
	// Reproduce .30 active seq8/restored with absent adapter: no repeat WAL/bind.
	before := m.journal.Seq
	o.log = nil
	o.goneQuery = nil
	s, e = m.Disable(context.Background())
	if e != nil || !s.CleanupComplete || b.j.Phase != "complete" || o.dev.closes != 1 || b.j.Seq != before+1 {
		t.Fatal(s, e, o.dev.closes)
	}
	for _, v := range o.log {
		if v == "wal" {
			t.Fatal("re-bound absent withdrawn adapter")
		}
	}
	if _, _, f := sw.PolicySnapshot(); f {
		t.Fatal("ordinary egress remained frozen")
	}
}
func TestCleanupUnknownOrConflictNeverAbsenceAndFirstCauseSurvives(t *testing.T) {
	for _, cause := range []error{errors.New("RECOVERY_CONFLICT"), errors.New("INTERFACE_QUERY")} {
		m, o, b, sw := cleanupFixture(t)
		o.goneQuery = func(context.Context, Adapter) (bool, error) {
			if o.dev.closes > 0 {
				return false, cause
			}
			return o.gone, nil
		}
		s, e := m.Disable(context.Background())
		if !errors.Is(e, cause) || s.CleanupComplete || b.j.Phase == "complete" || m.journal == nil {
			t.Fatal("query unknown swallowed", s, e)
		}
		if _, _, f := sw.PolicySnapshot(); !f {
			t.Fatal("query failure released egress")
		}
		o.goneQuery = nil
		m.Close()
	}
	m, o, b, _ := cleanupFixture(t)
	b.failWAL = true
	cause := errors.New("INTERFACE_QUERY")
	o.goneQuery = func(context.Context, Adapter) (bool, error) { return false, cause }
	_, e := m.Disable(context.Background())
	if e == nil || errors.Is(e, cause) {
		t.Fatal("first WAL failure replaced", e)
	}
	o.goneQuery = nil
	b.failWAL = false
	m.Close()
}
func TestCleanupRemovalThirtySecondContractAndBoundedNativeWait(t *testing.T) {
	if removalWait != 3*time.Second || removalPoll < 100*time.Millisecond || removalPoll > 250*time.Millisecond {
		t.Fatal("native wait contract")
	}
	m, o, _, _ := cleanupFixture(t)
	defer m.Close()
	o.goneQuery = func(context.Context, Adapter) (bool, error) { return false, nil }
	start := time.Now()
	e := m.waitAdapterGoneWithin(context.Background(), m.journal.Adapter, 60*time.Millisecond)
	if !errors.Is(e, errNativePending) || time.Since(start) > time.Second {
		t.Fatal("bounded native pending", e)
	}
	o.goneQuery = nil
}
func TestCleanupUnrestoredMissingAdapterStillRejectsWAL(t *testing.T) {
	m, o, b, sw := cleanupFixture(t)
	o.dev.Close()
	m.plane = nil
	m.dev = nil
	m.transferred = false
	_, e := m.Disable(context.Background())
	if e == nil || e.Error() != "JOURNAL_ADAPTER" {
		t.Fatal("unrestored disappearance must reject", e)
	}
	if b.j.Phase == "complete" {
		t.Fatal("bad account completed")
	}
	if _, _, f := sw.PolicySnapshot(); !f {
		t.Fatal("dirty account released")
	}
	m.cancel()
	m.wg.Wait()
}

func TestCleanupFinishErrorReleasesOnlyProvenNativeClearAndRetainsJournal(t *testing.T) {
	m, o, b, sw := cleanupFixture(t)
	defer m.Close()
	cause := At("journal_save", "JOURNAL_WRITE", errors.New("JOURNAL_WRITE"))
	b.finishError = cause
	s, e := m.Disable(context.Background())
	if e != cause || s.CleanupComplete || !s.NetworkClear || s.Intent || s.Enabled || s.State != "error" || m.journal == nil || b.j.Phase != "active" {
		t.Fatal("Finish error hidden or native fact missing", s, e)
	}
	if s.Failure == nil || s.Failure.Stage != "journal_save" || s.Failure.Code != "JOURNAL_WRITE" {
		t.Fatal("first typed lost", s.Failure)
	}
	if p, _, f := sw.PolicySnapshot(); p != nil || f {
		t.Fatal("known clean network stranded")
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, e := sw.DialContext(ctx, "tcp", listener.Addr().String())
	if e != nil {
		t.Fatal("same core ordinary dial blocked", e)
	}
	c.Close()
	if _, e = m.Prepare(context.Background()); e == nil {
		t.Fatal("new Begin passed retained journal")
	}
	b.finishError = nil
	s, e = m.Disable(context.Background())
	if e != nil || !s.CleanupComplete || !s.NetworkClear || b.j.Phase != "complete" || o.dev.closes != 1 {
		t.Fatal("normal cleanup retry failed", s, e)
	}
}
func TestCleanupNativeClearRejectsResidualRouteQueryFailureAndWrongOwner(t *testing.T) {
	for _, kind := range []string{"route-present", "route-query-error", "owner", "unknown-row"} {
		t.Run(kind, func(t *testing.T) {
			m, o, b, sw := cleanupFixture(t)
			cause := At("journal_save", "JOURNAL_WRITE", errors.New("JOURNAL_WRITE"))
			b.finishError = cause
			s, e := m.Disable(context.Background())
			if e != cause || !s.NetworkClear {
				t.Fatal(s, e)
			}
			// Original ledger and identity remain exact; a follow-up read must not
			// substitute adapter absence for GetIpForwardEntry2 route absence.
			switch kind {
			case "route-present", "route-query-error":
				o.readQuery = func(a Adapter, c Change) (*Value, error) {
					if a != m.journal.Adapter {
						t.Fatal("foreign adapter read")
					}
					if c.Installed.Route != nil {
						if kind == "route-query-error" {
							return nil, errors.New("ROUTE_QUERY")
						}
						return &c.Installed, nil
					}
					return nil, nil
				}
			case "owner":
				m.journal.Launch.OwnerSID = "different-owner"
			case "unknown-row":
				m.journal.Changes = append(m.journal.Changes, Change{ID: "unknown", State: "restored"})
			}
			s, e = m.Disable(context.Background())
			if e == nil || s.NetworkClear || s.CleanupComplete || b.j.Phase == "complete" {
				t.Fatal("dirty or unknown treated clean", s, e)
			}
			if _, _, f := sw.PolicySnapshot(); !f {
				t.Fatal("uncertain network released")
			}
			m.cancel()
			m.wg.Wait()
		})
	}
}
