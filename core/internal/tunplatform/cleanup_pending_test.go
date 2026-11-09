package tunplatform

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// Production Manager/worker contract, with an OS seam. This is NOT a Windows
// PnP verification or evidence that Wintun disappears within any duration.
func TestPendingOffSoleOwnerRouteFenceFinishFailureAndNormalRetry(t *testing.T) {
	m, o, b, sw := cleanupFixture(t)
	gone := false
	var observations []Diagnostic
	m.config.Observe = func(d Diagnostic) { observations = append(observations, d) }
	o.goneQuery = func(context.Context, Adapter) (bool, error) {
		if o.dev.closes == 0 {
			return false, nil
		}
		return gone, nil
	}
	start := time.Now()
	s, e := m.Disable(context.Background())
	if e != nil || !s.CleanupPending || s.CleanupComplete || s.Intent || s.Enabled || s.State != "off" || time.Since(start) < 2500*time.Millisecond || time.Since(start) > 5*time.Second {
		t.Fatal("OFF pending contract", s, e, time.Since(start))
	}
	if _, _, f := sw.PolicySnapshot(); f {
		t.Fatal("remained frozen after routes withdrawn")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	_, e = m.Prepare(ctx)
	cancel()
	if e == nil {
		t.Fatal("pending Begin passed")
	}
	m.mu.Lock()
	seq := b.j.Seq
	gone = true
	o.readQuery = func(a Adapter, c Change) (*Value, error) {
		if c.Installed.Route != nil {
			return &c.Installed, nil
		}
		return nil, nil
	}
	m.mu.Unlock()
	time.Sleep(2200 * time.Millisecond)
	m.mu.Lock()
	if b.j.Seq != seq || b.j.Phase == "complete" || !m.state.CleanupPending {
		t.Fatal("dirty route completed")
	}
	o.readQuery = nil
	cause := At("journal_save", "JOURNAL_WRITE", errors.New("JOURNAL_WRITE"))
	b.finishError = cause
	m.mu.Unlock()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		failed := m.state.Failure != nil && !m.cleanupWorker
		m.mu.Unlock()
		if failed {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	m.mu.Lock()
	if m.state.Failure == nil || m.state.Failure.Stage != "journal_save" || m.state.CleanupComplete || !m.state.CleanupPending || m.state.NetworkClear {
		t.Fatal("pending Finish failure erased", m.state)
	}
	if _, _, f := sw.PolicySnapshot(); f {
		t.Fatal("pending Finish failure froze ordinary egress after routes withdrawn")
	}
	b.finishError = nil
	m.mu.Unlock()
	s, e = m.Disable(context.Background())
	if e != nil || !s.CleanupComplete || s.CleanupPending || !s.NetworkClear || b.j.Phase != "complete" || b.j.Seq != seq+1 || o.dev.closes != 1 {
		t.Fatal("normal idempotent retry failed", s, e)
	}
	if _, _, f := sw.PolicySnapshot(); f {
		t.Fatal("Finish succeeded but fence retained")
	}
	counts := map[string]int{}
	for _, d := range observations {
		if d.Removal != nil {
			counts[d.Removal.Branch]++
		}
	}
	if counts["first"] != 1 || counts["final"] != 1 || counts["wait_timeout"] != 1 {
		t.Fatal("missing/duplicate native observations", counts)
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	c, e := sw.DialContext(context.Background(), "tcp", l.Addr().String())
	if e != nil {
		t.Fatal("ordinary same Switch dial", e)
	}
	c.Close()
	if e = m.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestDisableWhileCleanupPendingReturnsImmediatelyAndWorkerCompletes(t *testing.T) {
	m, o, b, sw := cleanupFixture(t)
	gone := false
	o.goneQuery = func(context.Context, Adapter) (bool, error) {
		if o.dev.closes == 0 {
			return false, nil
		}
		return gone, nil
	}
	s, e := m.Disable(context.Background())
	if e != nil || !s.CleanupPending || s.CleanupComplete {
		t.Fatal("initial pending Disable failed", s, e)
	}
	quitStart := time.Now()
	s2, e2 := m.Disable(context.Background())
	if e2 != nil || !s2.CleanupPending || s2.CleanupComplete || time.Since(quitStart) > 500*time.Millisecond {
		t.Fatal("second Disable during active cleanup_pending blocked or lost pending state", s2, e2, time.Since(quitStart))
	}
	m.mu.Lock()
	gone = true
	m.mu.Unlock()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		st := m.Status()
		if st.CleanupComplete && !st.CleanupPending {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	final := m.Status()
	if !final.CleanupComplete || final.CleanupPending || !final.NetworkClear || b.j.Phase != "complete" {
		t.Fatal("background cleanup did not complete after non-blocking quit Disable", final, b.j)
	}
	if _, _, f := sw.PolicySnapshot(); f {
		t.Fatal("physical egress remained fenced after completion")
	}
	if e := m.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestWaitAdapterGoneWithinZeroBudgetAndBoundedLoop(t *testing.T) {
	// Case 1: budget <= 0 while adapter is still present -> returns errNativePending (no TUN_TIMEOUT), Disable stays cleanup_pending.
	m, o, b, sw := cleanupFixture(t)
	gone := false
	var observations []Diagnostic
	m.config.Observe = func(d Diagnostic) { observations = append(observations, d) }
	o.goneQuery = func(ctx context.Context, _ Adapter) (bool, error) {
		if e := ctx.Err(); e != nil {
			return false, e
		}
		if o.dev.closes == 0 {
			return false, nil
		}
		return gone, nil
	}
	s, e := m.Disable(context.Background())
	if e != nil || !s.CleanupPending || s.CleanupComplete || s.State != "off" || s.Code != "RECOVERY_PENDING" {
		t.Fatal("initial Disable pending failed", s, e)
	}
	// Immediate second Disable (budget=0 path) while adapter is still present: must NOT fail with TUN_TIMEOUT / query_error.
	s2, e2 := m.Disable(context.Background())
	if e2 != nil || !s2.CleanupPending || s2.CleanupComplete || s2.State != "off" || s2.Code != "RECOVERY_PENDING" || s2.Failure != nil {
		t.Fatal("budget=0 Disable with adapter present failed", s2, e2)
	}
	for _, d := range observations {
		if d.Removal != nil && d.Removal.Branch == "query_error" {
			t.Fatal("unexpected query_error observation on budget=0 check", d)
		}
	}
	// Case 2: budget <= 0 when adapter is already gone -> returns nil immediately and completes cleanup.
	m.mu.Lock()
	gone = true
	m.mu.Unlock()
	s3, e3 := m.Disable(context.Background())
	if e3 != nil || !s3.CleanupComplete || s3.CleanupPending || !s3.NetworkClear || s3.State != "off" || s3.Failure != nil || b.j.Phase != "complete" {
		t.Fatal("budget=0 Disable with adapter gone did not complete", s3, e3, b.j)
	}
	if _, _, f := sw.PolicySnapshot(); f {
		t.Fatal("physical egress remained fenced after budget=0 completion")
	}
	// Case 3: budget > 0 remains bounded by wait when adapter stays present.
	start := time.Now()
	m.mu.Lock()
	gone = false
	err := m.waitAdapterGoneWithin(context.Background(), b.j.Adapter, 450*time.Millisecond)
	m.mu.Unlock()
	if !errors.Is(err, errNativePending) || time.Since(start) < 400*time.Millisecond || time.Since(start) > 1500*time.Millisecond {
		t.Fatal("budget > 0 wait was not bounded or returned wrong error", err, time.Since(start))
	}
	if e := m.Close(); e != nil {
		t.Fatal(e)
	}
}
