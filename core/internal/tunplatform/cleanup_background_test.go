package tunplatform

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A restored active account fixture exercises the SAME production worker,
// not Wintun or Windows timing. No pending cycle may release before Finish.
func TestBackgroundOwnedCompletionAndQueryErrorFence(t *testing.T) {
	for _, queryFails := range []bool{false, true} {
		m, o, b, sw := cleanupFixture(t)
		b.finishError = errors.New("JOURNAL_WRITE")
		if _, e := m.Disable(context.Background()); e == nil {
			t.Fatal("fixture needs active account")
		}
		m.mu.Lock()
		b.finishError = nil
		m.pendingRequiresFinish = true
		m.state.CleanupPending = true
		m.state.CleanupComplete = false
		m.state.NetworkClear = false
		m.state.Failure = nil
		sw.FreezeNew()
		if queryFails {
			o.goneQuery = func(context.Context, Adapter) (bool, error) { return false, errors.New("INTERFACE_QUERY") }
		}
		m.startCleanupWorkerLocked()
		m.startCleanupWorkerLocked()
		m.mu.Unlock()
		end := time.Now().Add(4 * time.Second)
		for time.Now().Before(end) {
			m.mu.Lock()
			running := m.cleanupWorker
			m.mu.Unlock()
			if !running {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		m.mu.Lock()
		if queryFails {
			if m.state.CleanupComplete || !m.state.CleanupPending || m.state.Failure == nil || b.j.Phase == "complete" {
				t.Fatal("query error became absence")
			}
			if _, _, f := sw.PolicySnapshot(); !f {
				t.Fatal("unknown released")
			}
		} else {
			if !m.state.CleanupComplete || m.state.CleanupPending || m.journal != nil || b.j.Phase != "complete" {
				t.Fatal("worker did not finish")
			}
			if _, _, f := sw.PolicySnapshot(); f {
				t.Fatal("successful Finish still fenced")
			}
		}
		o.goneQuery = nil
		m.mu.Unlock()
		m.Close()
	}
}
