package clientcore

import (
	"context"
	"errors"
	"syscall"
	"time"
)

const windowsRenameBudget = 2 * time.Second

// retryWindowsRename is used only by the Windows replacement path. Only
// replace-rename is retried: staging, write, sync, ACL and source errors are
// returned unchanged. Each failed rename is still uncommitted, so every new
// attempt must repeat the source check. Success is the commit point: do not
// turn a late cancellation into a false claim that the source was retained.
// now/wait/rename are arguments (not mutable globals) for deterministic tests.
func retryWindowsRename(ctx context.Context, check func() error, rename func() error, now func() time.Time, wait func(context.Context, time.Duration) error) error {
	deadline := now().Add(windowsRenameBudget)
	callerLimited := false
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
		callerLimited = true
	}
	var last error
	exhausted := func() error {
		if e := ctx.Err(); e != nil {
			return e
		}
		if callerLimited {
			return context.DeadlineExceeded
		}
		if last != nil {
			return last
		}
		return context.DeadlineExceeded
	}
	delay := 5 * time.Millisecond
	for {
		if e := ctx.Err(); e != nil {
			return e
		}
		if !now().Before(deadline) {
			return exhausted()
		}
		if e := check(); e != nil {
			if ce := ctx.Err(); ce != nil {
				return ce
			}
			return e
		}
		if !now().Before(deadline) {
			return exhausted()
		}
		// Predicate I/O may outlive cancellation. Keep the final admission check
		// immediately before rename; success, not a later ctx read, commits it.
		if e := ctx.Err(); e != nil {
			return e
		}
		last = rename()
		if last == nil {
			return nil
		}
		if e := ctx.Err(); e != nil {
			return e
		}
		if !transientWindowsRename(last) {
			return last
		}
		remaining := deadline.Sub(now())
		if remaining <= 0 {
			return exhausted()
		}
		pause := delay
		if pause > remaining {
			pause = remaining
		}
		if e := wait(ctx, pause); e != nil {
			return e
		}
		if delay < 100*time.Millisecond {
			delay *= 2
			if delay > 100*time.Millisecond {
				delay = 100 * time.Millisecond
			}
		}
	}
}

func transientWindowsRename(err error) bool {
	var n syscall.Errno
	return errors.As(err, &n) && (n == 5 || n == 32 || n == 33) // ACCESS_DENIED, SHARING/LOCK_VIOLATION
}
func waitWindowsRename(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
