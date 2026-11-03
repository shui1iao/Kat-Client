package clientcore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Test-only handshake: atomicWrite/its predicate use Err; Done is reached
// by waitWindowsRename only after a rename returned a recognized denial.
// Trigger the event synchronously there, before the next predicate. No sleep,
// production hooks or global state determines the ordering.
type sharingDeniedContext struct {
	context.Context
	once        sync.Once
	observed    bool
	afterDenied func()
}

func (c *sharingDeniedContext) Done() <-chan struct{} {
	c.once.Do(func() { c.observed = true; c.afterDenied() })
	return c.Context.Done()
}

type renameRetryHarness struct {
	at            time.Time
	calls, checks int
	waits         []time.Duration
	attempt       func() error
	check         func() error
	onWait        func() error
}

func (h *renameRetryHarness) run(ctx context.Context) error {
	return retryWindowsRename(ctx, func() error {
		h.checks++
		if h.check != nil {
			return h.check()
		}
		return nil
	}, func() error { h.calls++; return h.attempt() }, func() time.Time { return h.at }, func(_ context.Context, d time.Duration) error {
		h.waits = append(h.waits, d)
		h.at = h.at.Add(d)
		if h.onWait != nil {
			return h.onWait()
		}
		return nil
	})
}
func renameErr(n syscall.Errno) error {
	return &os.LinkError{Op: "rename", Old: "synthetic-stage", New: "synthetic-destination", Err: n}
}
func TestWindowsRenameTransientErrors(t *testing.T) {
	for _, n := range []syscall.Errno{5, 32, 33} {
		t.Run(numericErrno(n), func(t *testing.T) {
			h := &renameRetryHarness{at: time.Unix(0, 0)}
			h.attempt = func() error {
				if h.calls < 3 {
					return renameErr(n)
				}
				return nil
			}
			if e := h.run(context.Background()); e != nil || h.calls != 3 || h.checks != 3 || len(h.waits) != 2 || h.waits[0] != 5*time.Millisecond || h.waits[1] != 10*time.Millisecond {
				t.Fatal("transient rename was not retried with source rechecks", e, h.calls, h.checks)
			}
		})
	}
	for _, n := range []syscall.Errno{5, 32, 33} {
		for _, release := range []string{"after-sixth", "after-300ms"} {
			t.Run("recover-"+release+"-"+numericErrno(n), func(t *testing.T) {
				start := time.Unix(0, 0)
				h := &renameRetryHarness{at: start}
				h.attempt = func() error {
					if release == "after-sixth" && h.calls <= 6 || release == "after-300ms" && h.at.Sub(start) < 300*time.Millisecond {
						return renameErr(n)
					}
					return nil
				}
				if e := h.run(context.Background()); e != nil || h.calls <= 6 || h.checks != h.calls || h.at.Sub(start) <= 250*time.Millisecond {
					t.Fatal("recoverable rename rejected by former six-attempt/250ms limit", e, h.calls, h.checks, h.at.Sub(start))
				}
			})
		}
	}

}
func numericErrno(n syscall.Errno) string {
	switch n {
	case 5:
		return "access-denied"
	case 32:
		return "sharing-violation"
	default:
		return "lock-violation"
	}
}
func TestWindowsRenamePermanentDenialBounded(t *testing.T) {
	for _, n := range []syscall.Errno{5, 32, 33} {
		t.Run(numericErrno(n), func(t *testing.T) {
			h := &renameRetryHarness{at: time.Unix(0, 0), attempt: func() error { return renameErr(n) }}
			e := h.run(context.Background())
			sum := time.Duration(0)
			for _, d := range h.waits {
				sum += d
			}
			if !errors.Is(e, n) || h.calls != 24 || h.checks != 24 || len(h.waits) != 24 || sum != windowsRenameBudget {
				t.Fatal("permanent denial swallowed or unbounded", e, h.calls, sum)
			}
			for i, d := range h.waits {
				if d <= 0 || d > 100*time.Millisecond {
					t.Fatal("backoff outside approved cap", d)
				}
				if i < 5 && d != 5*time.Millisecond*time.Duration(1<<i) {
					t.Fatal("initial backoff changed", i, d)
				}
			}

		})
	}
	for _, n := range []syscall.Errno{2, 3, 87, 112} {
		h := &renameRetryHarness{at: time.Unix(0, 0), attempt: func() error { return renameErr(n) }}
		if e := h.run(context.Background()); !errors.Is(e, n) || h.calls != 1 || len(h.waits) != 0 {
			t.Fatal("nontransient error retried", n)
		}
	}
}

type renameCallerDeadlineContext struct {
	context.Context
	limit time.Time
}

func (c renameCallerDeadlineContext) Deadline() (time.Time, bool) { return c.limit, true }
func TestWindowsRenameBudgetIncludesChecks(t *testing.T) {
	t.Run("checks-consume-window", func(t *testing.T) {
		h := &renameRetryHarness{at: time.Unix(0, 0), attempt: func() error { return renameErr(5) }}
		h.check = func() error { h.at = h.at.Add(windowsRenameBudget/3 + time.Millisecond); return nil }
		if e := h.run(context.Background()); !errors.Is(e, syscall.Errno(5)) || h.calls != 2 || h.checks != 3 {
			t.Fatal("rename attempted beyond retry window", e, h.calls, h.checks)
		}
	})
	t.Run("no-first-IO-after-budget", func(t *testing.T) {
		h := &renameRetryHarness{at: time.Unix(0, 0), attempt: func() error { return nil }}
		h.check = func() error { h.at = h.at.Add(windowsRenameBudget); return nil }
		if e := h.run(context.Background()); !errors.Is(e, context.DeadlineExceeded) || h.calls != 0 || h.checks != 1 {
			t.Fatal("first rename admitted after budget", e, h.calls)
		}
	})
	t.Run("rename-consumes-window", func(t *testing.T) {
		h := &renameRetryHarness{at: time.Unix(0, 0)}
		h.attempt = func() error { h.at = h.at.Add(windowsRenameBudget); return renameErr(5) }
		if e := h.run(context.Background()); !errors.Is(e, syscall.Errno(5)) || h.calls != 1 || len(h.waits) != 0 {
			t.Fatal("budget excluded IO time", e, h.calls)
		}
	})
	t.Run("shorter-caller-absolute-deadline", func(t *testing.T) {
		start := time.Unix(0, 0)
		ctx := renameCallerDeadlineContext{context.Background(), start.Add(60 * time.Millisecond)}
		h := &renameRetryHarness{at: start, attempt: func() error { return renameErr(5) }}
		if e := h.run(ctx); !errors.Is(e, context.DeadlineExceeded) || h.at.Sub(start) != 60*time.Millisecond || h.calls != 4 || h.checks != 4 || h.waits[len(h.waits)-1] != 25*time.Millisecond {
			t.Fatal("caller deadline/clamped wait not respected", e, h.at.Sub(start), h.calls)
		}
	})
	t.Run("cancel-priority-at-budget", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h := &renameRetryHarness{at: time.Unix(0, 0), attempt: func() error { return nil }}
		h.check = func() error { h.at = h.at.Add(windowsRenameBudget); cancel(); return nil }
		if e := h.run(ctx); !errors.Is(e, context.Canceled) || h.calls != 0 {
			t.Fatal("budget hid caller cancellation", e, h.calls)
		}
	})
}

func TestWindowsRenameCancellationAndCommit(t *testing.T) {
	t.Run("before", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		h := &renameRetryHarness{at: time.Unix(0, 0), attempt: func() error { return nil }}
		if e := h.run(ctx); !errors.Is(e, context.Canceled) || h.calls != 0 {
			t.Fatal("pre-canceled rename")
		}
	})
	t.Run("during-wait", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h := &renameRetryHarness{at: time.Unix(0, 0), attempt: func() error { return renameErr(32) }}
		h.onWait = func() error { cancel(); return ctx.Err() }
		if e := h.run(ctx); !errors.Is(e, context.Canceled) || h.calls != 1 {
			t.Fatal("cancellation published retry")
		}
	})
	t.Run("failed-rename-cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h := &renameRetryHarness{at: time.Unix(0, 0), attempt: func() error { cancel(); return renameErr(5) }}
		if e := h.run(ctx); !errors.Is(e, context.Canceled) || h.calls != 1 || len(h.waits) != 0 {
			t.Fatal("failed rename ignored cancellation")
		}
	})
	t.Run("synchronized-first-denial", func(t *testing.T) {
		base, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := 0
		ctx := &sharingDeniedContext{Context: base, afterDenied: func() {
			if calls != 1 {
				t.Fatal("event not immediately after first denied rename")
			}
			cancel()
		}}
		e := retryWindowsRename(ctx, func() error { return nil }, func() error { calls++; return renameErr(32) }, time.Now, waitWindowsRename)
		if !ctx.observed || !errors.Is(e, context.Canceled) || calls != 1 {
			t.Fatal("denial handshake failed", e, calls)
		}
	})
	t.Run("during-predicate", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h := &renameRetryHarness{at: time.Unix(0, 0), attempt: func() error { return nil }}
		h.check = func() error { cancel(); return nil }
		if e := h.run(ctx); !errors.Is(e, context.Canceled) || h.calls != 0 {
			t.Fatal("predicate cancellation reached rename", e, h.calls)
		}
	})
	t.Run("during-predicate-real-file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "source")
		if e := os.WriteFile(path, []byte("accepted"), 0600); e != nil {
			t.Fatal(e)
		}
		info, e := os.Lstat(path)
		if e != nil {
			t.Fatal(e)
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		e = atomicWriteContext(ctx, path, []byte("candidate"), func() bool { ok := ctx.Err() == nil && matchesSource(path, "accepted", info); cancel(); return ok })
		b, re := os.ReadFile(path)
		if !errors.Is(e, context.Canceled) || re != nil || string(b) != "accepted" {
			t.Fatal("predicate cancellation published source", e)
		}
		left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".kat-write-*"))
		if len(left) != 0 {
			t.Fatal("canceled staging leaked")
		}
	})
	t.Run("after-real-commit", func(t *testing.T) {
		dir := t.TempDir()
		path, tmp := filepath.Join(dir, "source"), filepath.Join(dir, "staging")
		os.WriteFile(path, []byte("accepted"), 0600)
		os.WriteFile(tmp, []byte("candidate"), 0600)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		e := retryWindowsRename(ctx, func() error { return nil }, func() error {
			e := os.Rename(tmp, path)
			if e == nil {
				cancel()
			}
			return e
		}, time.Now, waitWindowsRename)
		b, re := os.ReadFile(path)
		if e != nil || re != nil || string(b) != "candidate" || ctx.Err() == nil {
			t.Fatal("successful commit falsely canceled", e)
		}
	})
	t.Run("after-commit", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h := &renameRetryHarness{at: time.Unix(0, 0), attempt: func() error { cancel(); return nil }}
		if e := h.run(ctx); e != nil || h.calls != 1 {
			t.Fatal("late cancellation falsely rejected committed source")
		}
	})
	t.Run("caller-deadline", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		calls := 0
		e := retryWindowsRename(ctx, func() error { return nil }, func() error { calls++; return renameErr(5) }, time.Now, waitWindowsRename)
		if !errors.Is(e, context.DeadlineExceeded) || calls != 1 {
			t.Fatal("short caller deadline lost", e, calls)
		}
	})
}
func TestWindowsRenameSourceConflictNeverOverwritten(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "content-edit", true: "same-content-replacement"}[replace], func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "source")
			tmp := filepath.Join(dir, "staging")
			os.WriteFile(path, []byte("accepted"), 0600)
			os.WriteFile(tmp, []byte("candidate"), 0600)
			info, _ := os.Lstat(path)
			h := &renameRetryHarness{at: time.Unix(0, 0)}
			h.check = func() error {
				if !matchesSource(path, "accepted", info) {
					return errSourceChanged
				}
				return nil
			}
			h.attempt = func() error {
				if h.calls == 1 {
					return renameErr(5)
				}
				return os.Rename(tmp, path)
			}
			want := "external"
			h.onWait = func() error {
				if replace {
					want = "accepted"
					return atomicWrite(path, []byte(want))
				}
				return os.WriteFile(path, []byte(want), 0600)
			}
			if e := h.run(context.Background()); !errors.Is(e, errSourceChanged) || h.calls != 1 || h.checks != 2 {
				t.Fatal("changed source not rejected", e, h.calls, h.checks)
			}
			b, e := os.ReadFile(path)
			if e != nil || string(b) != want {
				t.Fatal("external source overwritten")
			}
		})
	}
	t.Run("external-edit-after-sixth-denial", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "source")
		if e := os.WriteFile(path, []byte("accepted"), 0600); e != nil {
			t.Fatal(e)
		}
		info, e := os.Lstat(path)
		if e != nil {
			t.Fatal(e)
		}
		h := &renameRetryHarness{at: time.Unix(0, 0), attempt: func() error { return renameErr(5) }}
		h.check = func() error {
			if !matchesSource(path, "accepted", info) {
				return errSourceChanged
			}
			return nil
		}
		h.onWait = func() error {
			if h.calls == 6 {
				return os.WriteFile(path, []byte("external"), 0600)
			}
			return nil
		}
		if e := h.run(context.Background()); !errors.Is(e, errSourceChanged) || h.calls != 6 || h.checks != 7 {
			t.Fatal("late recovery did not recheck source before seventh attempt", e, h.calls, h.checks)
		}
		b, e := os.ReadFile(path)
		if e != nil || string(b) != "external" {
			t.Fatal("late external source overwritten")
		}
	})

}
