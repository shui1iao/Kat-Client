//go:build windows

package elevated

import (
	"context"
	"golang.org/x/sys/windows"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Every OVERLAPPED/buffer/event is cancelled and reaped before returning. Close
// fences new calls, cancels pending calls and waits before closing the HANDLE.
type pipeConn struct {
	h        windows.Handle
	ctx      context.Context
	deadline time.Time
	ops      sync.RWMutex
	closed   atomic.Bool
}

func (p *pipeConn) transfer(b []byte, write bool) (int, error) {
	p.ops.RLock()
	defer p.ops.RUnlock()
	if p.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	if len(b) == 0 {
		return 0, nil
	}
	event, e := windows.CreateEvent(nil, 1, 0, nil)
	if e != nil {
		return 0, e
	}
	defer windows.CloseHandle(event)
	ov := windows.Overlapped{HEvent: event}
	// Windows retains these addresses after ERROR_IO_PENDING. Go syscall
	// uintptr arguments only keep them stable for the syscall itself: ov must
	// not remain on a movable goroutine stack while the kernel owns it.
	var pinned runtime.Pinner
	pinned.Pin(&ov)
	pinned.Pin(&b[0])
	defer pinned.Unpin() // every pending path below first cancels/reaps completion
	var n uint32
	pinned.Pin(&n)
	if write {
		e = windows.WriteFile(p.h, b, &n, &ov)
	} else {
		e = windows.ReadFile(p.h, b, &n, &ov)
	}
	if e == windows.ERROR_IO_PENDING {
		for {
			if p.closed.Load() || p.ctx.Err() != nil || !p.deadline.IsZero() && time.Now().After(p.deadline) {
				_ = windows.CancelIoEx(p.h, &ov)
				_ = windows.GetOverlappedResult(p.h, &ov, &n, true)
				if p.ctx.Err() != nil {
					return 0, p.ctx.Err()
				}
				if p.closed.Load() {
					return 0, io.ErrClosedPipe
				}
				return 0, context.DeadlineExceeded
			}
			state, we := windows.WaitForSingleObject(event, 100)
			if we != nil {
				_ = windows.CancelIoEx(p.h, &ov)
				_ = windows.GetOverlappedResult(p.h, &ov, &n, true)
				return 0, we
			}
			if state == windows.WAIT_OBJECT_0 {
				e = windows.GetOverlappedResult(p.h, &ov, &n, false)
				if e == windows.ERROR_IO_INCOMPLETE {
					// A signaled event is not terminal completion. Never cancel a
					// healthy operation or return this transient status as a read
					// failure. The loop still checks close/context/deadline before
					// its next bounded wait, while all native addresses stay pinned.
					time.Sleep(time.Millisecond)
					continue
				}
				break
			}
			if state != uint32(windows.WAIT_TIMEOUT) {
				_ = windows.CancelIoEx(p.h, &ov)
				_ = windows.GetOverlappedResult(p.h, &ov, &n, true)
				return 0, ErrIdentity
			}
		}
	}
	if e == windows.ERROR_BROKEN_PIPE || e == windows.ERROR_PIPE_NOT_CONNECTED {
		return int(n), io.EOF
	}
	return int(n), e
}
func (p *pipeConn) Read(b []byte) (int, error) {
	n, e := p.transfer(b, false)
	if n == 0 && e == nil && len(b) > 0 {
		e = io.EOF
	}
	return n, e
}
func (p *pipeConn) Write(b []byte) (int, error) {
	written := 0
	for written < len(b) {
		n, e := p.transfer(b[written:], true)
		written += n
		if e != nil {
			return written, e
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}
func (p *pipeConn) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	_ = windows.CancelIoEx(p.h, nil)
	p.ops.Lock()
	defer p.ops.Unlock()
	return windows.CloseHandle(p.h)
}
