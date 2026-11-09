package clientcore

import (
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/userio"
	"os"
	"path/filepath"
	"time"
)

// prepareUpdate is reachable only through the native host's private stdio
// method. Serve drains all previously accepted requests and then freezes wire
// admission until host.resume-update. Nothing here starts probes or networking,
// serializes a new source, changes selections, or changes history accounting.
func (h *Host) prepareUpdate(ctx context.Context, params json.RawMessage) (any, *Error) {
	if e := decodeParams(params, &struct{}{}); e != nil {
		return nil, e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.updatePrepared = false
	if ctx.Err() != nil {
		return nil, requestCanceled()
	}
	if e := h.checkSourceLocked(); e != nil {
		return nil, fail("update_source_failed", "text", "Cannot confirm accepted source for update")
	}
	// Stop's final sample uses exactly the existing TrafficTotals/history path.
	// A failed sample save remains dirty, and the explicit save below must pass.
	drainErr := h.stopWithDrainLocked(150*time.Millisecond, true)
	sourceErr := h.syncUpdateSourceLocked()
	historyErr := h.saveHistory()
	if historyErr == nil {
		historyErr = h.syncUpdateHistoryLocked()
	}
	if drainErr != nil {
		return nil, fail("update_drain_failed", "runtime", "Core did not drain cleanly for update")
	}
	if sourceErr != nil {
		return nil, sourceErr
	}
	if historyErr != nil {
		return nil, fail("update_history_failed", "traffic", "Cannot persist traffic history for update")
	}
	if ctx.Err() != nil {
		return nil, requestCanceled()
	}
	h.updatePrepared = true
	return map[string]any{"prepared": true, "source_saved": true, "history_saved": true}, nil
}

func (h *Host) syncUpdateSourceLocked() *Error {
	// O_RDWR is required for FlushFileBuffers on Windows; bytes are never written.
	f, err := userio.OpenFile(h.path, os.O_RDWR, 0)
	if err != nil {
		return fail("update_source_failed", "text", "Cannot flush accepted source for update")
	}
	st, err := f.Stat()
	if err == nil && (h.sourceInfo == nil || !os.SameFile(st, h.sourceInfo) || !st.Mode().IsRegular()) {
		err = errSourceChanged
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil || ce != nil || h.checkSourceLocked() != nil {
		return fail("update_source_failed", "text", "Cannot flush accepted source for update")
	}
	return nil
}

// Resuming admission does not restart the runtime or restore network intent.
// The native lifecycle owner must do that only after this acknowledgement.
func (h *Host) resumeUpdate(params json.RawMessage) (any, *Error) {
	if e := decodeParams(params, &struct{}{}); e != nil {
		return nil, e
	}
	h.mu.Lock()
	h.updatePrepared = false
	h.mu.Unlock()
	return map[string]any{"resumed": true}, nil
}

func (h *Host) syncUpdateHistoryLocked() error {
	p := filepath.Join(h.workspace, "traffic-history.json")
	f, err := userio.OpenFile(p, os.O_RDWR, 0)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err == nil && !st.Mode().IsRegular() {
		err = os.ErrInvalid
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	return ce
}
