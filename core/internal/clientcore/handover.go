package clientcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/elevated"
	"os"
	"path/filepath"
)

// OpenHandover checks the old committed checkpoint AFTER obtaining the unique
// workspace lock, before reading/migrating user state or starting a sampler.
func OpenHandover(workspace string, c elevated.Checkpoint) (*Host, error) {
	if !c.Valid() {
		return nil, fail("handover_checkpoint", "", "Invalid committed checkpoint")
	}
	return openWorkspace(workspace, &c)
}
func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func persistedCheckpoint(workspace, path string) (elevated.Checkpoint, error) {
	source, e := readPrivate(path, maxDocument)
	if e != nil {
		return elevated.Checkpoint{}, e
	}
	history, e := readPrivate(filepath.Join(workspace, "traffic-history.json"), 64<<10)
	if os.IsNotExist(e) {
		history = nil
		e = nil
	}
	if e != nil {
		return elevated.Checkpoint{}, e
	}
	return elevated.Checkpoint{Schema: 1, SourceSHA256: digest(source), HistorySHA256: digest(history)}, nil
}
func checkHandover(workspace string, want elevated.Checkpoint) error {
	c, e := documentCandidates(workspace)
	if e != nil || len(c) != 1 {
		return fail("handover_source", "", "Saved source set changed")
	}
	got, e := persistedCheckpoint(workspace, filepath.Join(workspace, c[0].filename()))
	if e != nil || got != want {
		return fail("handover_checkpoint", "", "Committed source or history changed")
	}
	return nil
}
func (h *Host) prepareHandover(ctx context.Context, params json.RawMessage) (any, *Error) {
	result, e := h.prepareUpdate(ctx, params)
	if e != nil {
		return nil, e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	checkpoint, err := persistedCheckpoint(h.workspace, h.path)
	if err != nil {
		return nil, fail("update_history_failed", "traffic", "Cannot confirm persisted handover checkpoint")
	}
	ack := result.(map[string]any)
	ack["checkpoint"] = checkpoint
	return ack, nil
}
