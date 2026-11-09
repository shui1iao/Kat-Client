package clientcore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/userio"
	"os"
	"path/filepath"
)

type ipPolicyKey struct{}

func ipDisabled(ctx context.Context) bool { v, _ := ctx.Value(ipPolicyKey{}).(bool); return v }
func ipNetwork(ctx context.Context) string {
	if ipDisabled(ctx) {
		return "ip4"
	}
	return "ip"
}
func (h *Host) setIPPolicy(disabled bool) {
	h.ipMu.Lock()
	defer h.ipMu.Unlock()
	if h.ipLife != nil && h.ipDisabled == disabled {
		return
	}
	if h.ipCancel != nil {
		h.ipCancel()
	}
	h.ipDisabled = disabled
	h.ipLife, h.ipCancel = context.WithCancel(context.Background())
}
func (h *Host) ipContext(parent context.Context) (context.Context, func()) {
	h.ipMu.Lock()
	defer h.ipMu.Unlock()
	if h.ipLife == nil {
		h.ipLife, h.ipCancel = context.WithCancel(context.Background())
	}
	ctx, cancel := context.WithCancel(context.WithValue(parent, ipPolicyKey{}, h.ipDisabled))
	stop := context.AfterFunc(h.ipLife, cancel)
	return ctx, func() { stop(); cancel() }
}

// The c16 user decision intentionally changes the accepted desktop default.
// This one-time private marker is outside rotating snapshots. It is published
// only after the normal durable document transaction, so a failed migration
// never marks itself complete. The exact old source is kept for rollback.
func (h *Host) migrateIPv6() error {
	marker := filepath.Join(h.workspace, "c16-network-migration.json")
	if _, e := userio.Lstat(marker); e == nil {
		b, e := readPrivate(marker, 4096)
		var report struct {
			Version int      `json:"version"`
			Entries []string `json:"entries"`
		}
		if e != nil || json.Unmarshal(b, &report) != nil || report.Version != 1 {
			return errors.New("invalid network migration report")
		}
		return nil
	} else if !os.IsNotExist(e) {
		return e
	}
	backup := filepath.Join(h.workspace, "client-before-c16-network."+string(h.doc.format))
	if _, e := userio.Lstat(backup); os.IsNotExist(e) {
		if e = exclusiveDocumentWrite(backup, []byte(h.doc.text)); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	root, e := sourceJSON(h.doc)
	if e != nil {
		return e
	}
	var client map[string]json.RawMessage
	if json.Unmarshal(root["client"], &client) != nil {
		return errors.New("invalid migration source")
	}
	if string(client["ipv6"]) != "false" {
		client["ipv6"] = rawJSON(false)
		root["client"] = rawJSON(client)
		text, e := renderSubscriptionSource(h.doc, root)
		if e != nil {
			return e
		}
		if _, e := h.Apply(text, h.doc.format); e != nil {
			return e
		}
	}
	return exclusiveDocumentWrite(marker, []byte("{\"version\":1,\"entries\":[\"client.ipv6=false: c16 upgrade default applied\"]}\n"))
}
