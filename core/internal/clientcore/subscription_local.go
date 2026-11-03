package clientcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/shui1iao/Kat/internal/clientegress"
	"path/filepath"
	"time"
)

// Metadata points only into an accepted immutable subscription directory. It
// does not grant arbitrary filesystem reads or change the ownership model.
type subscriptionLocal struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	Updated  int64  `json:"updated"`
	Interval int64  `json:"interval"`
}

func (h *Host) subscriptionLocalBytes(old *fullSubscription, url string, limit int64) ([]byte, int64) {
	if old == nil {
		return nil, 0
	}
	v, ok := old.Resources[url]
	if !ok || h.resourceDir(v.Path) == "" || safeCacheDir(filepath.Dir(v.Path)) != nil {
		return nil, 0
	}
	b, e := readSubscriptionResource(v.Path, limit)
	if e != nil {
		return nil, 0
	}
	hash := sha256.Sum256(b)
	if hex.EncodeToString(hash[:]) != v.SHA256 {
		return nil, 0
	}
	return b, v.Updated
}
func (h *Host) subscriptionResource(ctx context.Context, old *fullSubscription, url string, ttl time.Duration, policy *clientegress.Policy, limit int64) ([]byte, int64, error) {
	b, updated := h.subscriptionLocalBytes(old, url, limit)
	if len(b) > 0 && updated > 0 && time.Now().Unix()-updated < int64(ttl/time.Second) {
		return b, updated, nil
	}
	fresh, e := h.fetchSubscriptionResource(ctx, url, policy, limit)
	if e != nil && len(b) > 0 {
		return b, updated, nil
	}
	if e != nil {
		return nil, 0, e
	}
	return fresh, time.Now().Unix(), nil
}
