package clientcore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
	"time"

	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/route"
)

// One current declaration, never a display-name lookup across stored profiles.
type manualResource struct {
	kind, name, path, url string
	declaration           json.RawMessage
	field                 []string
	set                   route.RuleSetOptions
	limit                 int64
	owner                 *fullSubscription
	ownerIndex            int
	snapshotField         []string
	local                 subscriptionLocal
}

func (h *Host) manualResourceLocked(base document, kind, name string) (manualResource, *Error) {
	target := manualResource{kind: kind, name: name, limit: 64 << 20}
	root, err := sourceJSON(base)
	if err != nil {
		return target, fail("resource_refresh_failed", "source", "Cannot read accepted source")
	}
	k := rawObject(root["kernel"])
	if kind == "rule_set" {
		target.limit = 16 << 20
		for i, b := range rawArray(k, "rule_sets") {
			if rawName(b) == name {
				target.declaration = b
				target.field = []string{"kernel", "rule_sets", strconv.Itoa(i), "path"}
				break
			}
		}
		if len(target.declaration) > 0 {
			if json.Unmarshal(target.declaration, &target.set) != nil {
				return target, fail("invalid_params", "params", "Invalid resource")
			}
			target.path = target.set.Path
			target.url = target.set.URL
			if target.set.MaxBytes > 0 {
				target.limit = int64(target.set.MaxBytes)
			}
		}
	} else if name == kind {
		target.declaration = k[kind]
		target.field = []string{"kernel", kind, "path"}
		var option route.GeoIPOptions
		if json.Unmarshal(target.declaration, &option) == nil {
			target.path = option.Path
			target.url = option.URL
			if option.MaxBytes > 0 {
				target.limit = int64(option.MaxBytes)
			}
		}
	}
	if target.path == "" || target.limit <= 0 || target.limit > 64<<20 {
		return target, fail("unsupported", "params", "No configured file or remote resource")
	}
	// Explicit remote declarations retain their original via/downloader semantics.
	if target.url != "" {
		return target, nil
	}
	subs, err := subscriptionsOf(root)
	if err != nil {
		return target, fail("resource_source_changed", "subscriptions", "Resource provenance is not reliable")
	}
	for si := range subs {
		sub := &subs[si]
		if !subActive(*sub) {
			continue
		}
		var snapshot json.RawMessage
		var field []string
		if kind == "rule_set" {
			for ri, b := range sub.Snapshot.RuleSets {
				if rawName(b) == name && sameJSON(b, target.declaration) {
					snapshot = b
					field = []string{"subscriptions", strconv.Itoa(si), "snapshot", "rule_sets", strconv.Itoa(ri), "path"}
					break
				}
			}
		} else {
			if kind == "geoip" {
				snapshot = sub.Snapshot.GeoIP
			} else {
				snapshot = sub.Snapshot.ASN
			}
			field = []string{"subscriptions", strconv.Itoa(si), "snapshot", kind, "path"}
		}
		if len(snapshot) == 0 || !sameJSON(snapshot, target.declaration) {
			continue
		}
		for url, meta := range sub.Resources {
			if meta.Path != target.path {
				continue
			}
			// Editable provenance can authorize a download, never writing its path.
			// Only accepted workspace cache leaves qualify; all writes use a NEW version.
			dir := h.resourceDir(meta.Path)
			if dir == "" || filepath.Dir(meta.Path) != filepath.Join(h.workspace, dir) || safeCacheDir(filepath.Dir(meta.Path)) != nil || !validImportURL(url) {
				return target, fail("resource_source_changed", "params", "Resource provenance no longer matches the accepted cache")
			}
			b, err := readSubscriptionResource(meta.Path, target.limit)
			sum := sha256.Sum256(b)
			if err != nil || hex.EncodeToString(sum[:]) != meta.SHA256 {
				return target, fail("resource_source_changed", "params", "Resource cache changed; previous runtime retained")
			}
			if target.owner != nil {
				return target, fail("resource_source_changed", "params", "Ambiguous resource provenance")
			}
			target.owner = sub
			target.ownerIndex = si
			target.snapshotField = field
			target.local = meta
			target.url = url
		}
	}
	return target, nil
}

func validateManualResource(base document, target manualResource, b []byte) error {
	if int64(len(b)) > target.limit {
		return errResourceLimit
	}
	switch target.kind {
	case "rule_set":
		_, err := route.ValidateSubscriptionSetWithDependencies(target.set, b, route.SubscriptionSetDependencies{GeoIP: base.config.GeoIP != nil, ASN: base.config.ASN != nil, Geosite: base.config.Geosite != nil})
		return err
	case "geoip", "asn":
		return validateSubscriptionDB(target.kind, b)
	}
	return errors.New("unknown resource kind")
}

func (h *Host) refreshDownloadedResource(ctx context.Context, base document, s *kernel.Server, generation uint64, policy *clientegress.Policy, target manualResource) (any, *Error) {
	// The existing resource downloader owns bounded HTTP, registered-origin SOCKS,
	// public-address checks, cancellation, redirects, physical egress and fallback.
	var b []byte
	var err error
	if target.owner == nil {
		// Independent remote resources retain the engine's exact URL/via/TLS/limits.
		b, err = s.DownloadResource(ctx, target.kind, target.name, generation)
	} else {
		ctx = context.WithValue(ctx, resourceKernelKey{}, target.owner.DownloadMode != "direct")
		ctx = context.WithValue(ctx, subscriptionHeadersKey{}, &subscriptionHeaders{})
		if target.owner.SourceOptions != nil {
			ctx = context.WithValue(ctx, legacyKey{}, &legacyConversion{Config: *target.owner.SourceOptions})
		}
		if target.owner.DownloadMode == "proxy" {
			b, err = h.fetchFull(ctx, target.url, policy, target.limit)
		} else {
			b, err = h.fetchSubscriptionResource(ctx, target.url, policy, target.limit)
		}
	}
	if err != nil {
		return nil, resourceError(ctx, target.kind, 0, "download", "connect", "unknown", err)
	}
	if ctx.Err() != nil {
		return nil, requestCanceled()
	}
	if err = validateManualResource(base, target, b); err != nil {
		return nil, resourceError(ctx, target.kind, 0, "download", "format_check", "invalid_format", nil)
	}
	// Only the requested bytes enter this private resource-specific version. No node,
	// profile or other resource is fetched or copied, including shared paths.
	// A unique leaf prevents independent remote timers from ever sharing an
	// immutable subscription cache or other writable download caches.
	file := "resource-" + subscriptionID()
	dir, owned, err := h.stageResourceVersion(base, map[string][]byte{file: b})
	if err != nil {
		return nil, fail("resource_refresh_failed", "params", "Cannot stage resource; previous data retained")
	}
	keep := false
	defer func() {
		h.mu.Lock()
		h.resourceUsing[dir]--
		if h.resourceUsing[dir] <= 0 {
			delete(h.resourceUsing, dir)
		}
		h.mu.Unlock()
		if !keep && owned != "" {
			_ = removeResourceVersion(h.workspace, filepath.Base(owned))
		}
	}()
	if owned != "" {
		if err = secureWorkspace(dir); err == nil {
			err = exclusiveDocumentWrite(filepath.Join(dir, file), b)
		}
		if err != nil {
			return nil, fail("resource_refresh_failed", "params", "Cannot save staged resource; previous data retained")
		}
	}
	path := filepath.Join(dir, file)
	sum := sha256.Sum256(b)
	updated := time.Now().Unix()
	changes := []resourceScalarPatch{{target.field, target.path, path}}
	if target.owner != nil {
		prefix := []string{"subscriptions", strconv.Itoa(target.ownerIndex), "resources", target.url}
		leaf := func(key string) []string { return append(append([]string{}, prefix...), key) }
		changes = append(changes, resourceScalarPatch{target.snapshotField, target.path, path},
			resourceScalarPatch{leaf("path"), target.local.Path, path}, resourceScalarPatch{leaf("sha256"), target.local.SHA256, hex.EncodeToString(sum[:])}, resourceScalarPatch{leaf("updated"), target.local.Updated, updated})
	}
	text, err := patchResourceSource(base, changes)
	if err != nil {
		return nil, fail("resource_source_changed", "source", "Cannot safely patch exact resource fields; source retained")
	}
	d, de := parseDocument(text, h.workspace, base.format)
	if de != nil {
		return nil, de
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if ctx.Err() != nil {
		return nil, requestCanceled()
	}
	if h.server != s || h.doc.text != base.text || h.doc.format != base.format || s.GenerationID() != generation {
		return nil, fail("resource_source_changed", "params", "Configuration changed; resource result discarded")
	}
	// Source save/check/rollback and kernel generation commit are the same
	// transaction primitives as document.apply, without import/overlay rewriting.
	tx, de := h.saveDocumentContextLocked(ctx, d)
	if de != nil {
		return nil, de
	}
	rollback := func(failure *Error) (any, *Error) {
		if tx.rollback() != nil {
			return nil, fail("rollback_failed", "source", "Cannot restore resource metadata; backup retained")
		}
		return nil, failure
	}
	if de = tx.checkPublished(); de != nil {
		return rollback(de)
	}
	if _, err = s.ApplyResourceConfigContext(ctx, h.runtimeConfig(d.config), target.kind, target.name, generation); err != nil {
		if ctx.Err() != nil {
			return rollback(requestCanceled())
		}
		return rollback(fail("resource_refresh_failed", "params", "Resource preparation failed; previous source and runtime retained"))
	}
	// A committed generation is accepted even on late caller cancellation.
	tx.accept()
	previous := h.doc
	h.doc = d
	keep = true
	h.resetManualLocked()
	h.collectResourceVersionsLocked(previous, dir)
	return map[string]any{"kind": target.kind, "name": target.name, "state": "ok", "action": "downloaded", "source_changed": true}, nil
}
