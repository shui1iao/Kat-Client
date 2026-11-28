package clientcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/userio"
	"io"
	"mime"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var resourceVersionName = regexp.MustCompile(`^subscription-(?:[0-9]+|[0-9a-f]{64})$`)

const acceptedResourceMarker = ".kat-accepted"
const resourceCacheState = "resource-cache-state.json"

type cacheState struct {
	Current  []string `json:"current"`
	Previous []string `json:"previous"`
}

func (h *Host) cacheFailure() {
	h.logs.record(kernel.ClientLogEvent{Time: time.Now(), Level: "warn", Event: "subscription_cache_cleanup_failed", Code: "FILE_IO"})
}
func (h *Host) resourceDir(path string) string {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return ""
	}
	rel, e := filepath.Rel(h.workspace, clean)
	if e != nil {
		return ""
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) < 1 || !resourceVersionName.MatchString(parts[0]) {
		return ""
	}
	return parts[0]
}
func (h *Host) resourceRefs(text string, format DocumentFormat) (map[string]bool, error) {
	if format != FormatJSON {
		b, e := yamlJSON([]byte(text))
		if e != nil {
			return nil, e
		}
		text = string(b)
	}
	var value any
	if e := json.Unmarshal([]byte(text), &value); e != nil {
		return nil, e
	}
	refs := map[string]bool{}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			if dir := h.resourceDir(x); dir != "" {
				refs[dir] = true
			}
		case []any:
			for _, v := range x {
				walk(v)
			}
		case map[string]any:
			for _, v := range x {
				walk(v)
			}
		}
	}
	walk(value)
	return refs, nil
}
func refNames(refs map[string]bool) []string {
	names := []string{}
	for n := range refs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
func sameNames(a, b []string) bool { return strings.Join(a, "\x00") == strings.Join(b, "\x00") }
func safeCacheDir(path string) error {
	st, e := userio.Lstat(path)
	if e != nil {
		return e
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe cache directory")
	}
	return rejectReparse(path)
}
func sameResourceData(dir string, data map[string][]byte) bool {
	if safeCacheDir(dir) != nil {
		return false
	}
	entries, e := userio.ReadDir(dir)
	if e != nil {
		return false
	}
	count := 0
	for _, entry := range entries {
		if entry.Name() == acceptedResourceMarker {
			continue
		}
		wanted, ok := data[entry.Name()]
		if !ok {
			return false
		}
		b, e := readPrivate(filepath.Join(dir, entry.Name()), 96<<20)
		if e != nil || sha256.Sum256(b) != sha256.Sum256(wanted) {
			return false
		}
		count++
	}
	return count == len(data)
}

// Reuse immutable, byte-identical accepted resources. Dir ownership is separate
// from their path: canceling a reused preview must never remove accepted bytes.
func (h *Host) stageResourceVersion(base document, data map[string][]byte) (dir, owned string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.resourceUsing == nil {
		h.resourceUsing = map[string]int{}
	}
	if len(data) == 0 {
		return "", "", nil
	}
	refs, e := h.resourceRefs(base.text, base.format)
	if e != nil {
		return "", "", e
	}
	for _, name := range refNames(refs) {
		p := filepath.Join(h.workspace, name)
		if sameResourceData(p, data) {
			h.resourceUsing[p]++
			return p, "", nil
		}
	}
	names := make([]string, 0, len(data))
	for k := range data {
		names = append(names, k)
	}
	sort.Strings(names)
	hash := sha256.New()
	for _, k := range names {
		sum := sha256.Sum256(data[k])
		hash.Write([]byte(k))
		hash.Write([]byte{0})
		hash.Write(sum[:])
	}
	dir = filepath.Join(h.workspace, "subscription-"+hex.EncodeToString(hash.Sum(nil)))
	if _, e := readPrivate(filepath.Join(dir, acceptedResourceMarker), 128); e == nil && sameResourceData(dir, data) {
		h.resourceUsing[dir]++
		return dir, "", nil
	}
	if _, e := userio.Lstat(dir); e == nil {
		unique := sha256.Sum256(append(hash.Sum(nil), []byte(subscriptionID())...))
		dir = filepath.Join(h.workspace, "subscription-"+hex.EncodeToString(unique[:]))
	}
	if e := userio.Mkdir(dir, 0700); e != nil {
		return "", "", e
	}
	h.resourceUsing[dir]++
	return dir, dir, nil
}

// Called only after successful document/kernel publication, under h.mu. Failures
// are maintenance-only and cannot roll back or change the publication result.
func (h *Host) collectResourceVersionsLocked(previous document, acceptedDir string) {
	current, e := h.resourceRefs(h.doc.text, h.doc.format)
	if e != nil {
		h.cacheFailure()
		return
	}
	before, e := h.resourceRefs(previous.text, previous.format)
	if e != nil {
		h.cacheFailure()
		return
	}
	state := cacheState{}
	p := filepath.Join(h.workspace, resourceCacheState)
	if len(current) == 0 && len(before) == 0 {
		if _, e := userio.Lstat(p); os.IsNotExist(e) {
			return
		}
	}
	if b, e := readPrivate(p, 1<<20); e == nil {
		if json.Unmarshal(b, &state) != nil {
			h.cacheFailure()
			return
		}
	} else if !os.IsNotExist(e) {
		h.cacheFailure()
		return
	}
	next := refNames(current)
	if !sameNames(next, state.Current) {
		state.Previous = refNames(before)
	}
	state.Current = next
	// Only known accepted directories acquire the marker. Legacy directories can
	// be adopted from document references; unproven orphan directories stay intact.
	for n := range current {
		d := filepath.Join(h.workspace, n)
		if safeCacheDir(d) != nil {
			h.cacheFailure()
			return
		}
		m := filepath.Join(d, acceptedResourceMarker)
		if _, e := userio.Lstat(m); os.IsNotExist(e) {
			if exclusiveDocumentWrite(m, []byte("Kat accepted resources\n")) != nil {
				h.cacheFailure()
				return
			}
		}
	}
	if acceptedDir != "" {
		if _, e := readPrivate(filepath.Join(acceptedDir, acceptedResourceMarker), 128); e != nil {
			h.cacheFailure()
			return
		}
	}
	bytes, _ := json.Marshal(state)
	if e := atomicWrite(p, bytes); e != nil {
		h.cacheFailure()
		return
	}
	for _, n := range state.Previous {
		if resourceVersionName.MatchString(n) {
			current[n] = true
		} else {
			h.cacheFailure()
			return
		}
	}
	for _, pending := range h.fullCandidates {
		refs, e := h.resourceRefs(pending.Text, pending.Format)
		if e != nil {
			h.cacheFailure()
			return
		}
		for n := range refs {
			current[n] = true
		}
		if n := h.resourceDir(pending.Dir); n != "" {
			current[n] = true
		}
	}
	for p := range h.resourceUsing {
		if n := h.resourceDir(p); n != "" {
			current[n] = true
		}
	}
	if h.server != nil {
		for _, p := range h.server.SubscriptionResourcePaths() {
			if n := h.resourceDir(p); n != "" {
				current[n] = true
			}
		}
	}
	backupDir := filepath.Join(h.workspace, "backups")
	if _, e := userio.Lstat(backupDir); e == nil {
		if safeCacheDir(backupDir) != nil {
			h.cacheFailure()
			return
		}
		entries, e := userio.ReadDir(backupDir)
		if e != nil {
			h.cacheFailure()
			return
		}
		// Never prune against a partial/unreadable backup set (including an in-flight
		// rotation). Read every retained backup, not just the most recent ten names.
		for _, entry := range entries {
			format, e := formatFromName(entry.Name())
			if e != nil {
				h.cacheFailure()
				return
			}
			b, e := readPrivate(filepath.Join(backupDir, entry.Name()), maxDocument)
			if e != nil {
				h.cacheFailure()
				return
			}
			refs, e := h.resourceRefs(string(b), format)
			if e != nil {
				h.cacheFailure()
				return
			}
			for n := range refs {
				current[n] = true
			}
		}
	} else if !os.IsNotExist(e) {
		h.cacheFailure()
		return
	}
	// The frozen pre-upgrade source is also a rollback root. Ordinary rotating
	// backups must not collect the resources needed by candidate 13's source.
	for _, format := range []DocumentFormat{FormatJSON, FormatYAML, FormatYML} {
		path := filepath.Join(h.workspace, "subscription-v1-before-upgrade."+string(format))
		b, e := readPrivate(path, maxDocument)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			h.cacheFailure()
			return
		}
		refs, e := h.resourceRefs(string(b), format)
		if e != nil {
			h.cacheFailure()
			return
		}
		for n := range refs {
			current[n] = true
		}
	}
	entries, e := userio.ReadDir(h.workspace)
	if e != nil {
		h.cacheFailure()
		return
	}
	for _, entry := range entries {
		n := entry.Name()
		if !resourceVersionName.MatchString(n) || current[n] {
			continue
		}
		dir := filepath.Join(h.workspace, n)
		if safeCacheDir(dir) != nil {
			continue
		}
		if _, e := readPrivate(filepath.Join(dir, acceptedResourceMarker), 128); e != nil {
			continue
		}
		if e := removeResourceVersion(h.workspace, n); e != nil {
			h.cacheFailure()
		}
	}
}
func formatFromName(name string) (DocumentFormat, error) {
	switch filepath.Ext(name) {
	case ".json":
		return FormatJSON, nil
	case ".yaml":
		return FormatYAML, nil
	case ".yml":
		return FormatYML, nil
	}
	return "", errors.New("unknown backup format")
}
func removeResourceVersion(root, name string) error {
	if !resourceVersionName.MatchString(name) {
		return errors.New("not a Kat resource version")
	}
	path := filepath.Join(root, name)
	// Reject every reparse point before deleting anything. OpenRoot then confines
	// deletion even if an entry is swapped after this check; RemoveAll never follows
	// symbolic links. Unknown trees are retained rather than traversed.
	if e := userio.WalkDir(path, func(p string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("cache link")
		}
		return rejectReparse(p)
	}); e != nil {
		return e
	}
	r, e := userio.OpenRoot(root)
	if e != nil {
		return e
	}
	defer r.Close()
	return r.RemoveAll(name)
}

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

// Only native supplies this optional static proxy. It never changes the saved
// route for the main subscription or enters the accepted document.
type resourceProxyKey struct{}
type ResourceAttempt struct {
	Route      string `json:"route"`
	Stage      string `json:"stage"`
	Category   string `json:"category"`
	HTTPStatus int    `json:"http_status,omitempty"`
}
type resourceAttemptsError struct {
	attempts []ResourceAttempt
	first    ResourceAttempt
	last     ResourceAttempt
	cause    error
}

func (e *resourceAttemptsError) Error() string { return "subscription resource routes exhausted" }
func (e *resourceAttemptsError) Unwrap() error { return e.cause }
func resourceRoute(ctx context.Context) string {
	if kernel, _ := ctx.Value(resourceKernelKey{}).(bool); kernel {
		return "kernel_rules"
	}
	if bootstrapFrom(ctx) != nil {
		return "windows_static_http"
	}
	return "direct"
}
func resourceAttempt(ctx context.Context, e error) ResourceAttempt {
	f := safeFailure(ctx, "connect", e).(*downloadFailure)
	return ResourceAttempt{Route: resourceRoute(ctx), Stage: f.stage, Category: f.category, HTTPStatus: f.status}
}
func (h *Host) fetchSubscriptionResource(ctx context.Context, url string, policy *clientegress.Policy, limit int64) ([]byte, error) {
	b, firstErr := h.fetchFull(ctx, url, policy, limit)
	if firstErr == nil {
		return b, nil
	}
	// Never resurrect a canceled preview, replaced egress or shutdown epoch.
	if ctx.Err() != nil || errors.Is(firstErr, context.Canceled) {
		return nil, firstErr
	}
	next := context.WithValue(ctx, resourceKernelKey{}, false)
	if kernel, _ := ctx.Value(resourceKernelKey{}).(bool); !kernel {
		// Stopped: saved route first; optional static HTTP proxy second. A saved
		// system-proxy route must not be redundantly retried as the same route.
		p, _ := ctx.Value(resourceProxyKey{}).(*bootstrapProxy)
		if bootstrapFrom(ctx) != nil || p == nil {
			return nil, firstErr
		}
		next = context.WithValue(next, bootstrapKey{}, p)
	}
	b, lastErr := h.fetchFull(next, url, policy, limit)
	if lastErr == nil {
		return b, nil
	}
	return nil, &resourceAttemptsError{first: resourceAttempt(ctx, firstErr), last: resourceAttempt(next, lastErr), cause: lastErr}
}

type subscriptionHeadersKey struct{}
type subscriptionHeaders struct {
	captured                 bool
	title, disposition       string
	userinfo, updateInterval string
}

func subscriptionName(ctx context.Context, raw string) string {
	clean := func(s string) string {
		s = strings.TrimSpace(s)
		if s == "" || len(s) > 128 || !utf8.ValidString(s) || strings.ContainsFunc(s, unicode.IsControl) {
			return ""
		}
		return s
	}
	if h, ok := ctx.Value(subscriptionHeadersKey{}).(*subscriptionHeaders); ok {
		title := h.title
		if strings.HasPrefix(strings.ToLower(title), "base64:") {
			v := strings.TrimSpace(title[7:])
			for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
				if b, err := e.DecodeString(v); err == nil {
					title = string(b)
					break
				}
			}
		}
		if !strings.HasPrefix(strings.ToLower(h.title), "base64:") {
			for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
				if b, err := e.DecodeString(title); err == nil && clean(string(b)) != "" {
					title = string(b)
					break
				}
			}
		}
		if s := clean(title); s != "" {
			return s
		}
		if _, p, e := mime.ParseMediaType(h.disposition); e == nil {
			if s := clean(path.Base(p["filename"])); s != "" && s != "." {
				return s
			}
		}
	}
	u, e := url.Parse(raw)
	if e != nil {
		return ""
	}
	if s := clean(path.Base(strings.TrimRight(u.Path, "/"))); s != "" && s != "." && s != "/" {
		return s
	}
	return clean(u.Hostname())
}

// An absent/invalid field stays absent, never an invented zero allowance/date.
type subscriptionUserInfo struct {
	Upload   uint64  `json:"upload"`
	Download uint64  `json:"download"`
	Total    *uint64 `json:"total,omitempty"`
	Expire   *int64  `json:"expire,omitempty"`
}

func parseSubscriptionUserInfo(s string) *subscriptionUserInfo {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	values := map[string]uint64{}
	for _, part := range strings.Split(s, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			return nil
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		if key != "upload" && key != "download" && key != "total" && key != "expire" {
			continue
		}
		if _, ok := values[key]; ok {
			return nil
		}
		v, e := strconv.ParseUint(strings.TrimSpace(kv[1]), 10, 53)
		if e != nil {
			return nil
		}
		values[key] = v
	}
	up, u := values["upload"]
	down, d := values["download"]
	if !u || !d || up+down > 1<<53-1 {
		return nil
	}
	info := &subscriptionUserInfo{Upload: up, Download: down}
	if v, ok := values["total"]; ok && v > 0 {
		info.Total = &v
	}
	if v, ok := values["expire"]; ok && v > 0 {
		n := int64(v)
		info.Expire = &n
	}
	return info
}
func parseSubscriptionInterval(s string) int {
	hours, e := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if e != nil || hours == 0 || hours > 720 {
		return 0
	}
	return int(hours) * 3600
}
func captureSubscriptionHeaders(ctx context.Context, header interface{ Get(string) string }) {
	if h, ok := ctx.Value(subscriptionHeadersKey{}).(*subscriptionHeaders); ok && !h.captured {
		h.captured = true
		h.title = header.Get("profile-title")
		h.disposition = header.Get("Content-Disposition")
		h.userinfo = header.Get("subscription-userinfo")
		h.updateInterval = header.Get("profile-update-interval")
	}
}

// Resources may be user-owned/shared paths, even when referenced by editable
// subscription metadata. Reading them must never chmod or rewrite their ACL.
// New subscription caches are protected separately when they are created.
func readSubscriptionResource(path string, limit int64) ([]byte, error) {
	b, _, err := readSubscriptionResourceStat(path, limit)
	return b, err
}

// statSubscriptionResource verifies regular-file, no-symlink/reparse, SameFile,
// and byte-limit invariants without reading file contents onto the Go heap.
func statSubscriptionResource(path string, limit int64) (os.FileInfo, error) {
	if limit <= 0 || limit > 64<<20 {
		return nil, errResourceLimit
	}
	before, err := userio.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, errResourceShape
	}
	f, err := openSubscriptionResource(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || !os.SameFile(before, st) {
		return nil, errResourceShape
	}
	if st.Size() > limit {
		return nil, errResourceLimit
	}
	return st, nil
}

func readSubscriptionResourceStat(path string, limit int64) ([]byte, os.FileInfo, error) {
	if limit <= 0 || limit > 64<<20 {
		return nil, nil, errResourceLimit
	}
	before, err := userio.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, nil, errResourceShape
	}
	// Open the leaf without following a symlink/reparse point. Check the opened
	// file, not only a prior pathname test (a replacement could race with Lstat).
	f, err := openSubscriptionResource(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !st.Mode().IsRegular() || !os.SameFile(before, st) {
		return nil, nil, errResourceShape
	}
	if st.Size() > limit {
		return nil, nil, errResourceLimit
	}
	// Stat is an allocation hint only; the same handle is still read to EOF
	// through the original limit+1 guard, even if the file grows or shrinks.
	hint := st.Size()
	if hint < 0 {
		hint = 0
	}
	buf := bytes.NewBuffer(make([]byte, 0, int(hint)+bytes.MinRead))
	_, err = buf.ReadFrom(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, nil, err
	}
	b := buf.Bytes()
	if int64(len(b)) > limit {
		return nil, nil, errResourceLimit
	}
	// A raced size change may grow or leave a mostly empty hinted buffer.
	// Do not retain that spare allocation in an in-memory database reader.
	if cap(b)-len(b) > bytes.MinRead {
		compact := make([]byte, len(b))
		copy(compact, b)
		b = compact
	}
	return b, st, nil
}
