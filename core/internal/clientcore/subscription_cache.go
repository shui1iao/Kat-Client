package clientcore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/userio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/shui1iao/Kat/internal/kernel"
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
