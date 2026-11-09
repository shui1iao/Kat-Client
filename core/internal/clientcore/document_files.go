package clientcore

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/userio"
	"os"
	"path/filepath"
	"strings"
)

var errSourceChanged = errors.New("saved source changed")

var documentFormats = []DocumentFormat{FormatJSON, FormatYAML, FormatYML}

// Lstat includes dangling links, directories and reparse destinations as
// candidates. Never resolve a conflict by extension priority or readability.
func documentCandidates(workspace string) ([]DocumentFormat, error) {
	var found []DocumentFormat
	for _, f := range documentFormats {
		if _, err := userio.Lstat(filepath.Join(workspace, f.filename())); err == nil {
			found = append(found, f)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	return found, nil
}
func candidateConflict(found []DocumentFormat) *Error {
	names := make([]string, len(found))
	for i, f := range found {
		names[i] = f.filename()
	}
	return fail("configuration_conflict", "", strings.Join(names, ", "))
}

// Publish a completed private file without replacing ANY destination. Link is
// atomic and no-replace on both Windows/NTFS and Unix; unlike Rename it cannot
// overwrite a destination created after the initial candidate check.
func exclusiveDocumentWrite(path string, b []byte) error {
	return exclusiveDocumentWriteContext(context.Background(), path, b)
}
func exclusiveDocumentWriteContext(ctx context.Context, path string, b []byte) error {
	f, err := userio.CreateTemp(filepath.Dir(path), ".kat-write-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer userio.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		err = userio.Link(tmp, path)
	}
	return err
}

func matchesSource(path, text string, info os.FileInfo) bool {
	st, err := userio.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || info == nil || !os.SameFile(st, info) || st.Size() != info.Size() || !st.ModTime().Equal(info.ModTime()) {
		return false
	}
	b, err := readPrivate(path, maxDocument)
	if err != nil || string(b) != text {
		return false
	}
	after, err := userio.Lstat(path)
	return err == nil && os.SameFile(st, after) && st.Size() == after.Size() && st.ModTime().Equal(after.ModTime())
}
func (h *Host) checkSourceLocked() *Error {
	found, err := documentCandidates(h.workspace)
	if err != nil {
		return fail("read_failed", "text", "Cannot inspect client document candidates")
	}
	if len(found) > 1 {
		return candidateConflict(found)
	}
	if len(found) != 1 || found[0] != h.doc.format || !matchesSource(h.path, h.doc.text, h.sourceInfo) {
		return fail("document_changed", "text", "Saved document changed externally; reopen before applying")
	}
	return nil
}

// All fallible file mutations precede kernel ApplyConfig. The kernel already
// atomically retains its old generation on failure. Keep the old accepted
// source in a private temporary recovery copy; never serialize projections.
type documentSave struct {
	h          *Host
	next       document
	target     string
	targetInfo os.FileInfo
	backup     string
	changed    bool
	converted  bool
	removed    bool
}

func (h *Host) saveDocumentLocked(d document) (*documentSave, *Error) {
	return h.saveDocumentContextLocked(context.Background(), d)
}
func (h *Host) saveDocumentContextLocked(ctx context.Context, d document) (*documentSave, *Error) {
	if ctx.Err() != nil {
		return nil, requestCanceled()
	}
	if e := h.checkSourceLocked(); e != nil {
		return nil, e
	}
	tx := &documentSave{h: h, next: d, target: filepath.Join(h.workspace, d.format.filename()), converted: d.format != h.doc.format}
	if !tx.converted && d.text == h.doc.text {
		tx.targetInfo = h.sourceInfo
		return tx, nil
	}
	// A copy (not a hard link) isolates the backup from outside in-place writes.
	f, err := userio.CreateTemp(h.workspace, ".kat-conversion-backup-*."+string(h.doc.format))
	if err != nil {
		return nil, fail("save_failed", "text", "Cannot back up accepted source; file and runtime unchanged")
	}
	tx.backup = f.Name()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write([]byte(h.doc.text))
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		userio.Remove(tx.backup)
		return nil, fail("save_failed", "text", "Cannot back up accepted source; file and runtime unchanged")
	}
	if e := h.checkSourceLocked(); e != nil {
		userio.Remove(tx.backup)
		return nil, e
	}
	if tx.converted {
		err = exclusiveDocumentWriteContext(ctx, tx.target, []byte(d.text))
	} else {
		err = atomicWriteContext(ctx, tx.target, []byte(d.text), func() bool { return ctx.Err() == nil && matchesSource(h.path, h.doc.text, h.sourceInfo) })
	}
	if err != nil {
		userio.Remove(tx.backup)
		if ctx.Err() != nil {
			return nil, requestCanceled()
		}
		// A raced-in conversion destination must remain untouched.
		if found, e := documentCandidates(h.workspace); e == nil && len(found) > 1 {
			return nil, candidateConflict(found)
		}
		if errors.Is(err, errSourceChanged) {
			return nil, fail("document_changed", "text", "Saved document changed externally; previous runtime retained")
		}
		return nil, fail("save_failed", "text", "Cannot save document; runtime unchanged")
	}
	tx.changed = true
	tx.targetInfo, err = userio.Lstat(tx.target)
	if err == nil && !matchesSource(tx.target, d.text, tx.targetInfo) {
		err = errors.New("destination changed")
	}
	if err == nil && tx.converted {
		if !matchesSource(h.path, h.doc.text, h.sourceInfo) {
			err = errors.New("source changed")
		} else {
			err = userio.Remove(h.path)
			tx.removed = err == nil
		}
	}
	if err != nil {
		if tx.rollback() != nil {
			return nil, fail("rollback_failed", "text", "Runtime retained; cannot restore accepted source")
		}
		return nil, fail("save_failed", "text", "Cannot save document; previous file and runtime retained")
	}
	return tx, nil
}
func (tx *documentSave) checkPublished() *Error {
	found, err := documentCandidates(tx.h.workspace)
	if err != nil {
		return fail("read_failed", "text", "Cannot inspect saved document")
	}
	if len(found) > 1 {
		return candidateConflict(found)
	}
	if len(found) != 1 || found[0] != tx.next.format || !matchesSource(tx.target, tx.next.text, tx.targetInfo) {
		return fail("document_changed", "text", "Saved document changed externally; previous runtime retained")
	}
	return nil
}
func (tx *documentSave) rollback() error {
	h := tx.h
	if !tx.changed {
		return nil
	}
	if tx.converted {
		if tx.removed {
			if err := exclusiveDocumentWrite(h.path, []byte(h.doc.text)); err != nil {
				return err
			}
			var err error
			h.sourceInfo, err = userio.Lstat(h.path)
			if err != nil {
				return err
			}
		} else if !matchesSource(h.path, h.doc.text, h.sourceInfo) {
			return errors.New("source changed")
		}
		if !matchesSource(tx.target, tx.next.text, tx.targetInfo) {
			return errors.New("target changed")
		}
		if err := userio.Remove(tx.target); err != nil {
			return err
		}
	} else {
		if !matchesSource(h.path, tx.next.text, tx.targetInfo) {
			return errors.New("source changed")
		}
		if err := atomicWrite(h.path, []byte(h.doc.text), func() bool { return matchesSource(h.path, tx.next.text, tx.targetInfo) }); err != nil {
			return err
		}
		var err error
		h.sourceInfo, err = userio.Lstat(h.path)
		if err != nil {
			return err
		}
	}
	_ = userio.Remove(tx.backup)
	return nil
}
func (tx *documentSave) accept() {
	tx.h.path, tx.h.sourceInfo = tx.target, tx.targetInfo
	// This is transaction recovery material, not a second backup collection.
	// Only an unsuccessful rollback retains it for manual recovery. The core
	// remains independent of the native host's bounded user-visible backups.
	if tx.changed {
		_ = userio.Remove(tx.backup)
	}
}
