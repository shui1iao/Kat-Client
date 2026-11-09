package clientcore

import (
	"bytes"
	"github.com/shui1iao/Kat/internal/userio"
	"io"
	"os"
)

// Resources may be user-owned/shared paths, even when referenced by editable
// subscription metadata. Reading them must never chmod or rewrite their ACL.
// New subscription caches are protected separately when they are created.
func readSubscriptionResource(path string, limit int64) ([]byte, error) {
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
	// Open the leaf without following a symlink/reparse point. Check the opened
	// file, not only a prior pathname test (a replacement could race with Lstat).
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
	// Stat is an allocation hint only; the same handle is still read to EOF
	// through the original limit+1 guard, even if the file grows or shrinks.
	hint := st.Size()
	if hint < 0 {
		hint = 0
	}
	buf := bytes.NewBuffer(make([]byte, 0, int(hint)+bytes.MinRead))
	_, err = buf.ReadFrom(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	b := buf.Bytes()
	if int64(len(b)) > limit {
		return nil, errResourceLimit
	}
	// A raced size change may grow or leave a mostly empty hinted buffer.
	// Do not retain that spare allocation in an in-memory database reader.
	if cap(b)-len(b) > bytes.MinRead {
		compact := make([]byte, len(b))
		copy(compact, b)
		b = compact
	}
	return b, nil
}
