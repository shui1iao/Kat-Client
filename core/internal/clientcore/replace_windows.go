package clientcore

import (
	"context"
	"errors"
	"github.com/shui1iao/Kat/internal/userio"
	"os"
	"time"
)

func replaceAtomicFile(ctx context.Context, tmp, path string, unchanged []func() bool) error {
	check := func() error {
		if len(unchanged) != 0 && !unchanged[0]() {
			return errSourceChanged
		}
		// Unconditional history writes have no accepted-source predicate, but a
		// raced-in directory/reparse destination must still never be replaced.
		if st, e := userio.Lstat(path); e == nil && (!st.Mode().IsRegular() || rejectReparse(path) != nil) {
			return errors.New("nonregular destination")
		} else if e != nil && !os.IsNotExist(e) {
			return e
		}
		return nil
	}
	return retryWindowsRename(ctx, check, func() error { return userio.Rename(tmp, path) }, time.Now, waitWindowsRename)
}
