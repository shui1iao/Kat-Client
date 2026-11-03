//go:build !windows

package clientcore

import (
	"context"
	"os"
)

// Keep the pre-existing single-rename semantics on non-Windows platforms.
func replaceAtomicFile(ctx context.Context, tmp, path string, unchanged []func() bool) error {
	if len(unchanged) != 0 && !unchanged[0]() {
		return errSourceChanged
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
