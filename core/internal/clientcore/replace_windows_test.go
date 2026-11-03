package clientcore

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Exercise real Windows share-delete denial in t.TempDir. Keep the handle
// held through the first actual rejection; inject cancel/edit BEFORE the
// next check, not in the unpromised comparison-to-rename CAS gap.
func TestAtomicWriteWindowsSharingHandle(t *testing.T) {
	for _, mode := range []string{"transient", "permanent", "cancel", "external-edit"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "source.json")
			if e := os.WriteFile(path, []byte("accepted"), 0600); e != nil {
				t.Fatal(e)
			}
			info, e := os.Lstat(path)
			if e != nil {
				t.Fatal(e)
			}
			p, e := windows.UTF16PtrFromString(path)
			if e != nil {
				t.Fatal(e)
			}
			held, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
			if e != nil {
				t.Fatal(e)
			}
			var closeOnce sync.Once
			closeHeld := func() { closeOnce.Do(func() { windows.CloseHandle(held) }) }
			defer closeHeld()
			// Confirm that this fixture really denies replace before depending on it.
			probe := filepath.Join(dir, "denial-probe")
			if e := os.WriteFile(probe, []byte("probe"), 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.Rename(probe, path); e == nil || !transientWindowsRename(e) {
				t.Fatal("fixture did not establish real delete-denial", e)
			}
			base, cancel := context.WithCancel(context.Background())
			defer cancel()
			var eventErr error
			ctx := &sharingDeniedContext{Context: base}
			ctx.afterDenied = func() {
				if mode == "external-edit" {
					eventErr = os.WriteFile(path, []byte("external"), 0600)
				}
				if mode == "cancel" {
					cancel()
				}
				if mode != "permanent" {
					closeHeld()
				}
			}
			start := time.Now()
			e = atomicWriteContext(ctx, path, []byte("candidate"), func() bool { return ctx.Err() == nil && matchesSource(path, "accepted", info) })
			elapsed := time.Since(start)
			if !ctx.observed {
				t.Fatal("no actual first rename rejection observed", e)
			}
			if eventErr != nil {
				t.Fatal("synchronized synthetic edit failed", eventErr)
			}
			b, re := os.ReadFile(path)
			if re != nil {
				t.Fatal(re)
			}
			switch mode {
			case "transient":
				if e != nil || string(b) != "candidate" {
					t.Fatal("transient held source not replaced", e)
				}
			case "permanent":
				if e == nil || !transientWindowsRename(e) || string(b) != "accepted" || elapsed < windowsRenameBudget || elapsed > windowsRenameBudget+time.Second {
					t.Fatal("permanent denial not bounded/preserved", e, elapsed)
				}
			case "cancel":
				if !errors.Is(e, context.Canceled) || string(b) != "accepted" {
					t.Fatal("pre-next-check cancellation did not retain source", e)
				}
			case "external-edit":
				if !errors.Is(e, errSourceChanged) || string(b) != "external" {
					t.Fatal("pre-next-check external edit not retained", e)
				}
			}
			left, _ := filepath.Glob(filepath.Join(dir, ".kat-write-*"))
			if len(left) != 0 {
				t.Fatal("staging leaked")
			}
			t.Logf("mode=%s real-denial=true synchronized-before-next-check=true", mode)
		})
	}
}
