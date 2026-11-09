//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package stats

import (
	"errors"
	"github.com/shui1iao/Kat/internal/userio"
	"os"
	"path/filepath"
	"syscall"
)

// ErrLocked: another running Kat instance owns this statistics file.
var ErrLocked = errors.New("stats: statistics file is used by another instance")

// Lock takes an exclusive advisory lock on path+".lock" so that two
// instances never persist into the same file. Release unlocks and closes.
func Lock(path string) (release func(), err error) {
	if e := userio.MkdirAll(filepath.Dir(path), 0o700); e != nil {
		return nil, e
	}
	f, e := userio.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if e != nil {
		return nil, e
	}
	if e := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		if errors.Is(e, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, e
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

func syncDir(dir string) {
	if d, e := userio.Open(dir); e == nil {
		_ = d.Sync()
		d.Close()
	}
}
