//go:build !(linux || darwin || freebsd || openbsd || netbsd || dragonfly)

package stats

import (
	"errors"
	"github.com/shui1iao/Kat/internal/userio"
	"os"
	"path/filepath"
)

// ErrLocked: another running Kat instance owns this statistics file.
var ErrLocked = errors.New("stats: statistics file is used by another instance")

// Lock creates the lock file exclusively while the instance runs. A lock file
// left by a crashed process is taken over when it can be removed (Windows
// refuses removal while the owning process keeps it open).
func Lock(path string) (release func(), err error) {
	if e := userio.MkdirAll(filepath.Dir(path), 0o700); e != nil {
		return nil, e
	}
	name := path + ".lock"
	f, e := userio.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if errors.Is(e, os.ErrExist) {
		if userio.Remove(name) != nil {
			return nil, ErrLocked
		}
		f, e = userio.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	}
	if e != nil {
		return nil, ErrLocked
	}
	return func() { f.Close(); userio.Remove(name) }, nil
}

func syncDir(string) {}
