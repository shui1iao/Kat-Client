//go:build unix

package route

import (
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

type mmapRegion struct {
	mu   sync.Mutex
	data []byte
}

func mapReadOnlyFile(f *os.File, size int64) (*mmapRegion, error) {
	if size <= 0 {
		return nil, os.ErrInvalid
	}
	b, err := unix.Mmap(int(f.Fd()), 0, int(size), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	return &mmapRegion{data: b}, nil
}

func (m *mmapRegion) bytes() []byte {
	if m == nil {
		return nil
	}
	return m.data
}

func cleanupMmapRegion(m *mmapRegion) {
	if m == nil {
		return
	}
	m.mu.Lock()
	b := m.data
	m.data = nil
	m.mu.Unlock()
	if b != nil {
		_ = unix.Munmap(b)
	}
}
