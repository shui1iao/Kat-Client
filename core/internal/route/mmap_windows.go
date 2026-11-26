//go:build windows

package route

import (
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type mmapRegion struct {
	mu      sync.Mutex
	mapping windows.Handle
	addr    uintptr
	data    []byte
}

func mapReadOnlyFile(f *os.File, size int64) (*mmapRegion, error) {
	if size <= 0 {
		return nil, os.ErrInvalid
	}
	h, err := windows.CreateFileMapping(windows.Handle(f.Fd()), nil, windows.PAGE_READONLY, uint32(uint64(size)>>32), uint32(size), nil)
	if err != nil {
		return nil, err
	}
	addr, err := windows.MapViewOfFile(h, windows.FILE_MAP_READ, 0, 0, uintptr(size))
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	// Build slice view safely via unsafe.Slice from pointer returned by OS mapping.
	// Use reflect-free pointer conversion only on valid OS-allocated mapping base.
	var p *byte
	*(*uintptr)(unsafe.Pointer(&p)) = addr
	data := unsafe.Slice(p, int(size))
	return &mmapRegion{mapping: h, addr: addr, data: data}, nil
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
	addr := m.addr
	h := m.mapping
	m.addr = 0
	m.mapping = 0
	m.data = nil
	m.mu.Unlock()
	if addr != 0 {
		_ = windows.UnmapViewOfFile(addr)
	}
	if h != 0 {
		_ = windows.CloseHandle(h)
	}
}
