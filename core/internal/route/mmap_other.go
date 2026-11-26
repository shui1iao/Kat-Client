//go:build !unix && !windows

package route

import "os"

type mmapRegion struct {
	data []byte
}

func mapReadOnlyFile(*os.File, int64) (*mmapRegion, error) {
	return nil, os.ErrInvalid
}

func (m *mmapRegion) bytes() []byte {
	if m == nil {
		return nil
	}
	return m.data
}

func cleanupMmapRegion(*mmapRegion) {}
