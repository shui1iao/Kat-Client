//go:build !windows

package clientcore

import (
	"github.com/shui1iao/Kat/internal/userio"

	"strconv"
	"strings"
)

// processMemoryBytes reports resident set size from /proc when available.
func processMemoryBytes() (uint64, bool) {
	b, err := userio.ReadFile("/proc/self/status")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "VmRSS:" {
			kb, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil {
				return 0, false
			}
			return kb * 1024, true
		}
	}
	return 0, false
}
