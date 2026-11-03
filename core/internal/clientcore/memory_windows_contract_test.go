//go:build windows

package clientcore

import (
	"testing"
	"unsafe"
)

// Compile/run on Windows x64: PROCESS_MEMORY_COUNTERS_EX must match psapi.h.
func TestWindowsOwnPrivateUsageLayout(t *testing.T) {
	var c processMemoryCountersEx
	if unsafe.Sizeof(uintptr(0)) != 8 || unsafe.Sizeof(c) != 80 || unsafe.Offsetof(c.privateUsage) != 72 {
		t.Fatalf("Windows AMD64 memory struct mismatch: size=%d private=%d", unsafe.Sizeof(c), unsafe.Offsetof(c.privateUsage))
	}
	if _, ok := processMemoryBytes(); !ok {
		t.Fatal("K32GetProcessMemoryInfo failed for own process")
	}
}
