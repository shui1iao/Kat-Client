//go:build windows

package clientcore

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// processMemoryCountersEx mirrors PROCESS_MEMORY_COUNTERS_EX (psapi.h).
type processMemoryCountersEx struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
	privateUsage               uintptr
}

var procGetProcessMemoryInfo = windows.NewLazySystemDLL("kernel32.dll").NewProc("K32GetProcessMemoryInfo")

// processMemoryBytes reports this core process private bytes, the figure closest
// to Task Manager memory for a Go process. ok=false when the API is unavailable.
func processMemoryBytes() (uint64, bool) {
	if procGetProcessMemoryInfo.Find() != nil {
		return 0, false
	}
	var c processMemoryCountersEx
	c.cb = uint32(unsafe.Sizeof(c))
	r, _, _ := procGetProcessMemoryInfo.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&c)), uintptr(c.cb))
	if r == 0 {
		return 0, false
	}
	return uint64(c.privateUsage), true
}
