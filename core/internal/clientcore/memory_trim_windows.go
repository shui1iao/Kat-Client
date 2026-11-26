//go:build windows

package clientcore

import (
	"golang.org/x/sys/windows"
	"syscall"
)

var setProcessWorkingSetSizeEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetProcessWorkingSetSizeEx")

// trimOSWorkingSet asks Windows to gently reclaim cold pages from the working
// set during idle memory trims without forcing active pages out.
func trimOSWorkingSet() {
	if setProcessWorkingSetSizeEx.Find() != nil {
		return
	}
	h := windows.CurrentProcess()
	minusOne := ^uintptr(0)
	_, _, _ = syscall.SyscallN(setProcessWorkingSetSizeEx.Addr(), uintptr(h), minusOne, minusOne, 0)
}
