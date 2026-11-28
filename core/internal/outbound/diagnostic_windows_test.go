//go:build windows

package outbound

import (
	"fmt"
	"syscall"
	"testing"
)

func TestCategoryBareWSAETIMEDOUTWindows(t *testing.T) {
	const wsaeTimedOut = syscall.Errno(10060) // WSAETIMEDOUT
	bareCat, bareNat := Category(wsaeTimedOut)
	wrapCat, wrapNat := Category(fmt.Errorf("winsock: %w", wsaeTimedOut))
	if bareCat != "timeout" || wrapCat != "timeout" {
		t.Fatalf("WSAETIMEDOUT category mismatch: bare=%q wrapped=%q", bareCat, wrapCat)
	}
	if bareNat == nil || wrapNat == nil || *bareNat != 10060 || *wrapNat != 10060 {
		t.Fatalf("WSAETIMEDOUT native mismatch: bare=%v wrapped=%v", bareNat, wrapNat)
	}
}
