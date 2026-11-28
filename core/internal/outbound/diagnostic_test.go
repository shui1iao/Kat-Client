package outbound

import (
	"context"
	"fmt"
	"syscall"
	"testing"
)

func TestCategoryBareAndWrappedErrnoConsistency(t *testing.T) {
	bareCat, bareNat := Category(syscall.ETIMEDOUT)
	wrapCat, wrapNat := Category(fmt.Errorf("connect failed: %w", syscall.ETIMEDOUT))
	if bareCat != "timeout" || wrapCat != "timeout" {
		t.Fatalf("ETIMEDOUT category mismatch: bare=%q wrapped=%q, want both timeout", bareCat, wrapCat)
	}
	if bareNat == nil || wrapNat == nil || *bareNat != uint32(syscall.ETIMEDOUT) || *wrapNat != *bareNat {
		t.Fatalf("ETIMEDOUT native code mismatch: bare=%v wrapped=%v", bareNat, wrapNat)
	}

	refCat, refNat := Category(syscall.ECONNREFUSED)
	if refCat != "os_error" || refNat == nil || *refNat != uint32(syscall.ECONNREFUSED) {
		t.Fatalf("ECONNREFUSED got (%q, %v), want (os_error, %d)", refCat, refNat, uint32(syscall.ECONNREFUSED))
	}

	canCat, _ := Category(context.Canceled)
	if canCat != "canceled" {
		t.Fatalf("context.Canceled got %q, want canceled", canCat)
	}
}
