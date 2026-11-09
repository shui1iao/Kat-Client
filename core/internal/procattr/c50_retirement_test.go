package procattr

import "testing"

func TestC50RetiredSessionIdentityFence(t *testing.T) {
	// Epoch zero only bypasses the retired bridge fence; it is NOT a replacement
	// for lookupLocal/resolveCurrent's PID, path and process-creation proof.
	ordinary := Identity{Name: "ordinary.exe", Path: `C:\Apps\ordinary.exe`, Status: "known", PID: 42, Stamp: 100}
	before := ordinary
	if !IdentityCurrent(ordinary) || ordinary != before {
		t.Fatal("ordinary identity altered or rejected")
	}
	for _, epoch := range []uint64{1, 2, 0xffff, 1 << 63, ^uint64(0)} {
		old := ordinary
		old.SessionEpoch = epoch
		if IdentityCurrent(old) {
			t.Fatalf("retired bridge identity accepted: epoch=%d", epoch)
		}
	}
}
