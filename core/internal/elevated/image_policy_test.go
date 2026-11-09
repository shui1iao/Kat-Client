package elevated

import (
	"os"
	"strings"
	"testing"
)

// The actual read-only ProgramData receipt is Users ALLOW/flags2/mask0x116.
// InheritOnly skipping remains in the unchanged Windows adapter.
func TestRuntimeAncestorActualACE(t *testing.T) {
	const users = "S-1-5-32-545"
	if uint32(0x116)&0x500d0142 != 0x102 || uint32(0x116)&0x500d0040 != 0 {
		t.Fatal("receipt/policy mismatch")
	}
	if !imageGrantSafe(users, 0x116, false, false, true) {
		t.Fatal("legitimate Runtime ancestor rejected")
	}
	for _, role := range [][3]bool{{false, false, false}, {false, true, false}} {
		if imageGrantSafe(users, 0x116, role[0], role[1], role[2]) {
			t.Fatal("strict Runtime root/App/image weakened")
		}
	}
	if !imageGrantSafe(users, 0x1200a9, false, false, true) {
		t.Fatal("read-only ACE rejected")
	}
	for _, sid := range []string{"S-1-5-18", "S-1-5-32-544"} {
		if !trusted(sid) || !imageGrantSafe(sid, 0x1f01ff, false, true, false) {
			t.Fatal("trusted full access changed")
		}
	}
	if trusted(users) || trusted("S-1-5-21-1-2-3-1000") {
		t.Fatal("ordinary owner trusted")
	}
	for _, mask := range []uint32{0x40, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000} {
		if imageGrantSafe(users, mask, false, false, true) {
			t.Fatalf("replacement authority accepted %x", mask)
		}
	}
	b, e := os.ReadFile("platform_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	for _, guard := range []string{`return pinImage(path, want, false)`, `runtime && i < len(parts)-1`, `pinImage(path, r.Hashes["kat-network-service.exe"], true)`, `a.Header.AceFlags&0x08 != 0`, `!trusted(owner.String())`, `windows.FILE_SHARE_READ`, `info.NumberOfLinks != 1`, `hex.EncodeToString(hash.Sum(nil)) != want`} {
		if !strings.Contains(s, guard) {
			t.Fatal("lost scope/pin guard", guard)
		}
	}
	if strings.Count(s, "pinImage(") != 3 {
		t.Fatal("Runtime role used outside service verifier")
	}
}
