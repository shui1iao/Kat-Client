package procattr

import (
	"os"
	"strings"
	"testing"
)

const recordSID = "S-1-5-21-1-2-3-1000"

func TestRuntimeAndProtectedGrantPolicy(t *testing.T) {
	for _, m := range []uint32{0x10000000, 0x40000000, 0x40000, 0x80000, 0x10000, 0x40} {
		if safeGrant("S-1-5-18", "S-1-5-32-545", m, 0, "runtime", false, false) {
			t.Fatal("replaceable runtime ancestor", m)
		}
	}
	if !safeGrant("S-1-5-18", "S-1-5-32-545", 0x116, 0, "runtime", false, false) {
		t.Fatal("Rust ProgramData ancestor child-create semantics")
	}
	for _, m := range []uint32{0x116, 2, 4, 0x100, 0x10000, 0x40} {
		if safeGrant("S-1-5-18", "S-1-5-32-545", m, 0, "protected", false, false) {
			t.Fatal("runtime leaf writable", m)
		}
	}
	if safeGrant(recordSID, "S-1-5-18", 0, 0, "runtime", false, false) {
		t.Fatal("bad owner")
	}
}

func TestRuntimePolicyAndWindowsChecksParity(t *testing.T) {
	raw, e := os.ReadFile("../../../app/src-tauri/src/service_self_read.rs")
	if e != nil || !strings.Contains(string(raw), "mask & 0x500d0040 == 0") {
		t.Fatal("runtime ancestor policy drift")
	}
	raw, e = os.ReadFile("authority_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s := string(raw)
	for _, token := range []string{"windows.KEY_READ|windows.KEY_WOW64_64KEY", "8 /* REG_OPTION_OPEN_LINK */", "SymbolicLinkValue", "windows.SE_DACL_PROTECTED", "windows.ReadFile(h,buf"} {
		if !strings.Contains(strings.ReplaceAll(s, " ", ""), strings.ReplaceAll(token, " ", "")) {
			t.Fatal("missing actual adapter check", token)
		}
	}
	for _, forbidden := range []string{"FILE_SHARE_DELETE", "os.Getenv", "HKEY_CURRENT_USER", "SetNamedSecurityInfo", "AdjustTokenPrivileges", "CreateService", "SetValue"} {
		if strings.Contains(s, forbidden) {
			t.Fatal("extra capability", forbidden)
		}
	}
}
