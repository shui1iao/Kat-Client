package procattr

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode/utf16"
)

const recordSID = "S-1-5-21-1-2-3-1000"
const runtimePath = `C:\ProgramData\Kat Client\Runtime`

func recordBytes(text string) []byte {
	u := utf16.Encode([]rune(text))
	u = append(u, 0)
	b := make([]byte, 2*len(u))
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	return b
}
func recordFixture(schema uint32) installationRecord {
	r := installationRecord{Schema: schema, Root: `C:\KatSplitInstallTest\tool\Kat`, SID: recordSID}
	if schema == 2 {
		runtime := runtimePath
		r.Runtime = &runtime
		r.Hashes = map[string]string{}
		for _, n := range installationFiles {
			r.Hashes[n] = strings.Repeat("a", 64)
		}
	}
	return r
}
func recordJSON(r installationRecord) string { b, _ := json.Marshal(r); return string(b) }
func TestInstallationRecordSchema1And2RoleBinding(t *testing.T) {
	for _, schema := range []uint32{1, 2} {
		r := recordFixture(schema)
		got, err := decodeInstallationRecord(1, recordBytes(recordJSON(r)), recordSID, runtimePath)
		if err != nil || got.Root != r.Root || got.SID != r.SID || got.Schema != schema {
			t.Fatal(schema, err)
		}
		service, pins, err := installationPins(got, r.Root+`\kat-client-core.exe`, runtimePath)
		if err != nil {
			t.Fatal(err)
		}
		expected := r.Root + `\kat-network-service.exe`
		if schema == 2 {
			expected = runtimePath + `\kat-network-service.exe`
		}
		if service != expected || len(pins) < 4 {
			t.Fatal(service, pins)
		}
	}
	legacy := recordJSON(recordFixture(1))
	legacy = strings.TrimSuffix(legacy, "}") + `,"runtime":null,"hashes":null}`
	if _, e := decodeInstallationRecord(1, recordBytes(legacy), recordSID, runtimePath); e != nil {
		t.Fatal("Rust legacy Option null compatibility", e)
	}
}
func TestInstallationRecordStrictShapeSIDRuntimeAndInventory(t *testing.T) {
	raw := recordJSON(recordFixture(2))
	cases := []string{
		strings.Replace(raw, `"schema":2`, `"schema":3`, 1), strings.Replace(raw, `"schema":2`, `"schema":1`, 1), strings.Replace(raw, `"schema":2`, `"schema":2,"schema":2`, 1),
		strings.TrimSuffix(raw, "}") + `,"unknown":"private"}`, strings.Replace(raw, `"root":`, `"rootx":`, 1), strings.Replace(raw, recordSID, "S-1-5-21-9-2-3-1000", 1),
		strings.Replace(raw, `C:\\ProgramData\\Kat Client\\Runtime`, `C:\\Other\\Runtime`, 1), strings.Replace(raw, `C:\\ProgramData\\Kat Client\\Runtime`, `C:\\KatSplitInstallTest\\tool\\Kat`, 1),
		strings.Replace(raw, `C:\\KatSplitInstallTest\\tool\\Kat`, `C:\\foo\\..\\Kat`, 1), strings.Replace(raw, `C:\\KatSplitInstallTest\\tool\\Kat`, `\\\\server\\share\\Kat`, 1),
		strings.Replace(raw, `"hashes":{`, `"hashes":{"unknown":"`+strings.Repeat("a", 64)+`",`, 1), strings.Replace(raw, `"hashes":{`, `"hashes":{"kat-client-core.exe":"`+strings.Repeat("a", 64)+`",`, 1),
		strings.Replace(raw, `"hashes":{`, `"unused":{`, 1), strings.Replace(raw, strings.Repeat("a", 64), strings.Repeat("A", 64), 1), raw + `{}`,
	}
	for i, s := range cases {
		if s == raw {
			t.Fatalf("test mutation%d unchanged", i)
		}
		if _, e := decodeInstallationRecord(1, recordBytes(s), recordSID, runtimePath); e == nil {
			t.Fatalf("invalid accepted%d", i)
		}
	}
	for _, change := range []func(*installationRecord){func(r *installationRecord) { r.Runtime = nil }, func(r *installationRecord) { r.Hashes = nil }, func(r *installationRecord) { delete(r.Hashes, "kat-client-core.exe") }} {
		r := recordFixture(2)
		change(&r)
		if _, e := decodeInstallationRecord(1, recordBytes(recordJSON(r)), recordSID, runtimePath); e == nil {
			t.Fatal("missing required binding")
		}
	}
	if _, e := decodeInstallationRecord(1, recordBytes(raw), recordSID, `D:\Unapproved\Runtime`); e == nil {
		t.Fatal("known folder mismatch")
	}
}
func TestInstallationRecordWireBoundsAndNoRawErrors(t *testing.T) {
	good := recordBytes(recordJSON(recordFixture(2)))
	bad := [][]byte{nil, {1}, {0, 0}, {0, 0xd8, 0, 0}, append(append([]byte{}, good...), 0, 0), good[:len(good)-2], make([]byte, 8194)}
	for _, b := range bad {
		if _, e := decodeInstallationRecord(1, b, recordSID, runtimePath); e == nil || e.Error() != "trusted original-flow service unavailable" {
			t.Fatal("bad wire")
		}
	}
	if _, e := decodeInstallationRecord(3, good, recordSID, runtimePath); e == nil {
		t.Fatal("REG_BINARY")
	}
	if _, e := decodeInstallationRecord(1, good, "S-1-5-18", runtimePath); e == nil {
		t.Fatal("other SID")
	}
}
func TestInstallationPinsWritableAppAncestorIsNotRuntimeAuthority(t *testing.T) {
	r := recordFixture(2)
	service, pins, e := installationPins(r, r.Root+`\kat-client-core.exe`, runtimePath)
	if e != nil {
		t.Fatal(e)
	}
	if service == r.Root+`\kat-network-service.exe` {
		t.Fatal("app service trusted")
	}
	for _, p := range pins {
		switch {
		case strings.HasPrefix(p.path, runtimePath):
			if p.aclKind != "protected" {
				t.Fatal("runtime leaf not protected", p)
			}
		case p.path == r.Root+`\kat-client-core.exe`:
			if p.aclKind != "" || p.hash != r.Hashes["kat-client-core.exe"] {
				t.Fatal("ordinary image role/hash", p)
			}
		case strings.HasPrefix(p.path, `C:\KatSplitInstallTest`):
			if p.aclKind != "" {
				t.Fatal("ordinary parent M would still reject", p)
			}
		}
	}
	for _, exe := range []string{r.Root + `\kat-network-service.exe`, runtimePath + `\kat-client-core.exe`, `C:\Fake\kat-client-core.exe`, r.Root + `\sub\..\kat-client-core.exe`} {
		if _, _, err := installationPins(r, exe, runtimePath); err == nil {
			t.Fatal("wrong ordinary role", exe)
		}
	}
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
func TestInstallationPinObjectRejectsReparseFinalAliasAndHardlink(t *testing.T) {
	for _, p := range []installationPin{{path: runtimePath, directory: true}, {path: runtimePath + `\kat-network-service.exe`}, {path: recordFixture(2).Root, directory: true}} {
		if !pinObjectMatches(p, p.directory, false, true, 1, `\\?\`+p.path) {
			t.Fatal("valid object")
		}
		if pinObjectMatches(p, p.directory, true, true, 1, p.path) || pinObjectMatches(p, p.directory, false, false, 1, p.path) || pinObjectMatches(p, !p.directory, false, true, 1, p.path) || pinObjectMatches(p, p.directory, false, true, 1, p.path+`\other`) {
			t.Fatal("bad object accepted")
		}
		if !p.directory && pinObjectMatches(p, false, false, true, 2, p.path) {
			t.Fatal("hardlink")
		}
	}
}
func TestRustFixedInventoryRuntimePolicyAndWindowsChecksParity(t *testing.T) {
	raw, e := os.ReadFile("../../../app/src-tauri/src/installer_files.rs")
	if e != nil {
		t.Fatal(e)
	}
	s := strings.Split(strings.Split(string(raw), "pub const FILES:")[1], "];")[0]
	names := regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(s, -1)
	if len(names) != len(installationFiles) {
		t.Fatal("manifest count")
	}
	for i, n := range names {
		if n[1] != installationFiles[i] {
			t.Fatal("manifest key", i)
		}
	}
	raw, e = os.ReadFile("../../../app/src-tauri/src/service_self_read.rs")
	if e != nil || !strings.Contains(string(raw), "mask & 0x500d0040 == 0") {
		t.Fatal("runtime ancestor policy drift")
	}
	raw, e = os.ReadFile("authority_windows.go")
	if e != nil {
		t.Fatal(e)
	}
	s = string(raw)
	for _, token := range []string{"windows.KEY_READ|windows.KEY_WOW64_64KEY", "8 /* REG_OPTION_OPEN_LINK */", "SymbolicLinkValue", "windows.SE_DACL_PROTECTED", "windows.KnownFolderPath(windows.FOLDERID_ProgramData,0)", "decodeInstallationRecord(kind,b,user.User.Sid.String(),runtime)", "windows.DRIVE_FIXED", "windows.FILE_FLAG_OPEN_REPARSE_POINT", "pinObjectMatches(p,", "p.aclKind!=\"\"&&checkedACL", "p.hash!=\"\"&&!pinnedHash", "share=windows.FILE_SHARE_READ", "windows.ReadFile(h,buf", "return service,release,nil"} {
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
