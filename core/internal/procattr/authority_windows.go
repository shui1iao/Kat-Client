package procattr

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"reflect"
	"unsafe"
)

func checkedACL(h windows.Handle, obj windows.SE_OBJECT_TYPE, kind string, leaf, volume bool) error {
	sd, err := windows.GetSecurityInfo(h, obj, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return unavailable()
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !trustedOwner(owner.String()) {
		return unavailable()
	}
	if kind == "protected" && owner.String() != "S-1-5-18" && owner.String() != "S-1-5-32-544" {
		return unavailable()
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return unavailable()
	}
	control, _, err := sd.Control()
	if err != nil || (kind == "registry" && leaf && control&windows.SE_DACL_PROTECTED == 0) {
		return unavailable()
	}
	for i := uint16(0); i < acl.AceCount; i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, uint32(i), &a) != nil || a == nil {
			return unavailable()
		}
		switch a.Header.AceType {
		case 0:
			if a.Header.AceSize < 12 {
				return unavailable()
			}
			sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
			if !sid.IsValid() || !safeGrant(owner.String(), sid.String(), uint32(a.Mask), a.Header.AceFlags, kind, leaf, volume) {
				return unavailable()
			}
		case 1, 2:
		default:
			return unavailable()
		}
	}
	return nil
}
func authorityKey(path string, leaf bool) (registry.Key, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, unavailable()
	}
	var h windows.Handle
	if windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, name, 8 /* REG_OPTION_OPEN_LINK */, windows.KEY_READ|windows.KEY_WOW64_64KEY, &h) != nil {
		return 0, unavailable()
	}
	k := registry.Key(h)
	if err := checkedACL(h, windows.SE_REGISTRY_KEY, "registry", leaf, false); err != nil {
		k.Close()
		return 0, err
	}
	if _, _, err := k.GetValue("SymbolicLinkValue", nil); err != windows.ERROR_FILE_NOT_FOUND {
		k.Close()
		return 0, unavailable()
	}
	return k, nil
}

// Read only the protected HKLM64 authority. No HKCU/environment/user fallback.
func machineRecord() (installationRecord, string, error) {
	fail := func() (installationRecord, string, error) { return installationRecord{}, "", unavailable() }
	parent, err := authorityKey("SOFTWARE", false)
	if err != nil {
		return fail()
	}
	defer parent.Close()
	key, err := authorityKey(`SOFTWARE\Kat Client Installation`, true)
	if err != nil {
		return fail()
	}
	defer key.Close()
	n, kind, err := key.GetValue("Record", nil)
	if err != nil || kind != registry.SZ || n < 2 || n > 8192 || n%2 != 0 {
		return fail()
	}
	b := make([]byte, n)
	n, kind, err = key.GetValue("Record", b)
	if err != nil || kind != registry.SZ || n != len(b) {
		return fail()
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fail()
	}
	data, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil || !validRoot(data) {
		return fail()
	}
	runtime := data + `\Kat Client\Runtime`
	record, err := decodeInstallationRecord(kind, b, user.User.Sid.String(), runtime)
	if err != nil {
		return fail()
	}
	return record, runtime, nil
}

// Hash through the held, no-write/no-delete-share regular-file handle. No path
// reopen and no user manifest is consulted. Limit matches Rust client pins.
func pinnedHash(h windows.Handle, info *windows.ByHandleFileInformation, expected string) bool {
	size := uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)
	if !exactHash(expected) || size > 256*1024*1024 {
		return false
	}
	sum := sha256.New()
	buf := make([]byte, 32768)
	var total uint64
	for {
		var n uint32
		err := windows.ReadFile(h, buf, &n, nil)
		if err != nil || total+uint64(n) > 256*1024*1024 {
			return false
		}
		if n == 0 {
			break
		}
		total += uint64(n)
		sum.Write(buf[:n])
	}
	return total == size && hex.EncodeToString(sum.Sum(nil)) == expected
}

// Pins remain live through the existing SCM/process/token/pipe/tuple checks.
// Schema1 keeps the legacy protected same-root policy. Schema2 separates the
// ordinary app role from the strict fixed system Runtime trust anchor.
func acquireInstallation(exe string) (*installationGuard, error) {
	record, runtime, err := machineRecord()
	if err != nil {
		return nil, err
	}
	service, plans, err := installationPins(record, exe, runtime)
	if err != nil {
		return nil, err
	}
	var handles []windows.Handle
	release := func() {
		for _, h := range handles {
			windows.CloseHandle(h)
		}
	}
	fail := func(native ...error) (*installationGuard, error) {
		release()
		if len(native) > 0 {
			return nil, attributionError("pin", native[0])
		}
		return nil, unavailable()
	}
	for _, p := range plans {
		name, e := windows.UTF16PtrFromString(p.path)
		if e != nil {
			return fail(e)
		}
		if p.volume && windows.GetDriveType(name) != windows.DRIVE_FIXED {
			return fail()
		}
		access := uint32(windows.FILE_READ_ATTRIBUTES)
		if p.aclKind != "" {
			access |= windows.READ_CONTROL
		}
		share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE)
		if p.hash != "" {
			access |= windows.FILE_READ_DATA
			share = windows.FILE_SHARE_READ
		}
		h, e := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if e != nil {
			return fail(e)
		}
		handles = append(handles, h)
		var info windows.ByHandleFileInformation
		if e := windows.GetFileInformationByHandle(h, &info); e != nil {
			return fail(e)
		}
		final := make([]uint16, 32768)
		n, e := windows.GetFinalPathNameByHandle(h, &final[0], uint32(len(final)), 0)
		if e != nil || n == 0 || int(n) >= len(final) {
			return fail()
		}
		typ, e := windows.GetFileType(h)
		if e != nil || !pinObjectMatches(p, info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0, info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, typ == windows.FILE_TYPE_DISK, info.NumberOfLinks, windows.UTF16ToString(final[:n])) {
			return fail()
		}
		if p.aclKind != "" && checkedACL(h, windows.SE_FILE_OBJECT, p.aclKind, false, p.volume) != nil {
			return fail()
		}
		if p.hash != "" && !pinnedHash(h, &info, p.hash) {
			return fail()
		}
	}
	return &installationGuard{record: record, runtime: runtime, expected: service, plans: plans, handles: handles, release: release}, nil
}

type installationGuard struct {
	record            installationRecord
	runtime, expected string
	plans             []installationPin
	handles           []windows.Handle
	release           func()
}

func pinInstallation(exe string) (string, func(), error) {
	g, e := acquireInstallation(exe)
	if e != nil {
		return "", nil, e
	}
	return g.expected, g.release, nil
}

// Content and role path replacement are prevented by the held no-write/no-
// delete-share pins. Re-read approval + recheck ACL/object metadata every use;
// this is NOT a TTL cache of a released installation authorization.
func (g *installationGuard) check() error {
	record, runtime, e := machineRecord()
	if e != nil || runtime != g.runtime || !reflect.DeepEqual(record, g.record) {
		return errors.New("installation approval changed")
	}
	for i, p := range g.plans {
		h := g.handles[i]
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(h, &info) != nil {
			return unavailable()
		}
		final := make([]uint16, 32768)
		n, e := windows.GetFinalPathNameByHandle(h, &final[0], uint32(len(final)), 0)
		typ, te := windows.GetFileType(h)
		if e != nil || te != nil || n == 0 || int(n) >= len(final) || !pinObjectMatches(p, info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0, info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, typ == windows.FILE_TYPE_DISK, info.NumberOfLinks, windows.UTF16ToString(final[:n])) {
			return unavailable()
		}
		if p.aclKind != "" && checkedACL(h, windows.SE_FILE_OBJECT, p.aclKind, false, p.volume) != nil {
			return unavailable()
		}
	}
	return nil
}
