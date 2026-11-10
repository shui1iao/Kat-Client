package procattr

import (
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
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

// Hash through the held, no-write/no-delete-share regular-file handle. No path
// reopen and no user manifest is consulted. Limit matches Rust client pins.
func pinnedHash(h windows.Handle, info *windows.ByHandleFileInformation, expected string) bool {
	if len(expected) != 64 {
		return false
	}
	for _, c := range expected {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	size := uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)
	if size > 256*1024*1024 {
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
