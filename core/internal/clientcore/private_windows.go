//go:build windows

package clientcore

import (
	"errors"

	"github.com/shui1iao/Kat/internal/userio"
	"golang.org/x/sys/windows"
)

func directoryAlreadySecured(path string, sid string) bool {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return false
	}
	h, e := userio.CreateFile(
		p,
		windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if e != nil {
		return false
	}
	defer windows.CloseHandle(h)
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if e != nil || sd == nil {
		return false
	}
	sddl := sd.String()
	body := "(A;OICI;FA;;;SY)(A;OICI;FA;;;" + sid + ")"
	return sddl == "D:P"+body || sddl == "D:PAI"+body
}

func applyExclusiveDACL(path string, checkExistingDir bool) error {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	sid := u.User.Sid.String()
	if checkExistingDir && directoryAlreadySecured(path, sid) {
		return nil
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + sid + ")")
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return userio.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

func secureWorkspace(path string) error { return applyExclusiveDACL(path, true) }
func secureFile(path string) error      { return applyExclusiveDACL(path, false) }

// Reparse files may look regular to Lstat on Windows. Never follow them for
// accepted source reads or replacements, even if their target is a file.
func rejectReparse(path string) error {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return e
	}
	a, e := userio.GetFileAttributes(p)
	if e != nil {
		return e
	}
	if a&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("reparse destination")
	}
	return nil
}
