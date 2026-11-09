//go:build windows

package clientcore

import (
	"errors"
	"github.com/shui1iao/Kat/internal/userio"
	"golang.org/x/sys/windows"
)

// Protect the per-user workspace and inherited files before writing credentials.
func secureWorkspace(path string) error {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + u.User.Sid.String() + ")")
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return userio.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
func secureFile(path string) error { return secureWorkspace(path) }

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
