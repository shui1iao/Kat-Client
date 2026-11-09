//go:build windows

package userio

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var medium atomic.Uintptr

// InstallMedium takes ownership of a service-duplicated impersonation token.
// No linked token, credentials, shell token lookup, or elevated fallback exists.
func InstallMedium(t windows.Token) error {
	if !Required() || t == 0 {
		return ErrMedium
	}
	var elevated, kind, session, ownSession uint32
	var n uint32
	query := func(tok windows.Token, k uint32, p *uint32) error {
		return windows.GetTokenInformation(tok, k, (*byte)(unsafe.Pointer(p)), 4, &n)
	}
	if query(t, windows.TokenElevation, &elevated) != nil || elevated != 0 || query(t, windows.TokenType, &kind) != nil || kind != windows.TokenImpersonation {
		return ErrMedium
	}
	if query(t, windows.TokenSessionId, &session) != nil || session == 0 || query(windows.GetCurrentProcessToken(), windows.TokenSessionId, &ownSession) != nil || session != ownSession {
		return ErrMedium
	}
	u, er := t.GetTokenUser()
	if er != nil {
		return ErrMedium
	}
	own, er := windows.GetCurrentProcessToken().GetTokenUser()
	if er != nil || !u.User.Sid.Equals(own.User.Sid) {
		return ErrMedium
	}
	var size uint32
	windows.GetTokenInformation(t, windows.TokenIntegrityLevel, nil, 0, &size)
	if size == 0 || size > 65536 {
		return ErrMedium
	}
	data := make([]byte, size)
	if windows.GetTokenInformation(t, windows.TokenIntegrityLevel, &data[0], size, &size) != nil {
		return ErrMedium
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&data[0]))
	sid := label.Label.Sid
	if sid == nil || sid.SubAuthorityCount() == 0 || sid.SubAuthority(uint32(sid.SubAuthorityCount()-1)) != 0x2000 {
		return ErrMedium
	}
	if !medium.CompareAndSwap(0, uintptr(t)) {
		return ErrMedium
	}
	return nil
}
func Check() error {
	if Required() && medium.Load() == 0 {
		return ErrMedium
	}
	return nil
}

// Native operation identifiers are private and fixed at compile time. There is
// intentionally no "run this Go callback while impersonated" API.
type operation uint8

const (
	opCreate operation = iota
	opMkdir
	opDelete
	opRmdir
	opMove
	opLink
	opAttrs
	opSetAttrs
	opSecurity
	opNtCreate
)

var kernel = windows.NewLazySystemDLL("kernel32.dll")
var advapi = windows.NewLazySystemDLL("advapi32.dll")
var nativeProcs = [...]*windows.LazyProc{
	kernel.NewProc("CreateFileW"), kernel.NewProc("CreateDirectoryW"), kernel.NewProc("DeleteFileW"), kernel.NewProc("RemoveDirectoryW"), kernel.NewProc("MoveFileExW"), kernel.NewProc("CreateHardLinkW"), kernel.NewProc("GetFileAttributesW"), kernel.NewProc("SetFileAttributesW"), advapi.NewProc("SetNamedSecurityInfoW"), windows.NewLazySystemDLL("ntdll.dll").NewProc("NtCreateFile"),
}
var setThread = advapi.NewProc("SetThreadToken")
var revertThread = advapi.NewProc("RevertToSelf")

func nativeFailure(op operation, e error) (uintptr, error) {
	switch op {
	case opCreate, opAttrs:
		return ^uintptr(0), e
	case opSecurity:
		return 5, e
	case opNtCreate:
		return 0xc0000022, e
	}
	return 0, e
}

//go:uintptrescapes
func native(op operation, args ...uintptr) (uintptr, error) {
	if e := Check(); e != nil {
		return nativeFailure(op, e)
	}
	token := medium.Load()
	if token == 0 {
		return nativeFailure(op, ErrMedium)
	}
	p := nativeProcs[op]
	if e := p.Find(); e != nil {
		return nativeFailure(op, e)
	}
	if e := setThread.Find(); e != nil {
		return nativeFailure(op, e)
	}
	if e := revertThread.Find(); e != nil {
		return nativeFailure(op, e)
	}
	// All allocations, lazy DLL loads and caller buffers precede impersonation.
	pa, sa, ra := p.Addr(), setThread.Addr(), revertThread.Addr()
	runtime.LockOSThread()
	ok, _, se := syscall.SyscallN(sa, 0, token)
	if ok == 0 {
		runtime.UnlockOSThread()
		return nativeFailure(op, se)
	}
	r, _, ne := syscall.SyscallN(pa, args...)
	restored, _, _ := syscall.SyscallN(ra)
	if restored == 0 {
		_ = windows.TerminateProcess(windows.CurrentProcess(), 0xC0000409)
		for {
		}
	}
	runtime.UnlockOSThread()
	return r, ne
}
func boolResult(r uintptr, e error) error {
	if r != 0 {
		return nil
	}
	if e == nil || e == syscall.Errno(0) {
		return syscall.EINVAL
	}
	return e
}
func pathError(op, p string, e error) error {
	if e == nil {
		return nil
	}
	return &os.PathError{Op: op, Path: p, Err: e}
}

// CreateFile performs one path operation with the fixed medium token. The
// non-impersonating process never opens a user path first.
func CreateFile(p *uint16, access, share uint32, sa *windows.SecurityAttributes, creation, flags uint32, template windows.Handle) (windows.Handle, error) {
	if !Required() {
		return windows.CreateFile(p, access, share, sa, creation, flags, template)
	}
	// A user path may name a pipe: never let that peer impersonate the
	// privileged process after this fixed medium path-open scope returns.
	flags |= windows.SECURITY_SQOS_PRESENT | windows.SECURITY_IDENTIFICATION
	r, e := native(opCreate, uintptr(unsafe.Pointer(p)), uintptr(access), uintptr(share), uintptr(unsafe.Pointer(sa)), uintptr(creation), uintptr(flags), uintptr(template))
	if r == uintptr(windows.InvalidHandle) || r == 0 {
		if e == nil || e == syscall.Errno(0) {
			e = ErrMedium
		}
		return windows.InvalidHandle, e
	}
	return windows.Handle(r), nil
}
func OpenFile(p string, flag int, perm os.FileMode) (*os.File, error) {
	if !Required() {
		return os.OpenFile(p, flag, perm)
	}
	w, e := windows.UTF16PtrFromString(p)
	if e != nil {
		return nil, pathError("open", p, e)
	}
	access := uint32(windows.GENERIC_READ)
	switch flag & (os.O_WRONLY | os.O_RDWR) {
	case os.O_WRONLY:
		access = windows.GENERIC_WRITE
	case os.O_RDWR:
		access = windows.GENERIC_READ | windows.GENERIC_WRITE
	}
	if flag&os.O_APPEND != 0 {
		access &^= windows.GENERIC_WRITE
		access |= windows.FILE_APPEND_DATA
	}
	create := uint32(windows.OPEN_EXISTING)
	switch {
	case flag&os.O_CREATE != 0 && flag&os.O_EXCL != 0:
		create = windows.CREATE_NEW
	case flag&os.O_CREATE != 0:
		create = windows.OPEN_ALWAYS
	}
	attrs := uint32(windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_FLAG_BACKUP_SEMANTICS)
	if perm&0200 == 0 && flag&os.O_CREATE != 0 {
		attrs |= windows.FILE_ATTRIBUTE_READONLY
	}
	if flag&os.O_SYNC != 0 {
		attrs |= windows.FILE_FLAG_WRITE_THROUGH
	}
	// No SHARE_DELETE: workspace/statistics exclusive lock semantics are retained.
	h, e := CreateFile(w, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, create, attrs, 0)
	if e != nil {
		return nil, pathError("open", p, e)
	}
	f := os.NewFile(uintptr(h), p)
	if f == nil {
		windows.CloseHandle(h)
		return nil, pathError("open", p, os.ErrInvalid)
	}
	if flag&os.O_TRUNC != 0 {
		if e = f.Truncate(0); e != nil {
			f.Close()
			return nil, e
		}
	}
	return f, nil
}
func stat(p string, nofollow bool) (os.FileInfo, error) {
	if !Required() {
		if nofollow {
			return os.Lstat(p)
		}
		return os.Stat(p)
	}
	w, e := windows.UTF16PtrFromString(p)
	if e != nil {
		return nil, pathError("stat", p, e)
	}
	flags := uint32(windows.FILE_FLAG_BACKUP_SEMANTICS)
	if nofollow {
		flags |= windows.FILE_FLAG_OPEN_REPARSE_POINT
	}
	h, e := CreateFile(w, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, flags, 0)
	if e != nil {
		return nil, pathError("stat", p, e)
	}
	f := os.NewFile(uintptr(h), p)
	if f == nil {
		windows.CloseHandle(h)
		return nil, os.ErrInvalid
	}
	defer f.Close()
	return f.Stat()
}
func Stat(p string) (os.FileInfo, error)  { return stat(p, false) }
func Lstat(p string) (os.FileInfo, error) { return stat(p, true) }
func Mkdir(p string, m os.FileMode) error {
	if !Required() {
		return os.Mkdir(p, m)
	}
	w, e := windows.UTF16PtrFromString(p)
	if e != nil {
		return e
	}
	r, e := native(opMkdir, uintptr(unsafe.Pointer(w)), 0)
	return pathError("mkdir", p, boolResult(r, e))
}
func GetFileAttributes(p *uint16) (uint32, error) {
	if !Required() {
		return windows.GetFileAttributes(p)
	}
	r, e := native(opAttrs, uintptr(unsafe.Pointer(p)))
	if uint32(r) == windows.INVALID_FILE_ATTRIBUTES {
		if e == nil || e == syscall.Errno(0) {
			e = ErrMedium
		}
		return uint32(r), e
	}
	return uint32(r), nil
}
func Remove(p string) error {
	if !Required() {
		return os.Remove(p)
	}
	w, e := windows.UTF16PtrFromString(p)
	if e != nil {
		return e
	}
	a, e := GetFileAttributes(w)
	if e != nil {
		return pathError("remove", p, e)
	}
	op := opDelete
	if a&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		op = opRmdir
	}
	r, e := native(op, uintptr(unsafe.Pointer(w)))
	return pathError("remove", p, boolResult(r, e))
}
func Rename(a, b string) error {
	if !Required() {
		return os.Rename(a, b)
	}
	wa, e := windows.UTF16PtrFromString(a)
	if e != nil {
		return e
	}
	wb, e := windows.UTF16PtrFromString(b)
	if e != nil {
		return e
	}
	r, e := native(opMove, uintptr(unsafe.Pointer(wa)), uintptr(unsafe.Pointer(wb)), windows.MOVEFILE_REPLACE_EXISTING)
	e = boolResult(r, e)
	if e != nil {
		return &os.LinkError{Op: "rename", Old: a, New: b, Err: e}
	}
	return nil
}
func Link(a, b string) error {
	if !Required() {
		return os.Link(a, b)
	}
	wa, e := windows.UTF16PtrFromString(a)
	if e != nil {
		return e
	}
	wb, e := windows.UTF16PtrFromString(b)
	if e != nil {
		return e
	}
	r, e := native(opLink, uintptr(unsafe.Pointer(wb)), uintptr(unsafe.Pointer(wa)), 0)
	e = boolResult(r, e)
	if e != nil {
		return &os.LinkError{Op: "link", Old: a, New: b, Err: e}
	}
	return nil
}
func Chmod(p string, m os.FileMode) error {
	if !Required() {
		return os.Chmod(p, m)
	}
	w, e := windows.UTF16PtrFromString(p)
	if e != nil {
		return e
	}
	a, e := GetFileAttributes(w)
	if e != nil {
		return e
	}
	if m&0200 != 0 {
		a &^= windows.FILE_ATTRIBUTE_READONLY
	} else {
		a |= windows.FILE_ATTRIBUTE_READONLY
	}
	r, e := native(opSetAttrs, uintptr(unsafe.Pointer(w)), uintptr(a))
	return pathError("chmod", p, boolResult(r, e))
}
func SetNamedSecurityInfo(p string, kind windows.SE_OBJECT_TYPE, info windows.SECURITY_INFORMATION, owner, group *windows.SID, dacl, sacl *windows.ACL) error {
	if !Required() {
		return windows.SetNamedSecurityInfo(p, kind, info, owner, group, dacl, sacl)
	}
	w, e := windows.UTF16PtrFromString(p)
	if e != nil {
		return e
	}
	r, e := native(opSecurity, uintptr(unsafe.Pointer(w)), uintptr(kind), uintptr(info), uintptr(unsafe.Pointer(owner)), uintptr(unsafe.Pointer(group)), uintptr(unsafe.Pointer(dacl)), uintptr(unsafe.Pointer(sacl)))
	if e == ErrMedium {
		return e
	}
	if r != 0 {
		return syscall.Errno(r)
	}
	return nil
}

// Root confines cleanup to handles opened relative to a pinned parent. Never
// downgrade os.Root's anti-swap guarantee to a lexical prefix check.
type Root struct {
	ordinary *os.Root
	dir      *os.File
}

func OpenRoot(p string) (*Root, error) {
	if !Required() {
		r, e := os.OpenRoot(p)
		if e != nil {
			return nil, e
		}
		return &Root{ordinary: r}, nil
	}
	w, e := windows.UTF16PtrFromString(p)
	if e != nil {
		return nil, e
	}
	h, e := CreateFile(w, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(h), p)
	if f == nil {
		windows.CloseHandle(h)
		return nil, os.ErrInvalid
	}
	st, e := f.Stat()
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		f.Close()
		return nil, os.ErrPermission
	}
	return &Root{dir: f}, nil
}
func (r *Root) Close() error {
	if r.ordinary != nil {
		return r.ordinary.Close()
	}
	return r.dir.Close()
}
func (r *Root) RemoveAll(name string) error {
	if r.ordinary != nil {
		return r.ordinary.RemoveAll(name)
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\:`) {
		return os.ErrInvalid
	}
	return removeAt(windows.Handle(r.dir.Fd()), name)
}
func removeAt(parent windows.Handle, name string) error {
	u, e := windows.NewNTUnicodeString(name)
	if e != nil {
		return e
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: parent, ObjectName: u, Attributes: windows.OBJ_CASE_INSENSITIVE}
	oa.Length = uint32(unsafe.Sizeof(oa))
	var h windows.Handle
	var status windows.IO_STATUS_BLOCK
	r, e := native(opNtCreate, uintptr(unsafe.Pointer(&h)), uintptr(windows.DELETE|windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE), uintptr(unsafe.Pointer(&oa)), uintptr(unsafe.Pointer(&status)), 0, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_OPEN, windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if e == ErrMedium {
		return e
	}
	if int32(r) < 0 {
		e = windows.NTStatus(r)
		if errors.Is(e, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(e, windows.STATUS_OBJECT_PATH_NOT_FOUND) {
			return nil
		}
		return e
	}
	f := os.NewFile(uintptr(h), name)
	if f == nil {
		windows.CloseHandle(h)
		return os.ErrInvalid
	}
	defer f.Close()
	var info windows.ByHandleFileInformation
	if e = windows.GetFileInformationByHandle(h, &info); e != nil {
		return e
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return os.ErrPermission
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		names, e := f.Readdirnames(-1)
		if e != nil {
			return e
		}
		for _, n := range names {
			if n == "." || n == ".." || strings.ContainsAny(n, `/\:`) {
				return os.ErrPermission
			}
			if e := removeAt(h, n); e != nil {
				return e
			}
		}
	}
	// This is handle I/O: DELETE access was granted under medium above.
	disposition := byte(1)
	return windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &disposition, 1)
}
func RemoveAll(p string) error {
	if !Required() {
		return os.RemoveAll(p)
	}
	p = filepath.Clean(p)
	r, e := OpenRoot(filepath.Dir(p))
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	defer r.Close()
	return r.RemoveAll(filepath.Base(p))
}
