//go:build windows

package tunplatform

// Kat-owned implementation of Microsoft's file/security ABI and the official
// Wintun 0.14.1 Permitted API (wintun.h, MIT option). No driver source or GPL code.
import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"
)

const wintunSHA256 = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"

type nativeDevice struct {
	adapter, session                                    uintptr
	stop, readEvent                                     windows.Handle
	luid                                                uint64
	guid                                                string
	dll                                                 *windows.DLL
	pins                                                []windows.Handle
	receive, release, allocate, send, end, closeAdapter *windows.Proc
	readMu, writeMu                                     sync.Mutex
	once                                                sync.Once
	closed                                              atomic.Bool
	closeErr                                            error
}

func (d *nativeDevice) MTU() int     { return MTU }
func (d *nativeDevice) LUID() uint64 { return d.luid }
func (d *nativeDevice) GUID() string { return d.guid }
func (d *nativeDevice) ReadPacket(b []byte) (int, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()
	for {
		if d.closed.Load() {
			return 0, io.ErrClosedPipe
		}
		var n uint32
		p, _, e := d.receive.Call(d.session, uintptr(unsafe.Pointer(&n)))
		if p != 0 {
			if n == 0 || n > 65535 {
				d.release.Call(d.session, p)
				return 0, errors.New("WINTUN_PACKET_SIZE")
			}
			if int(n) > len(b) {
				d.release.Call(d.session, p)
				return 0, io.ErrShortBuffer
			}
			copy(b, unsafe.Slice((*byte)(unsafe.Pointer(p)), int(n)))
			d.release.Call(d.session, p)
			return int(n), nil
		}
		if e != windows.ERROR_NO_MORE_ITEMS {
			return 0, fmt.Errorf("WINTUN_RECEIVE: %w", e)
		}
		which, err := windows.WaitForMultipleObjects([]windows.Handle{d.stop, d.readEvent}, false, windows.INFINITE)
		if err != nil {
			return 0, err
		}
		if which == windows.WAIT_OBJECT_0 {
			return 0, io.ErrClosedPipe
		}
		if which != windows.WAIT_OBJECT_0+1 {
			return 0, errors.New("WINTUN_WAIT")
		}
	}
}
func (d *nativeDevice) WritePacket(b []byte) error {
	if len(b) == 0 || len(b) > 65535 {
		return errors.New("WINTUN_PACKET_SIZE")
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	if d.closed.Load() {
		return io.ErrClosedPipe
	}
	p, _, e := d.allocate.Call(d.session, uintptr(len(b)))
	if p == 0 {
		return fmt.Errorf("WINTUN_ALLOCATE: %w", e)
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(p)), len(b)), b)
	d.send.Call(d.session, p)
	return nil
}
func (d *nativeDevice) Close() error {
	d.once.Do(func() {
		d.closed.Store(true)
		if d.stop != 0 {
			d.closeErr = windows.SetEvent(d.stop)
		}
		d.readMu.Lock()
		defer d.readMu.Unlock()
		d.writeMu.Lock()
		defer d.writeMu.Unlock()
		if d.session != 0 {
			d.end.Call(d.session)
			d.session = 0
		}
		if d.adapter != 0 {
			d.closeAdapter.Call(d.adapter)
			d.adapter = 0
		}
		if d.stop != 0 {
			windows.CloseHandle(d.stop)
			d.stop = 0
		}
		if d.dll != nil {
			if e := d.dll.Release(); d.closeErr == nil {
				d.closeErr = e
			}
		}
		for i := len(d.pins) - 1; i >= 0; i-- {
			windows.CloseHandle(d.pins[i])
		}
		d.pins = nil
	})
	return d.closeErr
}
func trustedSID(s string) bool {
	return s == "S-1-5-18" || s == "S-1-5-32-544" || s == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}

// Every mutable ancestor is pinned without write/delete sharing. ACLs are only
// read: creation-only grants on volume/ProgramData are not replacement rights.
func pinPath(path string, directory, ancestor bool) (windows.Handle, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return 0, e
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	access := uint32(windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL)
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE)
	if !directory {
		access |= windows.FILE_READ_DATA
		share = windows.FILE_SHARE_READ
	}
	h, e := windows.CreateFile(p, access, share, nil, windows.OPEN_EXISTING, flags, 0)
	if e != nil {
		return 0, e
	}
	fail := func(e error) (windows.Handle, error) { windows.CloseHandle(h); return 0, e }
	var info windows.ByHandleFileInformation
	if e = windows.GetFileInformationByHandle(h, &info); e != nil {
		return fail(e)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (!directory && (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || info.NumberOfLinks != 1)) {
		return fail(errors.New("WINTUN_UNTRUSTED_PATH"))
	}
	var final [32768]uint16
	n, e := windows.GetFinalPathNameByHandle(h, &final[0], uint32(len(final)), 0)
	if e != nil || n >= uint32(len(final)) {
		return fail(errors.New("WINTUN_FINAL_PATH"))
	}
	observed := strings.TrimPrefix(windows.UTF16ToString(final[:n]), `\\?\`)
	if !strings.EqualFold(filepath.Clean(path), filepath.Clean(observed)) {
		return fail(errors.New("WINTUN_PATH_IDENTITY"))
	}
	sd, e := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil || sd == nil {
		return fail(errors.New("WINTUN_ACL"))
	}
	owner, _, e := sd.Owner()
	if e != nil || owner == nil || !trustedSID(owner.String()) {
		return fail(errors.New("WINTUN_ACL_OWNER"))
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return fail(errors.New("WINTUN_ACL"))
	}
	for i := uint16(0); i < acl.AceCount; i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if e = windows.GetAce(acl, uint32(i), &a); e != nil || a == nil {
			return fail(errors.New("WINTUN_ACL"))
		}
		if a.Header.AceFlags&0x08 != 0 {
			continue
		}
		if a.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if a.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fail(errors.New("WINTUN_ACL_TYPE"))
		}
		sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
		if !sid.IsValid() {
			return fail(errors.New("WINTUN_ACL"))
		}
		if trustedSID(sid.String()) {
			continue
		}
		forbidden := uint32(windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.WRITE_DAC | windows.WRITE_OWNER | 0x40 /* FILE_DELETE_CHILD, winnt.h */)
		if !ancestor {
			forbidden |= windows.DELETE | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
		}
		if uint32(a.Mask)&forbidden != 0 {
			return fail(errors.New("WINTUN_ACL_WRITABLE"))
		}
	}
	return h, nil
}
func loadPinnedWintun() (dll *windows.DLL, kept []windows.Handle, err error) {
	stage := "dll_path"
	defer func() { err = At(stage, "", err) }()
	base, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil {
		return nil, nil, e
	}
	if len(filepath.VolumeName(base)) != 2 || !filepath.IsAbs(base) {
		return nil, nil, errors.New("WINTUN_RUNTIME_PATH")
	}
	paths := []string{filepath.VolumeName(base) + `\`, base, filepath.Join(base, "Kat Client"), filepath.Join(base, "Kat Client", "Runtime"), filepath.Join(base, "Kat Client", "Runtime", "network")}
	var pins []windows.Handle
	fail := func(e error) (*windows.DLL, []windows.Handle, error) {
		for i := len(pins) - 1; i >= 0; i-- {
			windows.CloseHandle(pins[i])
		}
		return nil, nil, e
	}
	stage = "dll_ancestor_pin"
	for i, p := range paths {
		h, e := pinPath(p, true, i < 3)
		if e != nil {
			return fail(e)
		}
		pins = append(pins, h)
	}
	dllPath := filepath.Join(paths[len(paths)-1], "wintun.dll")
	stage = "dll_pin"
	h, e := pinPath(dllPath, false, false)
	if e != nil {
		return fail(e)
	}
	pins = append(pins, h)
	stage = "dll_read"
	hash := sha256.New()
	var b [32768]byte
	total := 0
	for {
		var n uint32
		e = windows.ReadFile(h, b[:], &n, nil)
		if e != nil && e != windows.ERROR_HANDLE_EOF {
			return fail(e)
		}
		total += int(n)
		if total > 16<<20 {
			return fail(errors.New("WINTUN_SIZE"))
		}
		hash.Write(b[:n])
		if n == 0 || e == windows.ERROR_HANDLE_EOF {
			break
		}
	}
	stage = "dll_hash"
	if hex.EncodeToString(hash.Sum(nil)) != wintunSHA256 {
		return fail(errors.New("WINTUN_INTEGRITY"))
	}
	stage = "dll_load"
	module, e := windows.LoadLibraryEx(dllPath, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if e != nil {
		return fail(e)
	}
	return &windows.DLL{Name: dllPath, Handle: module}, pins, nil
}
func createNativeDevice(a Adapter) (dev Device, err error) {
	stage := "device_open"
	defer func() { err = At(stage, "", err) }()
	dll, pins, e := loadPinnedWintun()
	if e != nil {
		return nil, e
	}
	d := &nativeDevice{dll: dll, pins: pins, guid: a.GUID}
	fail := func(e error) (Device, error) { d.Close(); return nil, e }
	stage = "dll_exports"
	var create, start, event, getLUID *windows.Proc
	for _, item := range []struct {
		name string
		out  **windows.Proc
	}{
		{"WintunCreateAdapter", &create}, {"WintunCloseAdapter", &d.closeAdapter}, {"WintunStartSession", &start}, {"WintunEndSession", &d.end}, {"WintunGetReadWaitEvent", &event}, {"WintunGetAdapterLUID", &getLUID}, {"WintunReceivePacket", &d.receive}, {"WintunReleaseReceivePacket", &d.release}, {"WintunAllocateSendPacket", &d.allocate}, {"WintunSendPacket", &d.send},
	} {
		*item.out, e = dll.FindProc(item.name)
		if e != nil {
			return fail(e)
		}
	}
	guid, e := windows.GUIDFromString("{" + a.GUID + "}")
	if e != nil {
		return fail(e)
	}
	name, e := windows.UTF16PtrFromString(a.Alias)
	if e != nil {
		return fail(e)
	}
	kind, _ := windows.UTF16PtrFromString("Kat")
	stage = "adapter_create"
	d.adapter, _, e = create.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(kind)), uintptr(unsafe.Pointer(&guid)))
	if d.adapter == 0 {
		return fail(At(stage, "WINTUN_CREATE", e))
	}
	stage = "adapter_luid"
	getLUID.Call(d.adapter, uintptr(unsafe.Pointer(&d.luid)))
	if d.luid == 0 {
		return fail(errors.New("WINTUN_LUID"))
	}
	stage = "adapter_guid"
	var actual windows.GUID
	if e = ipCall("ConvertInterfaceLuidToGuid", uintptr(unsafe.Pointer(&d.luid)), uintptr(unsafe.Pointer(&actual))); e != nil {
		return fail(e)
	}
	if !strings.EqualFold(strings.Trim(actual.String(), "{}"), a.GUID) {
		return fail(errors.New("WINTUN_GUID"))
	}
	stage = "adapter_session"
	d.session, _, e = start.Call(d.adapter, 8<<20)
	if d.session == 0 {
		return fail(At(stage, "WINTUN_SESSION", e))
	}
	stage = "adapter_event"
	v, _, e := event.Call(d.session)
	if v == 0 {
		return fail(At(stage, "WINTUN_EVENT", e))
	}
	d.readEvent = windows.Handle(v)
	d.stop, e = windows.CreateEvent(nil, 1, 0, nil)
	if e != nil {
		return fail(e)
	}
	return d, nil
}
