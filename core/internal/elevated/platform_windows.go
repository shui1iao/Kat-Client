//go:build windows

package elevated

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"

	"github.com/shui1iao/Kat/internal/tunplatform"
	"github.com/shui1iao/Kat/internal/userio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"io"
	"os"
	"path/filepath"
	"strings"

	"time"
	"unsafe"
)

func Elevated() bool {
	var t windows.Token
	if windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &t) != nil {
		return true
	}
	defer t.Close()
	return t.IsElevated()
}

type record struct {
	Schema  uint32            `json:"schema"`
	Root    string            `json:"root"`
	SID     string            `json:"sid"`
	Runtime string            `json:"runtime"`
	Hashes  map[string]string `json:"hashes"`
}

func protected(h windows.Handle, kind windows.SE_OBJECT_TYPE, volume, leaf, runtimeAncestor bool) error {
	sd, e := windows.GetSecurityInfo(h, kind, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if e != nil {
		return ErrIdentity
	}
	owner, _, e := sd.Owner()
	if e != nil || !trusted(owner.String()) {
		return ErrIdentity
	}
	acl, _, e := sd.DACL()
	if e != nil || acl == nil {
		return ErrIdentity
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var a *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &a) != nil {
			return ErrIdentity
		}
		if a.Header.AceFlags&0x08 != 0 {
			continue
		}
		if a.Header.AceType == 0 {
			sid := (*windows.SID)(unsafe.Pointer(&a.SidStart))
			if trusted(sid.String()) {
				continue
			}
			mask := uint32(a.Mask)
			forbidden := uint32(0x10000000 | 0x40000000 | 0x40000 | 0x80000)
			if kind == windows.SE_REGISTRY_KEY {
				forbidden |= 0x10000 | 2 | 4 | 0x20
			} else {
				if !imageGrantSafe(sid.String(), mask, volume, leaf, runtimeAncestor) {
					return ErrIdentity
				}
				continue
			}
			if mask&forbidden != 0 {
				return ErrIdentity
			}
		} else if a.Header.AceType != 1 && a.Header.AceType != 2 {
			return ErrIdentity
		}
	}
	return nil
}
func loadRecord() (record, error) {
	var r record
	k, e := openAuthority(`SOFTWARE\Kat Client Installation`)
	if e != nil {
		return r, ErrIdentity
	}
	defer k.Close()
	if protected(windows.Handle(k), windows.SE_REGISTRY_KEY, false, false, false) != nil {
		return r, ErrIdentity
	}
	parent, e := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE`, registry.READ|registry.WOW64_64KEY|0x8)
	if e != nil {
		return r, ErrIdentity
	}
	defer parent.Close()
	sd, e := windows.GetSecurityInfo(windows.Handle(parent), windows.SE_REGISTRY_KEY, windows.OWNER_SECURITY_INFORMATION)
	if e != nil {
		return r, ErrIdentity
	}
	owner, _, e := sd.Owner()
	if e != nil || !trusted(owner.String()) {
		return r, ErrIdentity
	}
	text, _, e := k.GetStringValue("Record")
	if e != nil || len(text) > 8192 || strict([]byte(text), &r) != nil || r.Schema != 2 || !filepath.IsAbs(r.Root) || r.SID == "" {
		return r, ErrIdentity
	}
	runtime, e := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if e != nil || !same(r.Runtime, filepath.Join(runtime, "Kat Client", "Runtime")) {
		return r, ErrIdentity
	}
	return r, nil
}
func same(a, b string) bool {
	return strings.EqualFold(strings.TrimPrefix(a, `\\?\`), strings.TrimPrefix(b, `\\?\`))
}
func pin(path, want string) ([]io.Closer, error) {
	return pinImage(path, want, false)
}

// runtime is used only for the service image derived from the verified Record.
func pinImage(path, want string, runtime bool) ([]io.Closer, error) {
	if !Hex(want, 64) || !filepath.IsAbs(path) {
		return nil, ErrIdentity
	}
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean) + `\`
	if len(volume) != 3 || strings.HasPrefix(clean, `\\`) {
		return nil, ErrIdentity
	}
	var pins []io.Closer
	fail := func() ([]io.Closer, error) {
		for _, p := range pins {
			p.Close()
		}
		return nil, ErrIdentity
	}
	at := volume
	parts := strings.Split(strings.TrimPrefix(clean, volume), `\`)
	for i, part := range append([]string{""}, parts...) {
		if i > 0 {
			if part == "" || part == "." || part == ".." || strings.Contains(part, ":") {
				return fail()
			}
			at = filepath.Join(at, part)
		}
		last := i == len(parts)
		w, e := windows.UTF16PtrFromString(at)
		if e != nil {
			return fail()
		}
		access := uint32(windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL)
		flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT | windows.FILE_FLAG_BACKUP_SEMANTICS)
		share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE)
		if last {
			access |= windows.GENERIC_READ
			share = windows.FILE_SHARE_READ
		}
		h, e := windows.CreateFile(w, access, share, nil, windows.OPEN_EXISTING, flags, 0)
		if e != nil {
			return fail()
		}
		f := os.NewFile(uintptr(h), at)
		if f == nil {
			windows.CloseHandle(h)
			return fail()
		}
		pins = append(pins, f)
		var info windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || ((runtime || i >= len(parts)-1) && protected(h, windows.SE_FILE_OBJECT, i == 0, last, runtime && i < len(parts)-1) != nil) {
			return fail()
		}
		if last {
			if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 || info.NumberOfLinks != 1 {
				return fail()
			}
			hash := sha256.New()
			if _, e := io.Copy(hash, io.LimitReader(f, 256<<20+1)); e != nil || hex.EncodeToString(hash.Sum(nil)) != want {
				return fail()
			}
		} else if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return fail()
		}
	}
	return pins, nil
}
func stamp(p windows.Handle) (uint64, error) {
	var c, e, k, u windows.Filetime
	err := windows.GetProcessTimes(p, &c, &e, &k, &u)
	return uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime), err
}
func identity(p windows.Handle) (string, uint32, error) {
	var t windows.Token
	if e := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &t); e != nil {
		return "", 0, e
	}
	defer t.Close()
	u, e := t.GetTokenUser()
	if e != nil {
		return "", 0, e
	}
	var sess, n uint32
	e = windows.GetTokenInformation(t, windows.TokenSessionId, (*byte)(unsafe.Pointer(&sess)), 4, &n)
	return u.User.Sid.String(), sess, e
}
func process(pid uint32, created uint64, sid string, session uint32, image string) (windows.Handle, error) {
	p, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if e != nil {
		return 0, ErrIdentity
	}
	fail := func() (windows.Handle, error) { windows.CloseHandle(p); return 0, ErrIdentity }
	c, e := stamp(p)
	if e != nil || created != 0 && c != created {
		return fail()
	}
	s, se, e := identity(p)
	if e != nil || s != sid || se != session {
		return fail()
	}
	buf := make([]uint16, 32768)
	n := uint32(len(buf))
	if windows.QueryFullProcessImageName(p, 0, &buf[0], &n) != nil || !same(windows.UTF16ToString(buf[:n]), image) {
		return fail()
	}
	wait, e := windows.WaitForSingleObject(p, 0)
	if e != nil || wait != uint32(windows.WAIT_TIMEOUT) {
		return fail()
	}
	return p, nil
}
func verifyService(pid uint32, created uint64, r record) ([]io.Closer, error) {
	m, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return nil, ErrIdentity
	}
	defer windows.CloseServiceHandle(m)
	name, _ := windows.UTF16PtrFromString("KatClientNetwork")
	svc, e := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS)
	if e != nil {
		return nil, ErrIdentity
	}
	defer windows.CloseServiceHandle(svc)
	var st windows.SERVICE_STATUS_PROCESS
	var n uint32
	if windows.QueryServiceStatusEx(svc, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &n) != nil || st.CurrentState != windows.SERVICE_RUNNING || st.ProcessId != pid {
		return nil, ErrIdentity
	}
	path := filepath.Join(r.Runtime, "kat-network-service.exe")
	pins, e := pinImage(path, r.Hashes["kat-network-service.exe"], true)
	if e != nil {
		return nil, e
	}
	p, e := process(pid, created, "S-1-5-18", 0, path)
	if e != nil {
		for _, p := range pins {
			p.Close()
		}
		return nil, e
	}
	pins = append(pins, handleCloser{p})
	return pins, nil
}
func connectPipe(ctx context.Context, name string, pid uint32, overlapped bool) (windows.Handle, error) {
	w, e := windows.UTF16PtrFromString(name)
	if e != nil {
		return 0, e
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if e := ctx.Err(); e != nil {
			return 0, e
		}
		flags := uint32(windows.SECURITY_SQOS_PRESENT | windows.SECURITY_IDENTIFICATION)
		if overlapped {
			flags |= windows.FILE_FLAG_OVERLAPPED
		}
		h, e := windows.CreateFile(w, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, flags, 0)
		if e == nil {
			var server uint32
			if windows.GetNamedPipeServerProcessId(h, &server) != nil || server != pid {
				windows.CloseHandle(h)
				return 0, ErrIdentity
			}
			return h, nil
		}
		if e != windows.ERROR_PIPE_BUSY && e != windows.ERROR_FILE_NOT_FOUND {
			return 0, e
		}
		if time.Now().After(deadline) {
			return 0, context.DeadlineExceeded
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func openPipe(ctx context.Context, name string, pid uint32) (*pipeConn, error) {
	h, e := connectPipe(ctx, name, pid, true)
	if e != nil {
		return nil, e
	}
	return &pipeConn{h: h, ctx: ctx}, nil
}
func (s *Session) service(ctx context.Context, request map[string]any, out any) (err error) {
	stage := "service_identity"
	defer func() { err = tunplatform.At(stage, "", err) }()
	exact, e := process(s.servicePID, s.serviceStamp, "S-1-5-18", 0, s.serviceImage)
	if e != nil {
		return e
	}
	defer windows.CloseHandle(exact)

	stage = "service_connect"
	f, e := openPipe(ctx, `\\.\pipe\KatClientNetwork-v1`, s.servicePID)
	if e != nil {
		return e
	}
	defer f.Close()
	f.deadline = time.Now().Add(10 * time.Second)
	stage = "service_encode"
	b, e := json.Marshal(map[string]any{"action": "elevated", "request": request})
	if e != nil || len(b) > 32768 {
		return ErrIdentity
	}
	var lenbuf [4]byte
	binary.LittleEndian.PutUint32(lenbuf[:], uint32(len(b)))
	stage = "service_write"
	if _, e = f.Write(append(lenbuf[:], b...)); e != nil {
		return e
	}
	stage = "service_read"
	if _, e = io.ReadFull(f, lenbuf[:]); e != nil {
		return e
	}
	n := binary.LittleEndian.Uint32(lenbuf[:])
	stage = "service_frame"
	if n == 0 || n > 32768 {
		return ErrIdentity
	}
	b = make([]byte, n)
	stage = "service_read"
	if _, e = io.ReadFull(f, b); e != nil {
		return e
	}
	var reply struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	stage = "service_decode"
	if strict(b, &reply) != nil {
		return ErrIdentity
	}
	if !reply.OK {
		var failure struct {
			Code   string                  `json:"code"`
			Native *uint32                 `json:"os_error"`
			Detail *tunplatform.Diagnostic `json:"tun"`
		}
		if json.Unmarshal(reply.Error, &failure) != nil {
			return ErrIdentity
		}
		return tunplatform.ServiceFailure("service_request", failure.Code, failure.Native, failure.Detail, ErrIdentity)
	}
	if out != nil {
		return strict(reply.Result, out)
	}
	return nil
}
func Open(ctx context.Context, lease string, pid uint32, created uint64) (opened *Session, err error) {
	phase := ExitValidate
	defer func() {
		if err != nil {
			err = &BootstrapError{Code: phase, Err: err}
		}
	}()
	userio.RequireMedium()
	if !Elevated() || !Hex(lease, 64) || pid == 0 || created == 0 {
		return nil, ErrIdentity
	}
	phase = ExitRecord
	r, e := loadRecord()
	if e != nil {
		return nil, e
	}
	phase = ExitService
	pins, e := verifyService(pid, created, r)
	if e != nil {
		return nil, e
	}
	s := &Session{servicePID: pid, serviceStamp: created, serviceImage: filepath.Join(r.Runtime, "kat-network-service.exe"), pins: pins}
	fail := func(e error) (*Session, error) {
		for _, p := range s.pins {
			p.Close()
		}
		return nil, e
	}
	// Fatal/runtime stderr is attached before parsing any user configuration.
	phase = ExitStderr
	stderrHandle, e := connectPipe(ctx, PrivateStderrName(lease), pid, false)
	if e != nil {
		return fail(e)
	}
	if windows.SetStdHandle(windows.STD_ERROR_HANDLE, stderrHandle) != nil {
		windows.CloseHandle(stderrHandle)
		return fail(ErrIdentity)
	}
	os.Stderr = os.NewFile(uintptr(stderrHandle), "private-stderr")
	phase = ExitBind
	var b Binding
	if e = s.service(ctx, map[string]any{"op": "bind", "lease": lease}, &b); e != nil {
		return fail(e)
	}
	phase = ExitBindingIdentity
	selfStamp, e := stamp(windows.CurrentProcess())
	sid, session, se := identity(windows.CurrentProcess())
	if e != nil || se != nil || b.Schema != 1 || b.Lease != lease || !Hex(b.Epoch, 32) || !Hex(b.Package, 64) || b.OwnerSID != sid || sid != r.SID || session != b.Session || b.CorePID != uint32(os.Getpid()) || b.CoreStamp != selfStamp {
		return fail(ErrIdentity)
	}
	if b.TunLaunch.Schema != 2 || b.TunLaunch.Engine != "core_tun_v1" || b.TunLaunch.Epoch != b.Epoch || b.TunLaunch.PackageSHA256 != b.Package || b.TunLaunch.CorePID != b.CorePID || b.TunLaunch.CoreCreated != b.CoreStamp || b.TunLaunch.OwnerSID != b.OwnerSID || b.TunLaunch.Session != b.Session || b.TunLaunch.CoreSHA256 != r.Hashes["kat-client-core.exe"] {
		return fail(ErrIdentity)
	}
	phase = ExitCorePin
	corePins, e := pin(filepath.Join(r.Root, "kat-client-core.exe"), r.Hashes["kat-client-core.exe"])
	if e != nil {
		return fail(e)
	}
	s.pins = append(s.pins, corePins...)
	p, e := process(b.CorePID, b.CoreStamp, sid, session, filepath.Join(r.Root, "kat-client-core.exe"))
	if e != nil {
		return fail(e)
	}
	windows.CloseHandle(p)
	phase = ExitGUIPin
	guiPins, e := pin(filepath.Join(r.Root, "kat-desktop.exe"), r.Hashes["kat-desktop.exe"])
	if e != nil {
		return fail(e)
	}
	s.pins = append(s.pins, guiPins...)
	gui, e := process(b.GUIPID, b.GUIStamp, sid, session, filepath.Join(r.Root, "kat-desktop.exe"))
	if e != nil {
		return fail(e)
	}
	s.pins = append(s.pins, handleCloser{gui})
	phase = ExitMedium
	if e = userio.InstallMedium(windows.Token(b.MediumToken)); e != nil {
		return fail(e)
	}
	phase = ExitWorkspace
	actual, e := windows.Token(b.MediumToken).KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	if e != nil || !same(b.Workspace, filepath.Join(actual, "app.kat.client")) {
		actual, e = windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	}
	if e != nil || !same(b.Workspace, filepath.Join(actual, "app.kat.client")) {
		return fail(ErrIdentity)
	}
	phase = ExitControl
	control, e := openPipe(ctx, ControlName(lease), b.GUIPID)
	if e != nil {
		return fail(e)
	}
	s.Binding = b
	s.Conn = control
	s.Reader = bufio.NewReader(control)
	return s, nil
}

type handleCloser struct{ h windows.Handle }

func (h handleCloser) Close() error { return windows.CloseHandle(h.h) }

func openAuthority(path string) (registry.Key, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return 0, e
	}
	var h windows.Handle
	e = windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, p, 8, windows.KEY_READ|windows.KEY_WOW64_64KEY, &h)
	if e != nil {
		return 0, e
	}
	k := registry.Key(h)
	if _, _, e := k.GetStringValue("SymbolicLinkValue"); e != registry.ErrNotExist {
		k.Close()
		return 0, ErrIdentity
	}
	return k, nil
}
