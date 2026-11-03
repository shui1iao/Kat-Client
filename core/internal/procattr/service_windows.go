package procattr

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"net/netip"
	"os"
	"strings"
	"time"
	"unsafe"
)

var waitPipe = windows.NewLazySystemDLL("kernel32.dll").NewProc("WaitNamedPipeW")

func unavailable() error { return errors.New("trusted original-flow service unavailable") }
func serviceState(s windows.Handle) (windows.SERVICE_STATUS_PROCESS, error) {
	var state windows.SERVICE_STATUS_PROCESS
	var n uint32
	err := windows.QueryServiceStatusEx(s, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&state)), uint32(unsafe.Sizeof(state)), &n)
	return state, err
}
func checkedService(expected string) (windows.Handle, windows.Handle, uint64, uint32, error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, 0, 0, 0, unavailable()
	}
	defer windows.CloseServiceHandle(m)
	name, _ := windows.UTF16PtrFromString("KatClientNetwork")
	s, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return 0, 0, 0, 0, unavailable()
	}
	ok := false
	defer func() {
		if !ok {
			windows.CloseServiceHandle(s)
		}
	}()
	var n uint32
	_ = windows.QueryServiceConfig(s, nil, 0, &n)
	if n == 0 || n > 65536 {
		return 0, 0, 0, 0, unavailable()
	}
	b := make([]byte, n)
	cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&b[0]))
	if windows.QueryServiceConfig(s, cfg, n, &n) != nil {
		return 0, 0, 0, 0, unavailable()
	}

	if !strings.EqualFold(windows.UTF16PtrToString(cfg.BinaryPathName), `"`+expected+`" --service`) || !strings.EqualFold(windows.UTF16PtrToString(cfg.ServiceStartName), "LocalSystem") || cfg.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS {
		return 0, 0, 0, 0, unavailable()
	}
	st, err := serviceState(s)
	if err != nil || st.CurrentState != windows.SERVICE_RUNNING || st.ProcessId == 0 {
		return 0, 0, 0, 0, unavailable()
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, st.ProcessId)
	if err != nil {
		return 0, 0, 0, 0, unavailable()
	}
	valid := false
	defer func() {
		if !valid {
			windows.CloseHandle(h)
		}
	}()
	var token windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token) != nil {
		return 0, 0, 0, 0, unavailable()
	}
	user, err := token.GetTokenUser()
	token.Close()
	if err != nil || user.User.Sid.String() != "S-1-5-18" {
		return 0, 0, 0, 0, unavailable()
	}
	var session uint32
	if windows.ProcessIdToSessionId(st.ProcessId, &session) != nil || session != 0 {
		return 0, 0, 0, 0, unavailable()
	}
	image := make([]uint16, 32768)
	size := uint32(len(image))
	if windows.QueryFullProcessImageName(h, 0, &image[0], &size) != nil || !strings.EqualFold(strings.TrimPrefix(windows.UTF16ToString(image[:size]), `\\?\`), strings.TrimPrefix(expected, `\\?\`)) {
		return 0, 0, 0, 0, unavailable()
	}
	stamp, err := stamp(h)
	if err != nil {
		return 0, 0, 0, 0, unavailable()
	}
	valid = true
	ok = true
	return s, h, stamp, st.ProcessId, nil
}
func pipeTransfer(ctx context.Context, h windows.Handle, b []byte, write bool) error {
	for len(b) > 0 {
		if ctx.Err() != nil {
			return unavailable()
		}
		event, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			return unavailable()
		}
		ov := windows.Overlapped{HEvent: event}
		var n uint32
		if write {
			err = windows.WriteFile(h, b, &n, &ov)
		} else {
			err = windows.ReadFile(h, b, &n, &ov)
		}
		if err == windows.ERROR_IO_PENDING {
			for {
				wait, _ := windows.WaitForSingleObject(event, 25)
				if wait == windows.WAIT_OBJECT_0 {
					err = windows.GetOverlappedResult(h, &ov, &n, false)
					break
				}
				if wait != uint32(windows.WAIT_TIMEOUT) || ctx.Err() != nil {
					windows.CancelIoEx(h, &ov)
					_ = windows.GetOverlappedResult(h, &ov, &n, true)
					err = unavailable()
					break
				}
			}
		}
		windows.CloseHandle(event)
		if err != nil || n == 0 {
			return unavailable()
		}
		b = b[n:]
	}
	return nil
}

type flowWire struct {
	ID                 uint64 `json:"id"`
	Network            string `json:"network"`
	Source             string `json:"source"`
	Destination        string `json:"destination"`
	MidSource          string `json:"mid_source"`
	MidDestination     string `json:"mid_destination"`
	ControlSource      string `json:"control_source"`
	ControlDestination string `json:"control_destination"`
}

func sameEndpoint(a string, b netip.AddrPort) bool {
	p, err := netip.ParseAddrPort(a)
	return err == nil && p == b
}
func lookupService(ctx context.Context, q Query) (Identity, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		return Identity{}, false, unavailable()
	}
	expected, release, err := pinInstallation(exe)
	if err != nil {
		return Identity{}, false, err
	}
	defer release()
	s, process, created, pid, err := checkedService(expected)
	if err != nil {
		return Identity{}, false, err
	}
	defer windows.CloseServiceHandle(s)
	defer windows.CloseHandle(process)
	name, _ := windows.UTF16PtrFromString(`\\.\pipe\KatClientNetwork-v1`)
	for {
		r, _, _ := waitPipe.Call(uintptr(unsafe.Pointer(name)), 50)
		if r != 0 {
			break
		}
		if ctx.Err() != nil {
			return Identity{}, false, unavailable()
		}
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|0x100000|0x10000, 0)
	if err != nil {
		return Identity{}, false, unavailable()
	}
	defer windows.CloseHandle(h)
	var server uint32
	if windows.GetNamedPipeServerProcessId(h, &server) != nil || server != pid {
		return Identity{}, false, unavailable()
	}
	now, err := stamp(process)
	wait, _ := windows.WaitForSingleObject(process, 0)
	st, stateErr := serviceState(s)
	if err != nil || stateErr != nil || !trustedService(servicePeer{scmPID: st.ProcessId, pipePID: server, before: created, after: now, systemSID: "S-1-5-18", session: 0, image: "checked installed service", expected: "checked installed service", running: st.CurrentState == windows.SERVICE_RUNNING, alive: wait == uint32(windows.WAIT_TIMEOUT)}) {
		return Identity{}, false, unavailable()
	}
	request := map[string]any{"action": "lookup_original_flow", "query": map[string]string{"network": q.Network, "source": q.Source.String(), "destination": q.Destination.String(), "control_source": q.ControlSource.String(), "control_destination": q.ControlDestination.String(), "target": q.Target.String()}}
	b, err := json.Marshal(request)
	if err != nil {
		return Identity{}, false, unavailable()
	}
	frame := make([]byte, 4+len(b))
	binary.LittleEndian.PutUint32(frame, uint32(len(b)))
	copy(frame[4:], b)
	if pipeTransfer(ctx, h, frame, true) != nil {
		return Identity{}, false, unavailable()
	}
	lenbuf := make([]byte, 4)
	if pipeTransfer(ctx, h, lenbuf, false) != nil {
		return Identity{}, false, unavailable()
	}
	n := binary.LittleEndian.Uint32(lenbuf)
	if n == 0 || n > 32768 {
		return Identity{}, false, unavailable()
	}
	b = make([]byte, n)
	if pipeTransfer(ctx, h, b, false) != nil {
		return Identity{}, false, unavailable()
	}
	var reply struct {
		OK     bool `json:"ok"`
		Result struct {
			Bridge  bool      `json:"bridge"`
			Flow    *flowWire `json:"flow"`
			Process Identity  `json:"process"`
		} `json:"result"`
	}
	if json.Unmarshal(b, &reply) != nil || !reply.OK {
		return Identity{}, false, unavailable()
	}
	if !reply.Result.Bridge {
		return Identity{}, false, nil
	}
	f := reply.Result.Flow
	if f == nil || f.ID == 0 || f.Network != q.Network || !sameEndpoint(f.MidSource, q.Source) || !sameEndpoint(f.MidDestination, q.Destination) || !sameEndpoint(f.ControlSource, q.ControlSource) || !sameEndpoint(f.ControlDestination, q.ControlDestination) || !sameEndpoint(f.Destination, q.Target) {
		return Identity{}, false, unavailable()
	}
	id := reply.Result.Process
	if id.Status == "known" && (id.Name == "" || id.PID == 0 || id.Stamp == 0 || strings.ContainsAny(id.Name, "/\\")) {
		return Identity{}, false, unavailable()
	}
	source, e := netip.ParseAddrPort(f.Source)
	if e != nil || !source.IsValid() {
		return Identity{}, false, unavailable()
	}
	id.SourceAddr = source.String()
	id.InboundKind = "tun"
	return id, true, nil
}
