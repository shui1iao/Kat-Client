package procattr

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"net/netip"
	"os"
	"runtime"
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
		return 0, 0, 0, 0, attributionError("scm", err)
	}
	defer windows.CloseServiceHandle(m)
	name, _ := windows.UTF16PtrFromString("KatClientNetwork")
	s, err := windows.OpenService(m, name, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return 0, 0, 0, 0, attributionError("scm", err)
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
	if e := windows.QueryServiceConfig(s, cfg, n, &n); e != nil {
		return 0, 0, 0, 0, attributionError("scm", e)
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
		return 0, 0, 0, 0, attributionError("scm", err)
	}
	valid := false
	defer func() {
		if !valid {
			windows.CloseHandle(h)
		}
	}()
	var token windows.Token
	if e := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); e != nil {
		return 0, 0, 0, 0, attributionError("scm", e)
	}
	user, err := token.GetTokenUser()
	token.Close()
	if err != nil || user.User.Sid.String() != "S-1-5-18" {
		return 0, 0, 0, 0, unavailable()
	}
	var session uint32
	if e := windows.ProcessIdToSessionId(st.ProcessId, &session); e != nil || session != 0 {
		return 0, 0, 0, 0, attributionError("scm", e)
	}
	image := make([]uint16, 32768)
	size := uint32(len(image))
	if e := windows.QueryFullProcessImageName(h, 0, &image[0], &size); e != nil || !strings.EqualFold(strings.TrimPrefix(windows.UTF16ToString(image[:size]), `\\?\`), strings.TrimPrefix(expected, `\\?\`)) {
		return 0, 0, 0, 0, attributionError("scm", e)
	}
	stamp, err := stamp(h)
	if err != nil {
		return 0, 0, 0, 0, attributionError("scm", err)
	}
	valid = true
	ok = true
	return s, h, stamp, st.ProcessId, nil
}
func pipeTransfer(ctx context.Context, h windows.Handle, b []byte, write bool) error {
	var pins runtime.Pinner
	defer pins.Unpin()
	for len(b) > 0 {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		event, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			return err
		}
		ov := windows.Overlapped{HEvent: event}
		var n uint32
		// Windows may retain these addresses after the syscall returns with
		// IO_PENDING. Keep them fixed until completion (including cancel/reap);
		// syscall-call liveness alone does not cover that asynchronous interval.
		pins.Pin(&ov)
		pins.Pin(&n)
		pins.Pin(&b[0])
		if write {
			err = windows.WriteFile(h, b, &n, &ov)
		} else {
			err = windows.ReadFile(h, b, &n, &ov)
		}
		if err == windows.ERROR_IO_PENDING {
			for {
				wait, waitErr := windows.WaitForSingleObject(event, 25)
				if wait == windows.WAIT_OBJECT_0 {
					err = windows.GetOverlappedResult(h, &ov, &n, false)
					if err != windows.ERROR_IO_INCOMPLETE {
						break
					}
					// Event observation is not terminal completion. Keep the
					// buffer/OVERLAPPED alive; context cancellation still reaps.
					if ctx.Err() != nil {
						_ = windows.CancelIoEx(h, &ov)
						_ = windows.GetOverlappedResult(h, &ov, &n, true)
						err = ctx.Err()
						break
					}
					time.Sleep(time.Millisecond)
					continue
				}
				if wait != uint32(windows.WAIT_TIMEOUT) || ctx.Err() != nil {
					windows.CancelIoEx(h, &ov)
					_ = windows.GetOverlappedResult(h, &ov, &n, true)
					err = ctx.Err()
					if err == nil {
						err = waitErr
					}
					if err == nil {
						err = unavailable()
					}
					break
				}
			}
		}
		windows.CloseHandle(event)
		pins.Unpin()
		if err != nil {
			return err
		}
		if n == 0 {
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
func trustedRequest(ctx context.Context, request any, consume func(json.RawMessage) error) (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		return nil, unavailable()
	}
	expected, release, err := pinInstallation(exe)
	if err != nil {
		return nil, err
	}
	defer release()
	s, process, created, pid, err := checkedService(expected)
	if err != nil {
		return nil, err
	}
	defer windows.CloseServiceHandle(s)
	defer windows.CloseHandle(process)
	h, err := openTrustedPipe(ctx, `\\.\pipe\KatClientNetwork-v1`)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	var server uint32
	if windows.GetNamedPipeServerProcessId(h, &server) != nil || server != pid {
		return nil, unavailable()
	}
	now, err := stamp(process)
	wait, _ := windows.WaitForSingleObject(process, 0)
	st, stateErr := serviceState(s)
	if err != nil || stateErr != nil || !trustedService(servicePeer{scmPID: st.ProcessId, pipePID: server, before: created, after: now, systemSID: "S-1-5-18", session: 0, image: "checked installed service", expected: "checked installed service", running: st.CurrentState == windows.SERVICE_RUNNING, alive: wait == uint32(windows.WAIT_TIMEOUT)}) {
		return nil, unavailable()
	}
	b, err := json.Marshal(request)
	if err != nil {
		return nil, unavailable()
	}
	frame := make([]byte, 4+len(b))
	binary.LittleEndian.PutUint32(frame, uint32(len(b)))
	copy(frame[4:], b)
	if pipeTransfer(ctx, h, frame, true) != nil {
		return nil, unavailable()
	}
	lenbuf := make([]byte, 4)
	if pipeTransfer(ctx, h, lenbuf, false) != nil {
		return nil, unavailable()
	}
	n := binary.LittleEndian.Uint32(lenbuf)
	if n == 0 || n > 32768 {
		return nil, unavailable()
	}
	b = make([]byte, n)
	if pipeTransfer(ctx, h, b, false) != nil {
		return nil, unavailable()
	}
	var envelope struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code string `json:"code"`
		} `json:"error,omitempty"`
	}
	if json.Unmarshal(b, &envelope) != nil {
		return nil, unavailable()
	}
	if !envelope.OK {
		if envelope.Error != nil && (envelope.Error.Code == "EGRESS_CHANGED" || envelope.Error.Code == "DNS_REVISION") {
			return nil, ErrRevisionChanged
		}
		return nil, unavailable()
	}
	if consume != nil {
		if err := consume(envelope.Result); err != nil {
			return nil, err
		}
	}
	return envelope.Result, nil
}

// TrustedDNSRevision accepts identifiers only. Endpoints come from the pinned
// SYSTEM service and its current installed-core lease, never from GUI input.
func TrustedDNSRevision(ctx context.Context, revision uint64, fingerprint string) (json.RawMessage, error) {
	return trustedRequest(ctx, map[string]any{"action": "lookup_dns_revision", "schema": 3, "revision": revision, "fingerprint": fingerprint}, nil)
}
func decodeServiceFlow(result json.RawMessage, q Query) (Identity, bool, error) {
	var checked struct {
		Bridge  bool      `json:"bridge"`
		Flow    *flowWire `json:"flow"`
		Process *struct {
			Name   string `json:"name"`
			Path   string `json:"path"`
			Status string `json:"status"`
			PID    uint32 `json:"pid"`
			Stamp  uint64 `json:"stamp"`
			Cause  string `json:"cause,omitempty"`
			Win32  uint32 `json:"win32,omitempty"`
		} `json:"process"`
	}
	if !requiredKeys(result, []string{"bridge", "flow", "process"}) || strictJSON(result, &checked) != nil {
		return Identity{}, false, unavailable()
	}
	if checked.Bridge != (checked.Flow != nil) || checked.Bridge != (checked.Process != nil) {
		return Identity{}, false, unavailable()
	}
	if checked.Process != nil {
		p := checked.Process
		switch p.Status {
		case "known":
			if p.Cause != "" || p.Win32 != 0 {
				return Identity{}, false, unavailable()
			}
		case "denied", "closed", "changed", "ambiguous", "unknown", "unsupported":
			if SafeCause(p.Cause) != p.Cause || p.Cause != "process:"+p.Status {
				return Identity{}, false, unavailable()
			}
		default:
			return Identity{}, false, unavailable()
		}
	}

	b, err := json.Marshal(struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
	}{true, result})
	if err != nil {
		return Identity{}, false, err
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
	if checked.Process != nil {
		id.Cause = checked.Process.Cause
		id.Win32 = checked.Process.Win32
	}
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

// Name-window/busy races do not become immediate denial. Context is the sole
// total deadline; only the two retryable Win32 results are retried.
func openTrustedPipe(ctx context.Context, path string) (windows.Handle, error) {
	name, _ := windows.UTF16PtrFromString(path)
	for {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		h, e := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED|0x100000|0x10000, 0)
		if e == nil {
			return h, nil
		}
		if e != windows.ERROR_PIPE_BUSY && e != windows.ERROR_FILE_NOT_FOUND {
			return 0, e
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}
