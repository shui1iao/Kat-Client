package procattr

import (
	"context"
	"errors"
	"golang.org/x/sys/windows"
	"runtime"
	"strings"
	"time"
	"unsafe"
)

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
	if e := windows.QueryFullProcessImageName(h, 0, &image[0], &size); e != nil || !strings.EqualFold(strings.TrimPrefix(windows.UTF16ToString(image[:size]), `\?\`), strings.TrimPrefix(expected, `\?\`)) {
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
