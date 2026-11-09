package procattr

import (
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/windows"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

var iphlp = windows.NewLazySystemDLL("iphlpapi.dll")
var tcpTable = iphlp.NewProc("GetExtendedTcpTable")
var udpTable = iphlp.NewProc("GetExtendedUdpTable")

// OWNER_PID ABI: TCP4 row=24, TCP6 row=56; UDP4 row=12, UDP6
// row=28; each table starts with a DWORD count. Ports are network order.
func ownerRows(ctx context.Context, q Query) ([]Row, string, uint32) {
	if ctx.Err() != nil {
		return nil, "unknown", 0
	}
	if !q.Source.IsValid() || q.Source.Port() == 0 || q.Source.Addr().IsUnspecified() || q.Source.Addr().Zone() != "" {
		return nil, "unsupported", 0
	}
	fam := uintptr(2)
	if q.Source.Addr().Is6() {
		fam = 23
	}
	proc := tcpTable
	class := uintptr(5)
	size := 24
	if fam == 23 {
		size = 56
	}
	if q.Network == "udp" {
		proc = udpTable
		class = 1
		size = 12
		if fam == 23 {
			size = 28
		}
	} else if q.Network != "tcp" {
		return nil, "unsupported", 0
	}
	if q.Network == "tcp" && (!q.Destination.IsValid() || q.Destination.Port() == 0 || q.Destination.Addr().IsUnspecified() || q.Destination.Addr().Zone() != "" || q.Source.Addr().Is4() != q.Destination.Addr().Is4()) {
		return nil, "unsupported", 0
	}
	var n uint32
	r, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&n)), 0, fam, class, 0)
	if r != 122 {
		return nil, "denied", uint32(r)
	}
	for tries := 0; tries < 3; tries++ {
		if ctx.Err() != nil {
			return nil, "unknown", 0
		}
		if n < 4 {
			return nil, "changed", 0
		}
		if n > 16<<20 {
			return nil, "unsupported", 0
		}
		alloc := n + uint32(16*size)
		if alloc < n || alloc > 16<<20 {
			alloc = 16 << 20
		}
		n = alloc
		b := make([]byte, n)
		r, _, _ = proc.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&n)), 0, fam, class, 0)
		if ctx.Err() != nil {
			return nil, "unknown", 0
		}
		if r == 122 {
			continue
		}
		if r != 0 {
			return nil, "denied", uint32(r)
		}
		if n < 4 || int(n) > len(b) {
			return nil, "changed", 0
		}
		b = b[:n]
		count := int(binary.LittleEndian.Uint32(b))
		if count > (len(b)-4)/size {
			return nil, "changed", 0
		}
		rows := make([]Row, 0, count)
		for i := 0; i < count; i++ {
			if i&255 == 0 && ctx.Err() != nil {
				return nil, "unknown", 0
			}
			v := b[4+i*size : 4+(i+1)*size]
			var src, dst netip.Addr
			var sp, dp uint16
			var pid uint32
			if fam == 2 {
				off := 0
				if q.Network == "tcp" {
					if binary.LittleEndian.Uint32(v) != 5 {
						continue
					}
					off = 4
				}
				src = netip.AddrFrom4([4]byte(v[off : off+4]))
				sp = binary.BigEndian.Uint16(v[off+4 : off+6])
				if q.Network == "tcp" {
					dst = netip.AddrFrom4([4]byte(v[12:16]))
					dp = binary.BigEndian.Uint16(v[16:18])
					pid = binary.LittleEndian.Uint32(v[20:24])
				} else {
					pid = binary.LittleEndian.Uint32(v[8:12])
				}
			} else {
				if binary.LittleEndian.Uint32(v[16:20]) != 0 {
					continue
				}
				src = netip.AddrFrom16([16]byte(v[:16]))
				sp = binary.BigEndian.Uint16(v[20:22])
				if q.Network == "tcp" {
					if binary.LittleEndian.Uint32(v[48:52]) != 5 || binary.LittleEndian.Uint32(v[40:44]) != 0 {
						continue
					}
					dst = netip.AddrFrom16([16]byte(v[24:40]))
					dp = binary.BigEndian.Uint16(v[44:46])
					pid = binary.LittleEndian.Uint32(v[52:56])
				} else {
					pid = binary.LittleEndian.Uint32(v[24:28])
				}
			}
			row := Row{Source: netip.AddrPortFrom(src.Unmap(), sp), PID: pid}
			if dst.IsValid() {
				row.Destination = netip.AddrPortFrom(dst.Unmap(), dp)
			}
			rows = append(rows, row)
		}
		return rows, "known", 0
	}
	return nil, "changed", 0
}
func stamp(h windows.Handle) (uint64, error) {
	var c, e, k, u windows.Filetime
	err := windows.GetProcessTimes(h, &c, &e, &k, &u)
	return uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime), err
}
func processRunning(h windows.Handle) bool {
	var c, e, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &e, &k, &u) != nil || e.LowDateTime != 0 || e.HighDateTime != 0 {
		return false
	}
	var code uint32
	return windows.GetExitCodeProcess(h, &code) == nil && code == 259
}
func nativeUnavailable(status string, code uint32) Identity {
	id := unavailableIdentity(status)
	if status == "denied" {
		id.Cause = "local_denied"
	}
	id.Win32 = code
	return id
}

func nativeDenied(err error) Identity {
	var code syscall.Errno
	_ = errors.As(err, &code)
	return nativeUnavailable("denied", uint32(code))
}

func lookupLocal(ctx context.Context, q Query) Identity {
	if ctx.Err() != nil {
		return unavailableIdentity("unknown")
	}
	// Reject a process created between the first snapshot and OpenProcess:
	// a recycled PID must not make a different process look like that owner.
	var started windows.Filetime
	windows.GetSystemTimeAsFileTime(&started)
	before := uint64(started.HighDateTime)<<32 | uint64(started.LowDateTime)
	var tableCode uint32
	id := resolveCurrent(q, func(q Query) ([]Row, string) {
		rows, status, code := ownerRows(ctx, q)
		tableCode = code
		return rows, status
	}, func(pid uint32) (Identity, func() bool, func()) {
		if ctx.Err() != nil {
			return unavailableIdentity("unknown"), nil, nil
		}
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			return nativeDenied(err), nil, nil
		}
		close := func() { windows.CloseHandle(h) }
		created, err := stamp(h)
		if err != nil {
			return nativeDenied(err), nil, close
		}
		if !processCreatedBefore(created, before) {
			return unavailableIdentity("changed"), nil, close
		}
		if !processRunning(h) {
			return unavailableIdentity("changed"), nil, close
		}
		b := make([]uint16, 32768)
		n := uint32(len(b))
		if err := windows.QueryFullProcessImageName(h, 0, &b[0], &n); err != nil {
			return nativeDenied(err), nil, close
		}
		if n == 0 || n > uint32(len(b)) {
			return unavailableIdentity("unknown"), nil, close
		}
		path := windows.UTF16ToString(b[:n])
		name := filepath.Base(path)
		if !filepath.IsAbs(path) || name == "" || name == "." || strings.ContainsAny(name, "/\\") {
			return unavailableIdentity("unknown"), nil, close
		}
		var session uint32
		if err := windows.ProcessIdToSessionId(pid, &session); err != nil {
			return nativeDenied(err), nil, close
		}
		valid := func() bool {
			now, err := stamp(h)
			return err == nil && processProofCurrent(created, now, processRunning(h)) && ctx.Err() == nil
		}
		return Identity{Name: name, Path: path, Status: "known", PID: pid, Stamp: created}, valid, close
	})
	if ctx.Err() != nil {
		return unavailableIdentity("unknown")
	}
	if id.Status != "known" && tableCode != 0 {
		return nativeUnavailable(id.Status, tableCode)
	}
	return id
}

func Lookup(ctx context.Context, q Query) Identity {
	control := Query{Network: "tcp", Source: q.ControlSource, Destination: q.ControlDestination}
	if !control.Source.IsValid() {
		control.Source, control.Destination = q.Source, q.Destination
	}
	rows, status, code := ownerRows(ctx, control)
	if status != "known" {
		return nativeUnavailable(status, code)
	}
	pid, status := unique(rows, control)
	if status != "known" {
		return unavailableIdentity(status)
	}
	if pid == uint32(os.Getpid()) {
		if id, ok := httpIdentity(ctx, q); ok && q.Network == "tcp" {
			return id
		}
		return unavailableIdentity("unknown")
	}
	ctl := lookupLocal(ctx, control)
	if q.Network == "tcp" && control.Source == q.Source && control.Destination == q.Destination {
		return ctl
	}
	return lookupLocal(ctx, Query{Network: q.Network, Source: q.Source, Destination: q.Destination})
}
