package procattr

import (
	"context"
	"encoding/binary"
	"golang.org/x/sys/windows"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"unsafe"
)

var iphlp = windows.NewLazySystemDLL("iphlpapi.dll")
var tcpTable = iphlp.NewProc("GetExtendedTcpTable")
var udpTable = iphlp.NewProc("GetExtendedUdpTable")

func ownerRows(q Query) ([]Row, string) {
	if !q.Source.IsValid() || q.Source.Port() == 0 || q.Source.Addr().Zone() != "" {
		return nil, "unsupported"
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
		return nil, "unsupported"
	}
	var n uint32
	r, _, _ := proc.Call(0, uintptr(unsafe.Pointer(&n)), 0, fam, class, 0)
	if r != 122 || n < 4 || n > 16<<20 {
		return nil, "denied"
	}
	for tries := 0; tries < 3; tries++ {
		b := make([]byte, n)
		r, _, _ = proc.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&n)), 0, fam, class, 0)
		if r == 122 {
			if n > 16<<20 {
				return nil, "unsupported"
			}
			continue
		}
		if r != 0 {
			return nil, "denied"
		}
		if n < 4 || int(n) > len(b) {
			return nil, "changed"
		}
		b = b[:n]
		count := int(binary.LittleEndian.Uint32(b))
		if count > (len(b)-4)/size {
			return nil, "changed"
		}
		rows := make([]Row, 0, count)
		for i := 0; i < count; i++ {
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
		return rows, "known"
	}
	return nil, "changed"
}
func stamp(h windows.Handle) (uint64, error) {
	var c, e, k, u windows.Filetime
	err := windows.GetProcessTimes(h, &c, &e, &k, &u)
	return uint64(c.HighDateTime)<<32 | uint64(c.LowDateTime), err
}
func lookupLocal(ctx context.Context, q Query) Identity {
	if ctx.Err() != nil {
		return Identity{Status: "closed"}
	}
	return resolveCurrent(q, ownerRows, func(pid uint32) (Identity, func() bool, func()) {
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
		if err != nil {
			return Identity{PID: pid, Status: "denied"}, nil, nil
		}
		close := func() { windows.CloseHandle(h) }
		created, err := stamp(h)
		if err != nil {
			return Identity{PID: pid, Status: "denied"}, nil, close
		}
		b := make([]uint16, 32768)
		n := uint32(len(b))
		if windows.QueryFullProcessImageName(h, 0, &b[0], &n) != nil {
			return Identity{PID: pid, Status: "denied"}, nil, close
		}
		path := windows.UTF16ToString(b[:n])
		name := filepath.Base(path)
		if name == "" || strings.ContainsAny(name, "/\\") {
			return Identity{PID: pid, Status: "unknown"}, nil, close
		}
		var session uint32
		if windows.ProcessIdToSessionId(pid, &session) != nil {
			return Identity{PID: pid, Status: "denied"}, nil, close
		}
		valid := func() bool {
			now, err := stamp(h)
			wait, _ := windows.WaitForSingleObject(h, 0)
			return err == nil && now == created && wait == uint32(windows.WAIT_TIMEOUT) && ctx.Err() == nil
		}
		return Identity{Name: name, Path: path, Status: "known", PID: pid, Stamp: created}, valid, close
	})
}

func Lookup(ctx context.Context, q Query) Identity {
	control := Query{Network: "tcp", Source: q.ControlSource, Destination: q.ControlDestination}
	if !control.Source.IsValid() {
		control.Source, control.Destination = q.Source, q.Destination
	}
	rows, status := ownerRows(control)
	if status != "known" {
		return Identity{Status: status}
	}
	pid, status := unique(rows, control)
	if status != "known" {
		return Identity{Status: status}
	}
	if pid == uint32(os.Getpid()) {
		if id, ok := httpIdentity(ctx, q); ok && q.Network == "tcp" {
			return id
		}
		return Identity{Status: "unknown"}
	}
	ctl := lookupLocal(ctx, control)
	if ctl.Status == "denied" || strings.EqualFold(ctl.Name, "tun2socks.exe") {
		id, bridge, err := lookupService(ctx, q)
		if err != nil {
			return Identity{Status: "denied"}
		}
		if bridge {
			return id
		}
		if ctl.Status != "known" {
			return ctl
		}
		if strings.EqualFold(ctl.Name, "tun2socks.exe") {
			return Identity{Status: "unknown"}
		}
	}
	if q.Network == "tcp" && control.Source == q.Source && control.Destination == q.Destination {
		return ctl
	}
	return lookupLocal(ctx, Query{Network: q.Network, Source: q.Source, Destination: q.Destination})
}
