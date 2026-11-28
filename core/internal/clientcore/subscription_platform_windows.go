//go:build windows

package clientcore

import (
	"encoding/binary"
	"errors"
	"github.com/shui1iao/Kat/internal/userio"
	"golang.org/x/sys/windows"
	"net"
	"net/netip"
	"os"
	"unsafe"
)

var bootstrapTCPTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

// Exact reverse established tuple: no process handles/privileges, names, or token rights.
func bootstrapPeerPID(c net.Conn) (uint32, error) {
	local, e := netip.ParseAddrPort(c.LocalAddr().String())
	if e != nil {
		return 0, dl("proxy_connect", "proxy_identity_unknown")
	}
	peer, e := netip.ParseAddrPort(c.RemoteAddr().String())
	if e != nil {
		return 0, dl("proxy_connect", "proxy_identity_unknown")
	}
	family, size := uintptr(2), 24
	if peer.Addr().Is6() {
		family = 23
		size = 56
	}
	var n uint32
	r, _, _ := bootstrapTCPTable.Call(0, uintptr(unsafe.Pointer(&n)), 0, family, 5, 0)
	if r != 122 || n < 4 || n > 16<<20 {
		return 0, dl("proxy_connect", "proxy_identity_unknown")
	}
	for tries := 0; tries < 3; tries++ {
		b := make([]byte, n)
		r, _, _ = bootstrapTCPTable.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&n)), 0, family, 5, 0)
		if r == 122 {
			if n > 16<<20 {
				return 0, dl("proxy_connect", "proxy_identity_unknown")
			}
			continue
		}
		if r != 0 || n < 4 || int(n) > len(b) {
			return 0, dl("proxy_connect", "proxy_identity_unknown")
		}
		b = b[:n]
		count := int(binary.LittleEndian.Uint32(b))
		if count > (len(b)-4)/size {
			return 0, dl("proxy_connect", "proxy_identity_unknown")
		}
		return bootstrapPeerPIDTable(b, family == 23, local, peer)
	}
	return 0, dl("proxy_connect", "proxy_identity_unknown")
}

func verifyBootstrapPeer(c net.Conn) error {
	pid, e := bootstrapPeerPID(c)
	if e != nil {
		return e
	}
	if pid == uint32(os.Getpid()) {
		return dl("proxy_connect", "self_loop")
	}
	return nil
}

func openSubscriptionResource(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// Do not request WRITE_DAC/WRITE_OWNER or call secureFile: a readable shared
	// database is not ours to privatize. Inspect the opened leaf, not a separately
	// queried path which could have changed since the check.
	h, err := userio.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(h, &info)
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(h)
		return nil, errors.New("nonregular resource")
	}
	kind, err := windows.GetFileType(h)
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	if kind != windows.FILE_TYPE_DISK {
		windows.CloseHandle(h)
		return nil, errors.New("nonregular resource")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return nil, errors.New("cannot open resource")
	}
	return f, nil
}
