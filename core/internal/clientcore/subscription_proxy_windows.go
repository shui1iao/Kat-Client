//go:build windows

package clientcore

import (
	"encoding/binary"
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
