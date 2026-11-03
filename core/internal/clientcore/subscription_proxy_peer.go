package clientcore

import (
	"encoding/binary"
	"net/netip"
)

// Pure bounded table decoder shared with Windows API path and host regression tests.
func bootstrapPeerPIDTable(b []byte, ipv6 bool, local, peer netip.AddrPort) (uint32, error) {
	size := 24
	if ipv6 {
		size = 56
	}
	if len(b) < 4 {
		return 0, dl("proxy_connect", "proxy_identity_unknown")
	}
	count := int(binary.LittleEndian.Uint32(b))
	if count > (len(b)-4)/size {
		return 0, dl("proxy_connect", "proxy_identity_unknown")
	}
	found := uint32(0)
	matches := 0
	for i := 0; i < count; i++ {
		v := b[4+i*size : 4+(i+1)*size]
		var src, dst netip.Addr
		var sp, dp uint16
		var pid uint32
		if !ipv6 {
			if binary.LittleEndian.Uint32(v) != 5 {
				continue
			}
			src = netip.AddrFrom4([4]byte(v[4:8]))
			sp = binary.BigEndian.Uint16(v[8:10])
			dst = netip.AddrFrom4([4]byte(v[12:16]))
			dp = binary.BigEndian.Uint16(v[16:18])
			pid = binary.LittleEndian.Uint32(v[20:24])
		} else {
			if binary.LittleEndian.Uint32(v[48:52]) != 5 || binary.LittleEndian.Uint32(v[16:20]) != 0 || binary.LittleEndian.Uint32(v[40:44]) != 0 {
				continue
			}
			src = netip.AddrFrom16([16]byte(v[:16]))
			sp = binary.BigEndian.Uint16(v[20:22])
			dst = netip.AddrFrom16([16]byte(v[24:40]))
			dp = binary.BigEndian.Uint16(v[44:46])
			pid = binary.LittleEndian.Uint32(v[52:56])
		}
		if src.Unmap() == peer.Addr().Unmap() && sp == peer.Port() && dst.Unmap() == local.Addr().Unmap() && dp == local.Port() {
			matches++
			found = pid
		}
	}
	if matches != 1 || found == 0 {
		return 0, dl("proxy_connect", "proxy_identity_unknown")
	}
	return found, nil
}
func bootstrapPeerOwner(b []byte, ipv6 bool, local, peer netip.AddrPort, self uint32) error {
	pid, e := bootstrapPeerPIDTable(b, ipv6, local, peer)
	if e != nil {
		return e
	}
	if pid == self {
		return dl("proxy_connect", "self_loop")
	}
	return nil
}
