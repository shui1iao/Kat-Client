package tunstack

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestStage4UDPEncodeChecksumsAndMTU(t *testing.T) {
	for _, pair := range [][2]string{{"192.0.2.10:99", "198.18.0.1:4001"}, {"[2001:db8::10]:99", "[fd50::2]:4001"}} {
		for _, size := range []int{0, 19, 3001, 65507} {
			src, dst := netip.MustParseAddrPort(pair[0]), netip.MustParseAddrPort(pair[1])
			payload := bytes.Repeat([]byte{0x63}, size)
			frames, e := UDPReply(src, dst, payload, 0x1177)
			if e != nil {
				t.Fatal(e)
			}
			var udp []byte
			for i, p := range frames {
				if len(p) > MTU {
					t.Fatal("exceeds MTU")
				}
				if src.Addr().Is4() {
					if folded(sum16(p[:20])) != 0 || int(binary.BigEndian.Uint16(p[2:])) != len(p) {
						t.Fatal("IPv4 checksum/length")
					}
					if int(binary.BigEndian.Uint16(p[6:])&0x1fff)*8 != len(udp) {
						t.Fatal("v4 fragment offset")
					}
					udp = append(udp, p[20:]...)
				} else {
					off := 40
					if p[6] == 44 {
						off = 48
						if int(binary.BigEndian.Uint16(p[42:])&0xfff8) != len(udp) {
							t.Fatal("v6 fragment offset")
						}
					}
					udp = append(udp, p[off:]...)
				}
				_ = i
			}
			if !bytes.Equal(udp[8:], payload) || binary.BigEndian.Uint16(udp) != 99 || int(binary.BigEndian.Uint16(udp[4:])) != len(udp) {
				t.Fatal("UDP wire corrupted")
			}
			var pseudo []byte
			pseudo = append(pseudo, src.Addr().AsSlice()...)
			pseudo = append(pseudo, dst.Addr().AsSlice()...)
			if src.Addr().Is4() {
				pseudo = append(pseudo, 0, 17, byte(len(udp)>>8), byte(len(udp)))
			} else {
				pseudo = binary.BigEndian.AppendUint32(pseudo, uint32(len(udp)))
				pseudo = append(pseudo, 0, 0, 0, 17)
			}
			if folded(sum16(pseudo)+sum16(udp)) != 0 {
				t.Fatal("UDP pseudo checksum")
			}
		}
	}
	if _, e := UDPReply(netip.MustParseAddrPort("192.0.2.1:2"), netip.MustParseAddrPort("192.0.2.2:4"), make([]byte, 65508), 1); e == nil {
		t.Fatal("overlimit")
	}
}
