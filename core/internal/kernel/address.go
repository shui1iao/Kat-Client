package kernel

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type Address struct {
	Host string
	Port uint16
}

func (a Address) String() string { return net.JoinHostPort(a.Host, strconv.Itoa(int(a.Port))) }
func readN(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	_, e := io.ReadFull(r, b)
	return b, e
}
func readHost(r io.Reader) (Address, error) {
	var a Address
	b, e := readN(r, 1)
	if e != nil {
		return a, e
	}
	t := b[0]
	var raw []byte
	switch t {
	case 1:
		raw, e = readN(r, 4)
		if e == nil {
			a.Host = net.IP(raw).String()
		}
	case 4:
		raw, e = readN(r, 16)
		if e == nil {
			a.Host = net.IP(raw).String()
		}
	case 3:
		n, err := readN(r, 1)
		if err != nil {
			return a, err
		}
		if n[0] == 0 {
			return a, errors.New("empty domain")
		}
		raw, e = readN(r, int(n[0]))
		if e == nil {
			a.Host = string(raw)
			if strings.ContainsAny(a.Host, "\x00\r\n :/\\") {
				return a, errors.New("invalid domain")
			}
		}
	default:
		return a, errors.New("unsupported address type")
	}
	return a, e
}
func appendAddress(b []byte, a Address) []byte {
	ip, e := netip.ParseAddr(a.Host)
	if e == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			b = append(b, 1)
			x := ip.As4()
			b = append(b, x[:]...)
		} else {
			t := byte(4)
			b = append(b, t)
			x := ip.As16()
			b = append(b, x[:]...)
		}
	} else {
		t := byte(3)
		b = append(b, t, byte(len(a.Host)))
		b = append(b, a.Host...)
	}
	return binary.BigEndian.AppendUint16(b, a.Port)
}
func addrFromNet(a net.Addr) Address {
	h, p, _ := net.SplitHostPort(a.String())
	n, _ := strconv.Atoi(p)
	return Address{h, uint16(n)}
}
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func readAddress(r io.Reader) (Address, error) {
	a, e := readHost(r)
	if e != nil {
		return a, e
	}
	b, e := readN(r, 2)
	if e != nil {
		return a, e
	}
	a.Port = binary.BigEndian.Uint16(b)
	return a, nil
}

func parseAddressBytes(b []byte, cacheIP4 *[4]byte, cacheStr *string, cacheInit *bool) (Address, int, error) {
	if len(b) < 4 {
		return Address{}, 0, io.ErrUnexpectedEOF
	}
	var a Address
	var off int
	switch b[0] {
	case 1:
		if len(b) < 7 {
			return Address{}, 0, io.ErrUnexpectedEOF
		}
		var ip4 [4]byte
		copy(ip4[:], b[1:5])
		if cacheIP4 != nil && cacheStr != nil && cacheInit != nil {
			if !*cacheInit || ip4 != *cacheIP4 {
				*cacheIP4 = ip4
				*cacheStr = netip.AddrFrom4(ip4).String()
				*cacheInit = true
			}
			a.Host = *cacheStr
		} else {
			a.Host = netip.AddrFrom4(ip4).String()
		}
		off = 5
	case 4:
		if len(b) < 19 {
			return Address{}, 0, io.ErrUnexpectedEOF
		}
		var ip16 [16]byte
		copy(ip16[:], b[1:17])
		a.Host = netip.AddrFrom16(ip16).Unmap().String()
		off = 17
	case 3:
		n := int(b[1])
		if n == 0 {
			return Address{}, 0, errors.New("empty domain")
		}
		if len(b) < 2+n+2 {
			return Address{}, 0, io.ErrUnexpectedEOF
		}
		a.Host = string(b[2 : 2+n])
		if strings.ContainsAny(a.Host, "\x00\r\n :/\\") {
			return Address{}, 0, errors.New("invalid domain")
		}
		off = 2 + n
	default:
		return Address{}, 0, errors.New("unsupported address type")
	}
	a.Port = binary.BigEndian.Uint16(b[off : off+2])
	return a, off + 2, nil
}
