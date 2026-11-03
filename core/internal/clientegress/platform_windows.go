//go:build windows

package clientegress

import (
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/windows"
	"net"
	"syscall"
	"unsafe"
)

const Supported = true

func platformBind(o Options) func(string, syscall.RawConn) error {
	return func(network string, c syscall.RawConn) error {
		var setErr error
		e := c.Control(func(fd uintptr) {
			if network[len(network)-1] == '4' {
				if o.IPv4 == nil {
					setErr = errors.New("IPv4 interface unavailable")
					return
				}
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], *o.IPv4)
				index := binary.NativeEndian.Uint32(b[:])
				setErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31 /* IP_UNICAST_IF, ws2ipdef.h */, int(index))
			} else {
				if o.IPv6 == nil {
					setErr = errors.New("IPv6 interface unavailable")
					return
				}
				setErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, 31 /* IPV6_UNICAST_IF, ws2ipdef.h */, int(*o.IPv6))
			}
		})
		if e != nil {
			return e
		}
		return setErr
	}
}
func platformValidate(o Options) error {
	size := uint32(16 << 10)
	var buffer []byte
	var first *windows.IpAdapterAddresses
	complete := false
	for attempts := 0; attempts < 3; attempts++ {
		if size > 1<<20 {
			return errors.New("interface list exceeds limit")
		}
		buffer = make([]byte, size)
		first = (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		e := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER, 0, first, &size)
		if e == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if e != nil {
			return errors.New("cannot inspect physical interfaces")
		}
		complete = true
		break
	}
	if !complete {
		return errors.New("interface list changed during validation")
	}
	found4, found6 := o.IPv4 == nil, o.IPv6 == nil
	for a := first; a != nil; a = a.Next {
		if a.OperStatus != windows.IfOperStatusUp || a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		if o.IPv4 != nil && a.IfIndex == *o.IPv4 {
			found4 = true
		}
		if o.IPv6 != nil && a.Ipv6IfIndex == *o.IPv6 {
			found6 = true
		}
	}
	if !found4 || !found6 {
		return errors.New("physical interface unavailable")
	}
	// Validate socket options without remote packets. Family absent is accepted
	// only when no index was provided; any later remote use fails closed.
	for _, n := range []string{"udp4", "udp6"} {
		if n == "udp4" && o.IPv4 == nil || n == "udp6" && o.IPv6 == nil {
			continue
		}
		addr := "0.0.0.0:0"
		if n == "udp6" {
			addr = "[::]:0"
		}
		lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error { return platformBind(o)(n, c) }}
		c, e := lc.ListenPacket(context.Background(), n, addr)
		if e != nil {
			return errors.New("physical socket option unavailable")
		}
		c.Close()
	}
	return nil
}
