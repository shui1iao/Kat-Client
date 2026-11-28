//go:build linux

package kernel

import (
	"net"

	"golang.org/x/sys/unix"
)

func unwrapTCPConn(c net.Conn) *net.TCPConn {
	for c != nil {
		if tc, ok := c.(*net.TCPConn); ok {
			return tc
		}
		switch w := c.(type) {
		case *activityStream:
			c = w.Conn
		case *sniffedConn:
			c = w.Conn
		case *directDialConn:
			c = w.Conn
		case interface{ NetConn() net.Conn }:
			c = w.NetConn()
		default:
			return nil
		}
	}
	return nil
}

func tcpConnProgress(c net.Conn) (uint64, bool) {
	tc := unwrapTCPConn(c)
	if tc == nil {
		return 0, false
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var info *unix.TCPInfo
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		info, gerr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil || gerr != nil || info == nil {
		return 0, false
	}
	return info.Bytes_received + info.Bytes_acked, true
}

func tcpPairProgress(a, b net.Conn) (uint64, bool) {
	pa, oka := tcpConnProgress(a)
	pb, okb := tcpConnProgress(b)
	if !oka && !okb {
		return 0, false
	}
	return pa + pb, true
}
