//go:build windows

package kernel

import (
	"net"
	"syscall"
	"testing"
)

// Keep the actual socket-option assertion on both platforms, with the native
// descriptor type instead of excluding the Windows behavior test.
func ipv6Only(t *testing.T, c *net.UDPConn) int {
	t.Helper()
	raw, e := c.SyscallConn()
	if e != nil {
		t.Fatal(e)
	}
	var v int
	var ge error
	if e = raw.Control(func(fd uintptr) {
		v, ge = syscall.GetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY)
	}); e != nil || ge != nil {
		t.Fatal(e, ge)
	}
	return v
}
