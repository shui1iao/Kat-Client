//go:build !windows

package clientcore

import (
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"os"
)

// No production non-Windows system-proxy discovery exists. Tests use an explicit seam below.
func verifyBootstrapPeer(c net.Conn) error { return dl("proxy_connect", "proxy_identity_unknown") }

func openSubscriptionResource(path string) (*os.File, error) {
	// NONBLOCK also prevents a raced-in FIFO from hanging before the caller's
	// opened-handle regular-file check. No write or permission-changing access.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		unix.Close(fd)
		return nil, errors.New("cannot open resource")
	}
	return f, nil
}
