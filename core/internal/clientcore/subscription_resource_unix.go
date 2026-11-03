//go:build !windows

package clientcore

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

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
