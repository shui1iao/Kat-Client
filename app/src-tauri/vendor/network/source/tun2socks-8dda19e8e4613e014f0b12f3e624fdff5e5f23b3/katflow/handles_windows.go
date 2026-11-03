package katflow

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"syscall"
	"time"
	"unsafe"
)

var peek = windows.NewLazySystemDLL("kernel32.dll").NewProc("PeekNamedPipe")

func openHandles() error {
	for _, h := range []uint64{readHandle, writeHandle} {
		typ, err := windows.GetFileType(windows.Handle(h))
		if err != nil || typ != windows.FILE_TYPE_PIPE {
			return errors.New("flow handle is not a pipe")
		}
	}
	wire.read = os.NewFile(uintptr(readHandle), "kat-flow-ack")
	wire.write = os.NewFile(uintptr(writeHandle), "kat-flow-register")
	return nil
}
func readACK(deadline time.Time) error {
	for time.Now().Before(deadline) {
		var available uint32
		r, _, _ := peek.Call(uintptr(readHandle), 0, 0, 0, uintptr(unsafe.Pointer(&available)), 0)
		if r == 0 {
			return errors.New("flow ack pipe closed")
		}
		if available > 0 {
			b := []byte{0}
			n, err := wire.read.Read(b)
			if err == nil && n == 1 && b[0] == 1 {
				return nil
			}
			return errors.New("flow registration refused")
		}
		time.Sleep(time.Millisecond)
	}
	return syscall.ETIMEDOUT
}
