//go:build windows

package clientcore

import (
	"errors"
	"github.com/shui1iao/Kat/internal/userio"
	"os"

	"golang.org/x/sys/windows"
)

func openSubscriptionResource(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// Do not request WRITE_DAC/WRITE_OWNER or call secureFile: a readable shared
	// database is not ours to privatize. Inspect the opened leaf, not a separately
	// queried path which could have changed since the check.
	h, err := userio.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(h, &info)
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(h)
		return nil, errors.New("nonregular resource")
	}
	kind, err := windows.GetFileType(h)
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	if kind != windows.FILE_TYPE_DISK {
		windows.CloseHandle(h)
		return nil, errors.New("nonregular resource")
	}
	f := os.NewFile(uintptr(h), path)
	if f == nil {
		windows.CloseHandle(h)
		return nil, errors.New("cannot open resource")
	}
	return f, nil
}
