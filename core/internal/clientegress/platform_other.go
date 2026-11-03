//go:build !windows

package clientegress

import (
	"errors"
	"syscall"
)

const Supported = false

func platformBind(Options) func(string, syscall.RawConn) error {
	return func(string, syscall.RawConn) error { return errors.New("unsupported") }
}
func platformValidate(Options) error { return errors.New("unsupported") }
