//go:build !windows

package clientegress

import (
	"context"
	"errors"
	"net/netip"
	"syscall"
)

const Supported = false

func platformBind(Options) func(string, syscall.RawConn) error {
	return func(string, syscall.RawConn) error { return errors.New("unsupported") }
}
func platformValidate(Options) error { return errors.New("unsupported") }

func platformDNSOwner(DNSEndpoint) error { return errors.New("unsupported") }

func platformSelectSource(o OwnerState, dest, configured netip.Addr) (netip.Addr, error) {
	return chooseSnapshotSource(o, dest, configured)
}
func platformConfirmSource(OwnerState, netip.Addr) error { return errors.New("unsupported") }

func platformPing(context.Context, OwnerState, netip.Addr, netip.Addr, uint8, uint8, bool, []byte) ([]byte, uint8, error) {
	return nil, 0, errors.New("unsupported")
}
