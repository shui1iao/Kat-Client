package tunplatform

import (
	"context"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/clientegress"
	"io"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	wintunErrorBufferOverflow syscall.Errno = 111
	wintunAllocateRetryLimit                = 8
	wintunAllocateWaitMS                    = 1
	wintunAllocateMaxWait                   = 8 * time.Millisecond
)

// ErrWintunRingFull identifies Wintun send-ring allocation exhaustion after bounded retry.
var ErrWintunRingFull = errors.New("wintun send ring full")

type WintunRingFullError struct {
	Cause syscall.Errno
}

func (e *WintunRingFullError) Error() string {
	if e == nil {
		return "WINTUN_ALLOCATE"
	}
	return fmt.Sprintf("WINTUN_ALLOCATE: %v", e.Cause)
}
func (e *WintunRingFullError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}
func (e *WintunRingFullError) Is(target error) bool {
	return target == ErrWintunRingFull
}
func (e *WintunRingFullError) WintunRingFull() bool {
	return e != nil && e.Cause == wintunErrorBufferOverflow
}

func retryWintunWrite(
	b []byte,
	firstErrno syscall.Errno,
	closed *atomic.Bool,
	now func() time.Time,
	waitStop func() error,
	allocate func(int) (uintptr, syscall.Errno),
	send func(uintptr, []byte),
) error {
	errno := firstErrno
	var deadline time.Time
	for attempt := 0; ; attempt++ {
		if errno != wintunErrorBufferOverflow {
			return fmt.Errorf("WINTUN_ALLOCATE: %w", errno)
		}
		if attempt >= wintunAllocateRetryLimit {
			return &WintunRingFullError{Cause: errno}
		}
		at := now()
		if attempt == 0 {
			deadline = at.Add(wintunAllocateMaxWait)
		} else if !at.Before(deadline) {
			return &WintunRingFullError{Cause: errno}
		}
		if err := waitStop(); err != nil {
			return err
		}
		if closed.Load() {
			return io.ErrClosedPipe
		}
		p, nextErrno := allocate(len(b))
		if p != 0 {
			send(p, b)
			return nil
		}
		errno = nextErrno
	}
}

type Device interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) error
	Close() error
	MTU() int
	LUID() uint64
	GUID() string
}
type DataPlane interface {
	Quiesce()
	Resume() error
	Failed() <-chan struct{}
	Err() error
	Done() <-chan struct{}
	Close(context.Context) error
}
type FlowContext struct {
	Admitting func() bool
	Epoch     func() uint64
	Physical  Physical
}
type StartDataPlane func(context.Context, Device, FlowContext) (DataPlane, error)
type Source struct {
	Address netip.Addr
	Scope   uint32
	Usable  bool
}
type FamilyOwner struct {
	Family                                 uint16
	LUID                                   uint64
	IfIndex                                uint32
	GUID                                   string
	Up, Hardware, Forwarding, WeakHostSend bool
	Sources                                []Source
}
type Physical struct {
	Generation uint64
	IPv4, IPv6 *FamilyOwner
	Owners     []FamilyOwner
	DNS        []clientegress.DNSEndpoint
	Options    clientegress.Options
}
type Config struct {
	Launch  Launch
	Broker  Broker
	Egress  *clientegress.Switch
	Start   StartDataPlane
	Observe func(Diagnostic) // fixed native metadata only; never changes cleanup permission
}
type Prepared struct {
	Token    uint64
	Physical Physical
}
type Status struct {
	Intent          bool        `json:"intent"`
	Enabled         bool        `json:"enabled"`
	State           string      `json:"state"`
	Code            string      `json:"code,omitempty"`
	Failure         *Diagnostic `json:"failure,omitempty"`
	Epoch           uint64      `json:"epoch"`
	Generation      uint64      `json:"generation"`
	CleanupComplete bool        `json:"cleanup_complete"`
	CleanupPending  bool        `json:"cleanup_pending"`
	NetworkClear    bool        `json:"network_clear"` // native resource evidence, NOT journal completion
}
type Event struct{ Status Status }
type osBackend interface {
	Device(context.Context, Adapter) (Device, error)
	Snapshot(context.Context, uint64) (Physical, error)
	Read(context.Context, Adapter, Change) (*Value, error)
	Apply(context.Context, Adapter, Change) error
	Gone(context.Context, Adapter) (bool, error)
	InspectGone(context.Context, Adapter) (GoneRead, error)
	Watch(context.Context) (<-chan struct{}, error)
}
