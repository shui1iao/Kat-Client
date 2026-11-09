package tunplatform

import (
	"context"
	"github.com/shui1iao/Kat/internal/clientegress"
	"net/netip"
)

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
