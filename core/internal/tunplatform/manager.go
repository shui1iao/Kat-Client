package tunplatform

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

type Manager struct {
	mu                                                        sync.Mutex
	config                                                    Config
	os                                                        osBackend
	life                                                      context.Context
	cancel                                                    context.CancelFunc
	planeCancel                                               context.CancelFunc
	wg                                                        sync.WaitGroup
	dev                                                       Device
	transferred                                               bool
	plane                                                     DataPlane
	journal                                                   *Journal
	physical                                                  Physical
	state                                                     Status
	events                                                    chan Event
	admission                                                 atomic.Bool
	epoch                                                     atomic.Uint64
	token                                                     uint64
	closed                                                    bool
	watchStarted                                              bool
	candidate                                                 *Physical
	candidateSince                                            time.Time
	cleanupWorker                                             bool
	cleanupStarted                                            time.Time
	removalFirst, removalFinal, removalPending, removalSecond bool
	pendingRequiresFinish                                     bool
}

func New(c Config) (*Manager, error) {
	if c.Broker == nil || c.Egress == nil || c.Start == nil {
		return nil, At("make_config", "TUN_CONFIG", errors.New("TUN_CONFIG"))
	}
	backend, e := platformOS(c.Launch)
	if e != nil {
		return nil, At("make_identity", "", e)
	}
	return newManager(c, backend), nil
}
func newManager(c Config, backend osBackend) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{config: c, os: backend, life: ctx, cancel: cancel, state: Status{State: "off", CleanupComplete: true, NetworkClear: true}, events: make(chan Event, 1)}
}
func (m *Manager) Status() Status       { m.mu.Lock(); defer m.mu.Unlock(); return m.state }
func (m *Manager) Events() <-chan Event { return m.events }
func (m *Manager) publish() {
	m.state.Epoch = m.epoch.Load()
	select {
	case m.events <- Event{m.state}:
	default:
		select {
		case <-m.events:
		default:
		}
		select {
		case m.events <- Event{m.state}:
		default:
		}
	}
}
func (m *Manager) flowContext() FlowContext {
	return FlowContext{Admitting: m.admission.Load, Epoch: m.epoch.Load, Physical: m.physical}
}
func physicalSafe(p Physical) error {
	if p.IPv4 == nil && p.IPv6 == nil {
		return errors.New("WAITING_NETWORK")
	}
	required := map[[2]uint64]bool{}
	for _, o := range []*FamilyOwner{p.IPv4, p.IPv6} {
		if o != nil {
			required[[2]uint64{o.LUID, uint64(o.Family)}] = true
		}
	}
	for _, d := range p.DNS {
		family := uint64(2)
		if stringsIsIPv6(d.Address) {
			family = 23
		}
		required[[2]uint64{d.Owner, family}] = true
	}
	for k := range required {
		found := false
		for _, o := range p.Owners {
			if o.LUID == k[0] && uint64(o.Family) == k[1] {
				found = true
				if !o.Up {
					return errors.New("EGRESS_BIND_UNSAFE")
				}
				usable := false
				for _, source := range o.Sources {
					if source.Usable {
						usable = true
						break
					}
				}
				if !usable {
					return errors.New("WAITING_NETWORK")
				}
			}
		}
		if !found {
			return errors.New("EGRESS_BIND_UNSAFE")
		}
	}
	return nil
}
func stringsIsIPv6(s string) bool {
	for _, v := range s {
		if v == ':' {
			return true
		}
	}
	return false
}
func (m *Manager) accept(s JournalState) error {
	if s.Journal == nil || s.Schema != JournalSchema || s.Engine != Engine || s.Epoch != m.config.Launch.Epoch || s.Journal.Launch.Epoch != m.config.Launch.Epoch {
		return errors.New("JOURNAL_IDENTITY")
	}
	copy := *s.Journal
	copy.Changes = append([]Change(nil), copy.Changes...)
	m.journal = &copy
	return nil
}
func (m *Manager) Prepare(ctx context.Context) (prepared Prepared, err error) {
	if e := m.awaitPending(ctx); e != nil {
		return prepared, e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.journal != nil || m.plane != nil {
		return prepared, At("prepare_guard", "TUN_BUSY", errors.New("TUN_BUSY"))
	}
	m.cleanupStarted = time.Time{}
	m.removalFirst, m.removalFinal, m.removalPending, m.removalSecond = false, false, false, false
	m.pendingRequiresFinish = false
	stage := "physical_snapshot"
	m.state = Status{Intent: true, State: "preparing", CleanupComplete: false}
	m.publish()
	defer func() {
		if err != nil {
			err = At(stage, "", err)
			d := Describe(stage, err)
			cleanup, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			waiting := d.Code == "WAITING_NETWORK"
			ce := m.disableLocked(cleanup, waiting)
			if waiting && ce == nil && m.state.CleanupComplete && !m.state.CleanupPending {
				m.state.Intent = true
				m.state.State = "waiting_network"
				m.state.Code = "WAITING_NETWORK"
				m.state.Failure = nil
				m.publish()
				return
			}
			if ce != nil && waiting {
				err = At("active_failure", "", ce)
				d = Describe("active_failure", err)
			}
			m.state.Intent = false
			m.state.Code = d.Code
			m.state.Failure = &d
			if ce != nil && !waiting {
				m.state.Code += "; CLEANUP_PENDING"
			}
			m.state.State = "error"
			m.publish()
		}
	}()
	physical, e := m.os.Snapshot(ctx, 0)
	if e != nil {
		return prepared, e
	}
	stage = "physical_policy"
	if e = physicalSafe(physical); e != nil {
		return prepared, e
	}
	stage = "journal_begin"
	s, e := m.config.Broker.Begin(ctx)
	if e != nil {
		return prepared, e
	}
	stage = "journal_accept"
	if e = m.accept(s); e != nil {
		return prepared, e
	}
	m.physical = physical
	m.epoch.Add(1)
	m.state.Generation++
	stage = "device_open"
	m.dev, e = m.os.Device(ctx, m.journal.Adapter)
	if e != nil {
		return prepared, e
	}
	a := m.journal.Adapter
	a.LUID = m.dev.LUID()
	stage = "device_identity"
	if a.LUID == 0 || m.dev.MTU() != MTU || m.dev.GUID() != a.GUID {
		return prepared, errors.New("TUN_DEVICE_IDENTITY")
	}
	// Bind the service-generated GUID/LUID before any setting mutation.
	stage = "device_bind"
	s, e = m.config.Broker.WriteAhead(ctx, m.journal.Seq, a, nil)
	if e != nil {
		return prepared, e
	}
	stage = "journal_accept"
	if e = m.accept(s); e != nil {
		return prepared, e
	}
	stage = "settings_install"
	if e = m.install(ctx, settingChanges()); e != nil {
		return prepared, e
	}
	if m.config.Egress != nil {
		stage = "egress_reconcile"
		if e = m.config.Egress.Reconcile(egressSnapshot(physical, m.state.Generation, m.epoch.Load())); e != nil {
			return prepared, e
		}
	}
	if !m.watchStarted {
		stage = "physical_watch"
		if e = m.startWatch(); e != nil {
			return prepared, e
		}
	}

	planeCtx, planeCancel := context.WithCancel(m.life)
	m.planeCancel = planeCancel
	stop := context.AfterFunc(ctx, planeCancel)
	m.transferred = true // from this call onward DATA owns final Close, even on error
	stage = "data_start"
	m.plane, e = m.config.Start(planeCtx, m.dev, m.flowContext())
	stop()
	if e != nil {
		return prepared, e
	}
	stage = "data_ready"
	if e = m.healthy(); e != nil {
		return prepared, e
	}
	m.token++
	m.state.State = "prepared"
	m.publish()
	m.watchFatal(m.plane)
	return Prepared{Token: m.token, Physical: m.physical}, nil
}
func (m *Manager) healthy() error {
	if m.plane == nil {
		return errors.New("DATA_NOT_READY")
	}
	if e := m.plane.Err(); e != nil {
		return e
	}
	select {
	case <-m.plane.Failed():
		return errors.New("DATA_FAILED")
	default:
	}
	select {
	case <-m.plane.Done():
		return errors.New("DATA_STOPPED")
	default:
	}
	return nil
}
func (m *Manager) watchFatal(p DataPlane) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		select {
		case <-m.life.Done():
			return
		case <-p.Failed():
		case <-p.Done():
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.plane != p || m.closed {
			return
		}
		cause := p.Err()
		if cause == nil {
			cause = errors.New("DATA_STOPPED")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		m.disableLocked(ctx, true)
		m.state.State = "error"
		m.state.Code = cause.Error()
		m.publish()
	}()
}
func (m *Manager) Commit(ctx context.Context, token uint64) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.journal == nil || token != m.token || m.state.State != "prepared" {
		return m.state, At("commit_guard", "TUN_PREPARED_STALE", errors.New("TUN_PREPARED_STALE"))
	}
	stage := "commit_health"
	e := m.healthy()
	if e == nil {
		var next Physical
		stage = "commit_snapshot"
		next, e = m.os.Snapshot(ctx, m.journal.Adapter.LUID)
		if e == nil {
			stage = "commit_policy"
			e = physicalSafe(next)
		}
		if e == nil && next.Options.Fingerprint != m.physical.Options.Fingerprint {
			if next.Options.Identity != m.physical.Options.Identity {
				m.epoch.Add(1)
			}
			m.physical = next
			m.state.Generation++
			if m.config.Egress != nil {
				stage = "commit_reconcile"
				e = m.config.Egress.Reconcile(egressSnapshot(next, m.state.Generation, m.epoch.Load()))
			}
		}
	}
	if e == nil {
		stage = "route_install"
		e = m.install(ctx, routeChanges())
	}
	if e == nil {
		stage = "commit_final_health"
		e = m.healthy()
	}
	if e != nil {
		e = At(stage, "", e)
		d := Describe(stage, e)
		cleanup, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		waiting := d.Code == "WAITING_NETWORK"
		ce := m.disableLocked(cleanup, waiting)
		if waiting && ce == nil && m.state.CleanupComplete && !m.state.CleanupPending {
			m.state.Intent = true
			m.state.State = "waiting_network"
			m.state.Code = "WAITING_NETWORK"
			m.state.Failure = nil
			m.publish()
			return m.state, e
		}
		if ce != nil && waiting {
			e = At("active_failure", "", ce)
			d = Describe("active_failure", e)
		}
		m.state.Intent = false
		m.state.State = "error"
		m.state.Code = d.Code
		m.state.Failure = &d
		if ce != nil && !waiting {
			m.state.Code += "; CLEANUP_PENDING"
		}
		m.publish()
		return m.state, e
	}
	m.admission.Store(true)
	m.state.Enabled = true
	m.state.State = "on"
	m.state.Code = ""
	m.state.Failure = nil
	m.state.CleanupComplete = false
	m.publish()
	return m.state, nil
}
func settingChanges() []Change {
	var c []Change
	for _, f := range []uint16{2, 23} {
		v := Value{Interface: &InterfaceValue{Family: f, MTU: MTU, Metric: 5, AutomaticMetric: false, DADTransmits: 0}}
		c = append(c, Change{ID: fmt.Sprint("interface:", f), Installed: v, Desired: true, State: "pending"})
	}
	for _, a := range []AddressValue{{Address: "198.18.0.1", Prefix: 30, PrefixOrigin: 1, SuffixOrigin: 1}, {Address: "fd4b:6174::1", Prefix: 126, PrefixOrigin: 1, SuffixOrigin: 1}} {
		v := a
		c = append(c, Change{ID: "address:" + a.Address, Installed: Value{Address: &v}, Desired: true, State: "pending"})
	}
	return append(c, Change{ID: "dns", Installed: Value{DNS: &DNSValue{Servers: "198.18.0.2"}}, Desired: true, State: "pending"})
}
func routeChanges() []Change {
	var c []Change
	for _, d := range []string{"0.0.0.0", "128.0.0.0", "::", "8000::"} {
		hop := "0.0.0.0"
		if stringsIsIPv6(d) {
			hop = "::"
		}
		v := Value{Route: &RouteValue{Destination: d, Prefix: 1, NextHop: hop, Metric: 5, Protocol: 3, ValidLifetime: ^uint32(0), PreferredLifetime: ^uint32(0)}}
		c = append(c, Change{ID: "route:" + d + "/1", Installed: v, Desired: true, State: "pending"})
	}
	return c
}
func (m *Manager) install(ctx context.Context, additional []Change) (err error) {
	stage := "os_read"
	defer func() { err = At(stage, "", err) }()
	all := append([]Change(nil), m.journal.Changes...)
	for _, c := range additional {
		exists := false
		for i, old := range all {
			if old.ID == c.ID {
				all[i].Desired = true
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		before, e := m.os.Read(ctx, m.journal.Adapter, c)
		if e != nil {
			return e
		}
		if (c.Installed.Route != nil || c.Installed.Address != nil) && before != nil {
			return errors.New("OS_RESOURCE_FOREIGN")
		}
		if (c.Installed.Interface != nil || c.Installed.DNS != nil) && before == nil {
			return errors.New("OWN_INTERFACE_NOT_READY")
		}
		c.Before = before
		all = append(all, c)
	}
	return m.transact(ctx, all)
}
func (m *Manager) transact(ctx context.Context, desired []Change) (err error) {
	stage := "wal_write"
	defer func() { err = At(stage, "", err) }()
	s, e := m.config.Broker.WriteAhead(ctx, m.journal.Seq, m.journal.Adapter, desired)
	if e != nil {
		return e
	}
	stage = "journal_accept"
	if e = m.accept(s); e != nil {
		return e
	}
	var observed []Observation
	var first error
	// Routes first during withdrawal. Stable sort keeps interface/address setup
	// ordering during prepare; all rows have already been durably written ahead.
	order := make([]Change, 0, len(desired))
	for _, c := range desired {
		if !c.Desired && c.Installed.Route != nil {
			order = append(order, c)
		}
	}
	for _, c := range desired {
		if c.Desired || c.Installed.Route == nil {
			order = append(order, c)
		}
	}
	for _, c := range order {
		stage = "os_read"
		gone, e := m.os.Gone(ctx, m.journal.Adapter)
		if e != nil {
			if first == nil {
				first = At(stage, "", e)
			}
			continue
		}
		if !c.Desired && gone && c.Installed.Route == nil {
			observed = append(observed, Observation{ID: c.ID, OwnerAbsent: true})
			continue
		}
		stage = "os_apply"
		if e = m.os.Apply(ctx, m.journal.Adapter, c); e != nil {
			if first == nil {
				first = At(stage, "", e)
			}
			continue
		}
		stage = "os_readback"
		v, e := m.os.Read(ctx, m.journal.Adapter, c)
		if e != nil {
			if first == nil {
				first = At(stage, "", e)
			}
			continue
		}
		observed = append(observed, Observation{ID: c.ID, Current: v})
	}
	if first != nil {
		return first
	}
	stage = "journal_commit"
	s, e = m.config.Broker.Commit(ctx, m.journal.Seq, observed)
	if e != nil {
		return e
	}
	stage = "journal_accept"
	return m.accept(s)
}
func (m *Manager) Disable(ctx context.Context) (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.disableLocked(ctx, false)
	return m.state, e
}
func (m *Manager) disableLocked(ctx context.Context, preserveIntent bool) error {
	m.state.NetworkClear = false
	m.admission.Store(false)
	if m.config.Egress != nil {
		m.config.Egress.FreezeNew()
	}
	m.state.Enabled = false
	m.state.Intent = preserveIntent && m.state.Intent
	m.token++
	if m.plane != nil {
		m.plane.Quiesce()
	}
	var first error
	if m.journal != nil && len(m.journal.Changes) > 0 {
		// A previous OFF may have committed every restoration before the
		// created adapter disappeared. Do not re-bind/re-WAL a completed
		// withdrawal: the service will still verify every row in Finish.
		withdraw := false
		for _, c := range m.journal.Changes {
			if c.Desired || c.State != "restored" {
				withdraw = true
				break
			}
		}
		if withdraw {
			desired := append([]Change(nil), m.journal.Changes...)
			for i := range desired {
				desired[i].Desired = false
			}
			first = m.transact(ctx, desired)
		}
	}
	if m.plane != nil {
		if e := m.plane.Close(ctx); e != nil {
			if first == nil {
				first = e
			}
		} else {
			m.plane = nil
		}
	} else if m.dev != nil && !m.transferred {
		if e := m.dev.Close(); e != nil && first == nil {
			first = e
		}
	}
	if m.planeCancel != nil {
		m.planeCancel()
		m.planeCancel = nil
	}
	if m.plane == nil {
		m.dev = nil
		m.transferred = false
	}
	finishAttempted := false
	if m.journal != nil && first == nil {
		first = m.validateWithdrawal()
		if first == nil {
			if m.pendingRequiresFinish && m.state.CleanupPending && m.cleanupWorker {
				first = m.waitAdapterGoneWithin(ctx, m.journal.Adapter, 0)
			} else {
				first = m.waitAdapterGone(ctx, m.journal.Adapter)
			}
		}
		if first == nil {
			first = m.verifyNetworkClear(ctx)
			if first != nil && first.Error() == "ADAPTER_REMAINS" {
				first = errNativePending
			}
		}
		if first == nil {
			finishAttempted = true
			first = m.finishOwnedLocked(ctx)
		}
	}
	if errors.Is(first, errNativePending) {
		m.pendingRequiresFinish = true
		m.state.CleanupPending = true
		m.state.CleanupComplete = false
		m.state.State = "off"
		m.state.Code = "RECOVERY_PENDING"
		m.state.Failure = nil
		if m.config.Egress != nil {
			m.config.Egress.ReleasePhysical()
		}
		m.startCleanupWorkerLocked()
		m.publish()
		return nil // OFF accepted, not network readiness or journal completion
	}
	// Preserve .31's proven-clear Finish-error fallback, except a pending cycle
	// MUST finish its original account before releasing the physical fence.
	clear := first == nil
	if finishAttempted && first != nil && !m.pendingRequiresFinish && m.journal != nil && m.plane == nil && m.dev == nil {
		clear = m.verifyNetworkClear(ctx) == nil
	}
	hasRouteChanges := false
	if m.journal != nil {
		for _, c := range m.journal.Changes {
			if c.Installed.Route != nil {
				hasRouteChanges = true
				break
			}
		}
	}
	m.state.NetworkClear = clear
	if (clear || !hasRouteChanges) && m.config.Egress != nil {
		m.config.Egress.ReleasePhysical()
	}
	if first == nil {
		m.pendingRequiresFinish = false
	}
	m.state.CleanupComplete = first == nil
	m.state.CleanupPending = first != nil && m.pendingRequiresFinish
	m.state.State = "off"
	if first != nil {
		m.state.State = "error"
		m.state.Code = first.Error()
		d := Describe("active_failure", first)
		m.state.Failure = &d
	} else {
		m.state.Code = ""
		m.state.Failure = nil
	}

	m.publish()
	return first
}

func (m *Manager) validateWithdrawal() error {
	j := m.journal
	if j == nil || j.Schema != JournalSchema || j.Engine != Engine || j.Launch != m.config.Launch || j.Seq == 0 || j.Phase != "active" && j.Phase != "complete" || j.Adapter.GUID == "" || j.Adapter.Compartment != 1 || len(j.Changes) > 0 && j.Adapter.LUID == 0 {
		return errors.New("JOURNAL_IDENTITY")
	}
	known := append(settingChanges(), routeChanges()...)
	seen := map[string]bool{}
	for _, c := range j.Changes {
		if c.Desired || c.State != "restored" {
			return errors.New("RECOVERY_PENDING")
		}
		if seen[c.ID] {
			return errors.New("JOURNAL_FIELDS")
		}
		seen[c.ID] = true
		valid := false
		for _, k := range known {
			if c.ID == k.ID && reflect.DeepEqual(c.Installed, k.Installed) {
				valid = true
				break
			}
		}
		if !valid {
			return errors.New("JOURNAL_FIELDS")
		}
	}
	return nil
}

// A broker-accepted journal is scoped to this exact launch, never an alias
// search. It can only describe our fixed virtual settings and split routes.
// Virtual DNS is configured on j.Adapter only; no physical DNS is changed.
func (m *Manager) verifyNetworkClear(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if e := m.validateWithdrawal(); e != nil {
		return e
	}
	j := m.journal
	r, e := m.inspectRemoval(ctx, j.Adapter)
	if e != nil {
		return e
	}
	if !r.Gone {
		if !m.removalSecond {
			m.removalSecond = true
			m.observeRemoval(r, "second_check")
		}
		return errors.New("ADAPTER_REMAINS")
	}
	for _, c := range j.Changes {
		if c.Installed.Route == nil {
			continue
		}
		// Read uses GetIpForwardEntry2 with the recorded LUID and route key.
		// Only ERROR_NOT_FOUND is absence, not query error or changed contents.
		v, e := m.os.Read(ctx, j.Adapter, c)
		if e != nil {
			return e
		}
		if v != nil {
			return errors.New("RECOVERY_PENDING")
		}
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	return nil
}

func (m *Manager) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	m.mu.Lock()
	if m.closed {
		pending := !m.state.CleanupComplete
		m.mu.Unlock()
		if pending {
			return errors.New("RECOVERY_PENDING")
		}
		return nil
	}
	e := m.disableLocked(ctx, false)
	if e == nil && !m.state.CleanupComplete {
		e = errors.New("RECOVERY_PENDING")
	}
	if e != nil {
		m.mu.Unlock()
		return e
	}
	m.closed = true
	m.cancel()
	m.mu.Unlock()
	m.wg.Wait()
	return e
}
