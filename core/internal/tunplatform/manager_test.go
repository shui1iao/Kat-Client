package tunplatform

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeDevice struct {
	os     *fakeOS
	closes int
}

func (d *fakeDevice) ReadPacket([]byte) (int, error) { return 0, errors.New("unused") }
func (d *fakeDevice) WritePacket([]byte) error       { return nil }
func (d *fakeDevice) MTU() int                       { return MTU }
func (d *fakeDevice) LUID() uint64                   { return 7 }
func (d *fakeDevice) GUID() string                   { return "11111111-1111-1111-1111-111111111111" }
func (d *fakeDevice) Close() error {
	d.closes++
	d.os.log = append(d.os.log, "device.close")
	d.os.gone = true
	d.os.rows = map[string]*Value{}
	return nil
}

type fakePlane struct {
	os           *fakeOS
	dev          Device
	failed, done chan struct{}
	err          error
	closed       bool
}

func (p *fakePlane) Quiesce()                { p.os.log = append(p.os.log, "quiesce") }
func (p *fakePlane) Resume() error           { return p.err }
func (p *fakePlane) Failed() <-chan struct{} { return p.failed }
func (p *fakePlane) Done() <-chan struct{}   { return p.done }
func (p *fakePlane) Err() error              { return p.err }
func (p *fakePlane) Close(context.Context) error {
	p.os.log = append(p.os.log, "plane.close")
	if !p.closed {
		p.closed = true
		close(p.done)
		return p.dev.Close()
	}
	return nil
}

type fakeOS struct {
	log       []string
	rows      map[string]*Value
	gone      bool
	dev       *fakeDevice
	fail      string
	goneQuery func(context.Context, Adapter) (bool, error)
	readQuery func(Adapter, Change) (*Value, error)
}

func (o *fakeOS) Device(_ context.Context, _ Adapter) (Device, error) {
	o.log = append(o.log, "device.create")
	o.gone = false
	o.dev = &fakeDevice{os: o}
	return o.dev, nil
}
func (o *fakeOS) Snapshot(context.Context, uint64) (Physical, error) {
	o.log = append(o.log, "snapshot")
	owner := FamilyOwner{Family: 2, LUID: 19, IfIndex: 3, Up: true, Hardware: true, Sources: []Source{{Address: netip.MustParseAddr("192.0.2.9"), Usable: true}}}
	return Physical{IPv4: &owner, Owners: []FamilyOwner{owner}}, nil
}
func (o *fakeOS) Read(_ context.Context, a Adapter, c Change) (*Value, error) {
	if o.readQuery != nil {
		return o.readQuery(a, c)
	}
	o.log = append(o.log, "read:"+c.ID)
	if o.gone {
		return nil, nil
	}
	return o.rows[c.ID], nil
}
func (o *fakeOS) Apply(_ context.Context, _ Adapter, c Change) error {
	o.log = append(o.log, "apply:"+c.ID+":"+boolString(c.Desired))
	if c.ID == o.fail {
		return errors.New("injected OS failure")
	}
	if c.Desired {
		v := c.Installed
		o.rows[c.ID] = &v
	} else {
		if reflect.DeepEqual(o.rows[c.ID], &c.Installed) || reflect.DeepEqual(o.rows[c.ID], c.Before) {
			o.rows[c.ID] = c.Before
		} else {
			return errors.New("RECOVERY_CONFLICT")
		}
	}
	return nil
}
func (o *fakeOS) Gone(ctx context.Context, a Adapter) (bool, error) {
	if o.goneQuery != nil {
		return o.goneQuery(ctx, a)
	}
	return o.gone, nil
}
func (o *fakeOS) InspectGone(ctx context.Context, a Adapter) (GoneRead, error) {
	if e := ctx.Err(); e != nil {
		return GoneRead{Rows: []GoneRow{}}, e
	}
	gone, e := o.Gone(ctx, a)
	r := GoneRead{Gone: gone, Rows: []GoneRow{}}
	if e == nil {
		z := uint32(0)
		r.RC = &z
		if !gone {
			r.Rows = []GoneRow{{GUID: a.GUID, LUID: fmt.Sprint(a.LUID), OperStatus: 1}}
		}
	}
	return r, e
}
func (o *fakeOS) Watch(context.Context) (<-chan struct{}, error) { return make(chan struct{}), nil }
func boolString(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

type fakeBroker struct {
	os              *fakeOS
	j               Journal
	failWAL         bool
	rejectAbsentWAL bool
	finishError     error
}

func (b *fakeBroker) state() JournalState {
	return JournalState{Schema: 2, Engine: Engine, Epoch: b.j.Launch.Epoch, Seq: b.j.Seq, Phase: b.j.Phase, Journal: &b.j, CleanupComplete: b.j.Phase == "complete"}
}
func (b *fakeBroker) Begin(context.Context) (JournalState, error) {
	b.os.log = append(b.os.log, "begin")
	b.j.Seq = 1
	b.j.Phase = "active"
	return b.state(), nil
}
func (b *fakeBroker) WriteAhead(_ context.Context, s uint64, a Adapter, c []Change) (JournalState, error) {
	b.os.log = append(b.os.log, "wal")
	if b.failWAL {
		return JournalState{}, errors.New("injected WAL failure")
	}
	if b.rejectAbsentWAL && b.os.gone {
		return JournalState{}, errors.New("JOURNAL_ADAPTER")
	}
	if b.j.Seq != s {
		return JournalState{}, errors.New("seq")
	}
	b.j.Adapter = a
	b.j.Changes = append([]Change(nil), c...)
	b.j.Seq++
	return b.state(), nil
}
func (b *fakeBroker) Commit(_ context.Context, s uint64, observed []Observation) (JournalState, error) {
	b.os.log = append(b.os.log, "commit")
	if s != b.j.Seq || len(observed) != len(b.j.Changes) {
		return JournalState{}, errors.New("readback")
	}
	for i, c := range b.j.Changes {
		var found *Observation
		for j := range observed {
			if observed[j].ID == c.ID {
				found = &observed[j]
			}
		}
		if found == nil {
			return JournalState{}, errors.New("missing")
		}
		want := c.Before
		if c.Desired {
			want = &c.Installed
		}
		if !reflect.DeepEqual(found.Current, want) && !(found.OwnerAbsent && !c.Desired && found.Current == nil) {
			return JournalState{}, errors.New("mismatch")
		}
		b.j.Changes[i].State = "restored"
		if c.Desired {
			b.j.Changes[i].State = "applied"
		}
	}
	b.j.Seq++
	return b.state(), nil
}
func (b *fakeBroker) Finish(context.Context, uint64) (JournalState, error) {
	b.os.log = append(b.os.log, "finish")
	if b.finishError != nil {
		return JournalState{}, b.finishError
	}
	if !b.os.gone {
		return JournalState{}, errors.New("ADAPTER_REMAINS")
	}
	b.j.Phase = "complete"
	b.j.Seq++
	return b.state(), nil
}
func (b *fakeBroker) Read(context.Context) (JournalState, error) { return b.state(), nil }
func fixtureManager(t *testing.T, factoryFailure bool) (*Manager, *fakeOS, *fakeBroker) {
	t.Helper()
	o := &fakeOS{rows: map[string]*Value{}, gone: true}
	for _, f := range []uint16{2, 23} {
		o.rows["interface:"+map[uint16]string{2: "2", 23: "23"}[f]] = &Value{Interface: &InterfaceValue{Family: f, MTU: 1500, Metric: 25, AutomaticMetric: true, DADTransmits: 1}}
	}
	o.rows["dns"] = &Value{DNS: &DNSValue{Servers: ""}}
	launch := Launch{Schema: 2, Engine: Engine, Epoch: strings.Repeat("a", 32)}
	b := &fakeBroker{os: o, j: Journal{Schema: 2, Engine: Engine, Launch: launch, Adapter: Adapter{GUID: "11111111-1111-1111-1111-111111111111", Compartment: 1}}}
	c := Config{Launch: launch, Broker: b, Start: func(_ context.Context, d Device, f FlowContext) (DataPlane, error) {
		o.log = append(o.log, "factory.ready")
		if f.Admitting() {
			t.Fatal("admission before commit")
		}
		if factoryFailure {
			d.Close()
			return nil, errors.New("factory failed")
		}
		return &fakePlane{os: o, dev: d, failed: make(chan struct{}), done: make(chan struct{})}, nil
	}}
	return newManager(c, o), o, b
}
func TestManagerReadyBeforeSplitCommitAndStopOrdering(t *testing.T) {
	m, o, _ := fixtureManager(t, false)
	defer m.Close()
	p, e := m.Prepare(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	for k := range o.rows {
		if strings.HasPrefix(k, "route:") {
			t.Fatal("route before Ready/Commit")
		}
	}
	if m.Status().Enabled {
		t.Fatal("early on")
	}
	s, e := m.Commit(context.Background(), p.Token)
	if e != nil || !s.Enabled {
		t.Fatal(s, e)
	}
	o.log = nil
	s, e = m.Disable(context.Background())
	if e != nil || s.Enabled || !s.CleanupComplete {
		t.Fatal(s, e)
	}
	idx := func(prefix string) int {
		for i, v := range o.log {
			if strings.HasPrefix(v, prefix) {
				return i
			}
		}
		return -1
	}
	if !(idx("quiesce") < idx("apply:route:") && idx("apply:route:") < idx("plane.close") && idx("plane.close") < idx("device.close") && idx("device.close") < idx("finish")) {
		t.Fatal(o.log)
	}
	if o.dev.closes != 1 {
		t.Fatal("duplicate native Close", o.dev.closes)
	}
}
func TestManagerFactoryFailureDataClosesOnce(t *testing.T) {
	m, o, _ := fixtureManager(t, true)
	defer m.Close()
	if _, e := m.Prepare(context.Background()); e == nil {
		t.Fatal("failure hidden")
	}
	if o.dev.closes != 1 {
		t.Fatal("factory close owner violated", o.dev.closes)
	}
	if !m.Status().CleanupComplete {
		t.Fatal(m.Status())
	}
}
func TestManagerWALFailureNoMutationAndCleanupFailureRetainsAccount(t *testing.T) {
	m, o, b := fixtureManager(t, false)
	defer m.Close()
	p, e := m.Prepare(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	b.failWAL = true
	o.log = nil
	if _, e = m.Commit(context.Background(), p.Token); e == nil {
		t.Fatal("WAL failure hidden")
	}
	for _, v := range o.log {
		if strings.HasPrefix(v, "apply:") {
			t.Fatal("mutation without durable WAL", o.log)
		}
	}
	if m.Status().Enabled || m.Status().CleanupComplete || m.journal == nil {
		t.Fatal("off is not cleanup complete", m.Status())
	}
}

func TestR04RuntimeUnsafeWithdrawsOnlyOwnedRoutesAndSafeStableResume(t *testing.T) {
	m, o, _ := fixtureManager(t, false)
	defer m.Close()
	prep, e := m.Prepare(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Commit(context.Background(), prep.Token); e != nil {
		t.Fatal(e)
	}
	p, e := o.Snapshot(context.Background(), 7)
	if e != nil {
		t.Fatal(e)
	}
	p.Owners[0].Up = false
	m.mu.Lock()
	m.reconcileObserved(context.Background(), p, nil, time.Now())
	m.mu.Unlock()
	s := m.Status()
	if s.Enabled || !s.Intent || s.Code != "EGRESS_BIND_UNSAFE" || s.CleanupComplete {
		t.Fatal(s)
	}
	for k, v := range o.rows {
		if strings.HasPrefix(k, "route:") && v != nil {
			t.Fatal("owned route still intercepts", k)
		}
		if k == "dns" && v == nil {
			t.Fatal("virtual DNS state disappeared")
		}
	}
	if o.dev.closes != 0 {
		t.Fatal("recoverable unsafe state closed whole DATA")
	}
	p.Owners[0].Up = true
	p.Options.Fingerprint = "safe-new"
	now := time.Now()
	m.mu.Lock()
	if !m.reconcileObserved(context.Background(), p, nil, now) {
		t.Fatal("missing stable candidate")
	}
	if !m.reconcileObserved(context.Background(), p, nil, now.Add(stableWindow/2)) {
		t.Fatal("unstable accepted")
	}
	m.reconcileObserved(context.Background(), p, nil, now.Add(stableWindow))
	m.mu.Unlock()
	if !m.Status().Enabled {
		t.Fatal(m.Status())
	}
}
func TestR04ReadFailureIsNotInventedSourceDeletion(t *testing.T) {
	m, o, _ := fixtureManager(t, false)
	defer m.Close()
	p, e := m.Prepare(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	m.Commit(context.Background(), p.Token)
	m.mu.Lock()
	m.reconcileObserved(context.Background(), Physical{}, errors.New("native read error"), time.Now())
	m.mu.Unlock()
	if m.Status().Enabled || !m.Status().Intent || o.dev.closes != 0 {
		t.Fatal(m.Status())
	}
}
