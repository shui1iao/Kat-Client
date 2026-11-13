package tunplatform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
	log           []string
	rows          map[string]*Value
	gone          bool
	dev           *fakeDevice
	fail          string
	goneQuery     func(context.Context, Adapter) (bool, error)
	readQuery     func(Adapter, Change) (*Value, error)
	snapshotQuery func(context.Context, uint64) (Physical, error)
}

func (o *fakeOS) Device(_ context.Context, _ Adapter) (Device, error) {
	o.log = append(o.log, "device.create")
	o.gone = false
	o.dev = &fakeDevice{os: o}
	return o.dev, nil
}
func (o *fakeOS) Snapshot(ctx context.Context, exclude uint64) (Physical, error) {
	o.log = append(o.log, "snapshot")
	if o.snapshotQuery != nil {
		return o.snapshotQuery(ctx, exclude)
	}
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

func TestWintunWriteRetryTransientExhaustedEOFAndCloseWake(t *testing.T) {
	t.Run("transient_111_recovers_and_preserves_bytes_without_early_reuse", func(t *testing.T) {
		for _, failCount := range []int{1, 3, wintunAllocateRetryLimit} {
			var closed atomic.Bool
			nowAt := time.Unix(100, 0)
			waits := 0
			allocCalls := 0
			sendCalls := 0
			ringSlot := make([]byte, 1500)
			var sentBytes []byte

			scratch := make([]byte, 65535)
			want := bytes.Repeat([]byte{byte(0x30 + failCount)}, 1420)
			copy(scratch[:len(want)], want)

			err := retryWintunWrite(
				scratch[:len(want)],
				wintunErrorBufferOverflow,
				&closed,
				func() time.Time { return nowAt },
				func() error {
					waits++
					nowAt = nowAt.Add(time.Millisecond)
					return nil
				},
				func(n int) (uintptr, syscall.Errno) {
					allocCalls++
					if allocCalls < failCount {
						return 0, wintunErrorBufferOverflow
					}
					return uintptr(0x1000 + failCount), 0
				},
				func(p uintptr, src []byte) {
					if p != uintptr(0x1000+failCount) {
						t.Errorf("unexpected packet token: %#x", p)
					}
					sendCalls++
					copy(ringSlot[:len(src)], src)
					sentBytes = append([]byte(nil), ringSlot[:len(src)]...)
				},
			)
			// Immediately overwrite caller scratch after WritePacket returns to verify no aliasing.
			for i := range scratch[:len(want)] {
				scratch[i] = 0xFF
			}
			if err != nil {
				t.Fatalf("failCount=%d: unexpected error: %v", failCount, err)
			}
			if waits != failCount || allocCalls != failCount || sendCalls != 1 {
				t.Fatalf("failCount=%d: waits=%d allocCalls=%d sendCalls=%d", failCount, waits, allocCalls, sendCalls)
			}
			if !bytes.Equal(sentBytes, want) || !bytes.Equal(ringSlot[:len(want)], want) {
				t.Fatalf("failCount=%d: sent bytes corrupted or aliased", failCount)
			}
		}
	})

	t.Run("sustained_111_exhausts_retry_limit_and_unwraps_errno_111", func(t *testing.T) {
		var closed atomic.Bool
		nowAt := time.Unix(200, 0)
		waits := 0
		allocCalls := 0
		sendCalls := 0

		err := retryWintunWrite(
			[]byte("pkt"),
			wintunErrorBufferOverflow,
			&closed,
			func() time.Time { return nowAt },
			func() error {
				waits++
				nowAt = nowAt.Add(time.Millisecond)
				return nil
			},
			func(int) (uintptr, syscall.Errno) {
				allocCalls++
				return 0, wintunErrorBufferOverflow
			},
			func(uintptr, []byte) {
				sendCalls++
			},
		)
		if err == nil {
			t.Fatal("expected ring full error, got nil")
		}
		if waits != wintunAllocateRetryLimit || allocCalls != wintunAllocateRetryLimit || sendCalls != 0 {
			t.Fatalf("unexpected counts: waits=%d allocCalls=%d sendCalls=%d", waits, allocCalls, sendCalls)
		}
		if !errors.Is(err, ErrWintunRingFull) {
			t.Fatalf("expected errors.Is(err, ErrWintunRingFull), got %v", err)
		}
		if !errors.Is(err, syscall.Errno(111)) {
			if errors.Unwrap(err) != syscall.Errno(111) {
				t.Fatalf("expected Unwrap()==syscall.Errno(111), got %#v", errors.Unwrap(err))
			}
		}
		var rf *WintunRingFullError
		if !errors.As(err, &rf) || !rf.WintunRingFull() {
			t.Fatalf("expected *WintunRingFullError with WintunRingFull()=true, got %#v", err)
		}
	})

	t.Run("monotonic_time_budget_prevents_coarse_timer_multi_tick_accumulation", func(t *testing.T) {
		var closed atomic.Bool
		nowAt := time.Unix(300, 0)
		waits := 0
		allocCalls := 0

		// Simulate Windows coarse timer tick where a single 1ms WaitForSingleObject takes 15.6ms (>= 8ms budget).
		err := retryWintunWrite(
			[]byte("pkt"),
			wintunErrorBufferOverflow,
			&closed,
			func() time.Time { return nowAt },
			func() error {
				waits++
				nowAt = nowAt.Add(15600 * time.Microsecond)
				return nil
			},
			func(int) (uintptr, syscall.Errno) {
				allocCalls++
				return 0, wintunErrorBufferOverflow
			},
			func(uintptr, []byte) {},
		)
		if !errors.Is(err, ErrWintunRingFull) || errors.Unwrap(err) != syscall.Errno(111) {
			t.Fatalf("expected WintunRingFullError wrapping 111, got %v", err)
		}
		if waits != 1 || allocCalls != 1 {
			t.Fatalf("coarse timer tick accumulated multiple waits: waits=%d allocCalls=%d, want 1", waits, allocCalls)
		}
	})

	t.Run("eof_38_and_unknown_errors_fail_immediately_without_wait", func(t *testing.T) {
		for _, code := range []syscall.Errno{38, 13, 5} {
			var closed atomic.Bool
			waits := 0
			allocCalls := 0
			err := retryWintunWrite(
				[]byte("pkt"),
				code,
				&closed,
				time.Now,
				func() error { waits++; return nil },
				func(int) (uintptr, syscall.Errno) { allocCalls++; return 0, code },
				func(uintptr, []byte) {},
			)
			if err == nil || !errors.Is(err, code) || errors.Is(err, ErrWintunRingFull) {
				t.Fatalf("errno=%d: unexpected err=%v", code, err)
			}
			var rf *WintunRingFullError
			if errors.As(err, &rf) {
				t.Fatalf("errno=%d: non-111 error must not be WintunRingFullError", code)
			}
			if waits != 0 || allocCalls != 0 {
				t.Fatalf("errno=%d: must not wait or retry, got waits=%d allocCalls=%d", code, waits, allocCalls)
			}
		}

		// Transition from 111 to EOF 38 on retry #1 must fail immediately with 38 (not ring full).
		var closed atomic.Bool
		waits := 0
		err := retryWintunWrite(
			[]byte("pkt"),
			wintunErrorBufferOverflow,
			&closed,
			time.Now,
			func() error { waits++; return nil },
			func(int) (uintptr, syscall.Errno) { return 0, 38 },
			func(uintptr, []byte) {},
		)
		if err == nil || !errors.Is(err, syscall.Errno(38)) || errors.Is(err, ErrWintunRingFull) || waits != 1 {
			t.Fatalf("111->38 transition failed: err=%v waits=%d", err, waits)
		}
	})

	t.Run("close_sets_stop_before_writeMu_and_wakes_wait_without_handle_race", func(t *testing.T) {
		var writeMu sync.Mutex
		var closed atomic.Bool
		var handleOpen atomic.Bool
		handleOpen.Store(true)
		stopCh := make(chan struct{})
		enteredWait := make(chan struct{})

		writeDone := make(chan error, 1)
		go func() {
			writeMu.Lock()
			defer writeMu.Unlock()
			err := retryWintunWrite(
				[]byte("pkt"),
				wintunErrorBufferOverflow,
				&closed,
				time.Now,
				func() error {
					if !handleOpen.Load() {
						t.Error("waitStop called after stop/session handle was closed")
					}
					close(enteredWait)
					<-stopCh
					if !handleOpen.Load() {
						t.Error("stop/session handle closed while WritePacket still held writeMu")
					}
					return io.ErrClosedPipe
				},
				func(int) (uintptr, syscall.Errno) {
					t.Error("allocate must not run after stop wakeup")
					return 0, wintunErrorBufferOverflow
				},
				func(uintptr, []byte) {
					t.Error("send must not run after stop wakeup")
				},
			)
			writeDone <- err
		}()

		<-enteredWait
		// Mirror nativeDevice.Close(): store closed=true and signal stop BEFORE acquiring writeMu,
		// then tear down session/adapter/stop handles only AFTER writeMu is acquired.
		closeDone := make(chan struct{})
		go func() {
			closed.Store(true)
			close(stopCh)
			writeMu.Lock()
			handleOpen.Store(false)
			writeMu.Unlock()
			close(closeDone)
		}()

		select {
		case err := <-writeDone:
			if !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("expected io.ErrClosedPipe on Close wake, got %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("WritePacket did not wake on stop signal")
		}
		select {
		case <-closeDone:
		case <-time.After(time.Second):
			t.Fatal("Close did not complete after WritePacket released writeMu")
		}
	})
}

func TestPrepareWaitingNetworkPreservesIntentThenRecoversOrCancelsAndNeverSwallowsCleanupFailure(t *testing.T) {
	m, o, b := fixtureManager(t, false)
	defer m.Close()
	o.snapshotQuery = func(context.Context, uint64) (Physical, error) {
		return Physical{}, errors.New("WAITING_NETWORK")
	}
	o.log = nil
	// Initial and N repeated offline Prepare calls must NOT call Broker.Begin/WriteAhead/Finish or create a device.
	for i := 0; i < 5; i++ {
		_, e := m.Prepare(context.Background())
		if e == nil || Describe("physical_snapshot", e).Code != "WAITING_NETWORK" {
			t.Fatal("expected WAITING_NETWORK error", i, e)
		}
		s := m.Status()
		if s.State != "waiting_network" || !s.Intent || s.Enabled || !s.CleanupComplete || s.CleanupPending || s.Failure != nil || m.journal != nil || b.j.Seq != 0 {
			t.Fatal("unexpected status or journal mutation after offline prepare", i, s, m.journal, b.j)
		}
	}
	for _, entry := range o.log {
		if entry == "begin" || entry == "wal" || entry == "finish" || entry == "device.create" {
			t.Fatal("offline prepare performed journal or device write:", o.log)
		}
	}
	// Cancel while waiting_network must clear Intent and return to off cleanly without journal writes.
	sOff, eOff := m.Disable(context.Background())
	if eOff != nil || sOff.State != "off" || sOff.Intent || sOff.Enabled || !sOff.CleanupComplete || b.j.Seq != 0 {
		t.Fatal("disable while waiting failed", sOff, eOff, b.j.Seq)
	}
	// Prepare again while offline -> waiting_network, then recover when physical network returns (normal Begin -> Prepare -> Commit).
	if _, e := m.Prepare(context.Background()); e == nil {
		t.Fatal("expected waiting error")
	}
	o.snapshotQuery = nil
	p, e := m.Prepare(context.Background())
	if e != nil {
		t.Fatal("recovery prepare failed", e)
	}
	sOn, e := m.Commit(context.Background(), p.Token)
	if e != nil || !sOn.Enabled || !sOn.Intent || sOn.State != "on" {
		t.Fatal("recovery commit failed", sOn, e)
	}
	// If physical network drops between Prepare and Commit AND cleanup/Finish fails, must remain hard error and never swallow cleanup failure.
	if _, e = m.Disable(context.Background()); e != nil {
		t.Fatal(e)
	}
	p2, e := m.Prepare(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	o.snapshotQuery = func(context.Context, uint64) (Physical, error) {
		return Physical{}, errors.New("WAITING_NETWORK")
	}
	b.finishError = At("journal_save", "JOURNAL_WRITE", errors.New("JOURNAL_WRITE"))
	_, e = m.Commit(context.Background(), p2.Token)
	sErr := m.Status()
	if e == nil || sErr.State != "error" || sErr.Intent || sErr.CleanupComplete || sErr.Failure == nil || sErr.Failure.Code != "JOURNAL_WRITE" {
		t.Fatal("cleanup failure during Commit WAITING_NETWORK was swallowed", sErr, e)
	}
	// Prior unresolved cleanup / retained journal must still reject new Prepare as hard error even while offline.
	_, e = m.Prepare(context.Background())
	if e == nil || Describe("prepare_guard", e).Code != "TUN_BUSY" {
		t.Fatal("retained dirty journal allowed offline Prepare", e)
	}
	b.finishError = nil
	o.snapshotQuery = nil
	if _, e = m.Disable(context.Background()); e != nil {
		t.Fatal("cleanup retry failed", e)
	}
}
