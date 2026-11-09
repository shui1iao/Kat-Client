package procattr

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestStage4TupleBudgetAndSaturation(t *testing.T) {
	block := make(chan struct{})
	done := make(chan struct{}, 4)
	var active, max atomic.Int32
	lookup := func(context.Context, Query) Identity {
		n := active.Add(1)
		for old := max.Load(); n > old; old = max.Load() {
			if max.CompareAndSwap(old, n) {
				break
			}
		}
		<-block
		active.Add(-1)
		done <- struct{}{}
		return Identity{Status: "known", PID: 44, Stamp: 55}
	}
	for i := 0; i < 8; i++ {
		start := time.Now()
		id := budgetTuple(context.Background(), Query{}, lookup)
		if id.Status != "unknown" || id.Cause != "process:unknown" || id.PID != 0 || time.Since(start) > 100*time.Millisecond {
			t.Fatal("lookup blocked forwarding or trusted late proof")
		}
	}
	if max.Load() != 4 {
		t.Fatal("native concurrency", max.Load())
	}
	close(block)
	for i := 0; i < 4; i++ {
		<-done
	}
	// Worker slot is released by worker, not by forwarding timeout.
	end := time.Now().Add(time.Second)
	for len(tupleSlots) > 0 && time.Now().Before(end) {
		time.Sleep(time.Millisecond)
	}
	if len(tupleSlots) != 0 {
		t.Fatal("slots leaked")
	}
	fresh := budgetTuple(context.Background(), Query{}, func(context.Context, Query) Identity {
		return Identity{Status: "known", Name: "fresh.exe", Path: `C:\Apps\fresh.exe`, PID: 45, Stamp: 56}
	})
	if fresh.Status != "known" || fresh.PID != 45 {
		t.Fatal("late result or global positive reused", fresh)
	}
}
func TestStage4OwnerUnknownAmbiguousAndPIDReuse(t *testing.T) {
	q := Query{Network: "udp", Source: netip.MustParseAddrPort("10.0.0.2:6000")}
	for _, netw := range []string{"udp", "tcp"} {
		q.Network = netw
		q.Destination = netip.MustParseAddrPort("203.0.113.1:443")
		row := Row{Source: q.Source, Destination: q.Destination, PID: 9}
		calls := 0
		r := resolveCurrent(q, func(Query) ([]Row, string) {
			calls++
			if calls == 2 {
				row.PID = 10
			}
			return []Row{row}, "known"
		}, func(uint32) (Identity, func() bool, func()) {
			return Identity{Status: "known", PID: 9, Stamp: 1}, func() bool { return true }, func() {}
		})
		if r.Status != "changed" {
			t.Fatal("PID owner changed accepted", r)
		}
		r = resolveCurrent(q, func(Query) ([]Row, string) { return []Row{row, row}, "known" }, nil)
		if r.Status != "ambiguous" {
			t.Fatal(r)
		}
		r = resolveCurrent(q, func(Query) ([]Row, string) { return nil, "known" }, nil)
		if r.Status == "known" {
			t.Fatal("empty table accepted")
		}
		r = resolveCurrent(q, func(Query) ([]Row, string) { return []Row{row}, "known" }, func(uint32) (Identity, func() bool, func()) {
			return Identity{Status: "known", PID: 10, Stamp: 1}, func() bool { return false }, func() {}
		})
		if r.Status != "changed" {
			t.Fatal("creation/handle stale accepted")
		}
	}
}
