package clientegress

import (
	"runtime"
	"sync"
	"testing"
)

func TestPolicySnapshotReadOnlyAndFencedStates(t *testing.T) {
	s := &Switch{}
	if p, g, f := s.PolicySnapshot(); p != nil || g != 0 || f {
		t.Fatal("initial no-policy state", p, g, f)
	}
	// A fence without a policy is still blocked, never ordinary/direct.
	s.FreezeNew()
	if p, g, f := s.PolicySnapshot(); p != nil || g != 0 || !f {
		t.Fatal("nil fence lost", p, g, f)
	}
	p := &Policy{}
	if e := s.installSnapshot(EgressSnapshot{Generation: 7, Epoch: 2}, p); e != nil {
		t.Fatal(e)
	}
	if got, g, f := s.PolicySnapshot(); got != p || g != 7 || f {
		t.Fatal("reconcile snapshot", got, g, f)
	}
	s.FreezeNew()
	for i := 0; i < 2; i++ {
		if got, g, f := s.PolicySnapshot(); got != p || g != 7 || !f || !got.Ready() {
			t.Fatal("getter modified or erased frozen policy", got, g, f)
		}
	}
	if s.current != p || s.generation != 7 || !s.frozen {
		t.Fatal("getter wrote switch")
	}
	p.Fail()
	if got, g, f := s.PolicySnapshot(); got != p || g != 7 || !f || got.Ready() {
		t.Fatal("failed policy hidden as direct", got, g, f)
	}
	// Failure is also observable when no explicit Switch fence has yet been
	// raised: a failed non-nil policy must not disappear into nil/direct.
	failed := &Policy{}
	if e := s.installSnapshot(EgressSnapshot{Generation: 8, Epoch: 2}, failed); e != nil {
		t.Fatal(e)
	}
	failed.Fail()
	if got, g, f := s.PolicySnapshot(); got != failed || g != 8 || f || got.Ready() {
		t.Fatal("unfrozen failed policy hidden", got, g, f)
	}
	s.ReleasePhysical()
	if got, g, f := s.PolicySnapshot(); got != nil || g != 0 || f {
		t.Fatal("successful ordinary release", got, g, f)
	}
}

func TestPolicySnapshotConcurrentTuple(t *testing.T) {
	const count = 256
	policies := make([]*Policy, count+1)
	for i := 1; i <= count; i++ {
		policies[i] = &Policy{}
	}
	s := &Switch{}
	start, done := make(chan struct{}), make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		<-start
		defer close(done)
		for i := 1; i <= count; i++ {
			if e := s.installSnapshot(EgressSnapshot{Generation: uint64(i), Epoch: 1}, policies[i]); e != nil {
				t.Error(e)
				return
			}
			s.FreezeNew()
			runtime.Gosched()
		}
	}()
	close(start)
	// Read while the actual reconcile/fence writer changes generations. A
	// returned pointer can fail immediately afterward; only the locked tuple,
	// not post-read Ready(), is the consistency promise under test.
	samples := 0
	for {
		p, g, f := s.PolicySnapshot()
		samples++
		if (g == 0 && (p != nil || f)) || (g > 0 && (g > count || p != policies[g])) {
			t.Errorf("torn policy/generation/fence tuple: %p %d %v", p, g, f)
			break
		}
		select {
		case <-done:
			writer.Wait()
			if samples == 0 {
				t.Fatal("no snapshot samples")
			}
			return
		default:
			runtime.Gosched()
		}
	}
	writer.Wait()
}
