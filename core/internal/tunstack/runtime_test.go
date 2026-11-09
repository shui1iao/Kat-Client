package tunstack

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
)

// Exercise the linearization point directly: a pre-fence handshake reservation
// cannot become a new callback once Quiesce has returned, even if the OS gate
// happens to be open. This test is bounded, not a stress test.
func TestC50AdmissionLinearization(t *testing.T) {
	var gate atomic.Bool
	gate.Store(true)
	var epoch atomic.Uint64
	epoch.Store(1)
	r := &Runtime{ctx: context.Background(), cfg: Config{Admitting: gate.Load, Epoch: epoch.Load}, active: map[net.Conn]struct{}{}}
	if !r.reserve() {
		t.Fatal("initial handshake reserve")
	}
	r.Quiesce()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	f := Flow{Source: netip.MustParseAddrPort("10.50.0.2:1234"), Destination: netip.MustParseAddrPort("203.0.113.50:443"), Protocol: TCP}
	if r.enter(a, &f) {
		t.Fatal("pre-fence handshake entered after ACK")
	}
	r.release(nil)
	var wg sync.WaitGroup
	for j := 0; j < 16; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r.reserve() {
				r.release(nil)
				t.Error("new admission after ACK")
			}
		}()
	}
	wg.Wait()
	gate.Store(false)
	epoch.Store(2)
	if e := r.Resume(); e != nil {
		t.Fatal(e)
	}
	if r.reserve() || r.enter(a, &f) {
		t.Fatal("Resume bypassed OS gate")
	}
	gate.Store(true)
	if !r.reserve() || !r.enter(a, &f) || f.Epoch != 2 {
		t.Fatal("new epoch admission failed")
	}
	r.release(a)
	// An epoch change sampled in the OS hooks must invalidate this admission.
	r.cfg.Epoch = func() uint64 { return epoch.Add(1) }
	if r.enter(b, &f) {
		t.Fatal("torn OS epoch admitted")
	}
}
