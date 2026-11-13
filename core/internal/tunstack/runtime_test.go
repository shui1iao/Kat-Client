package tunstack

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
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

func TestInitStackTCPRecoveryOptionAndSACK(t *testing.T) {
	r := &Runtime{}
	if err := r.initStack(); err != nil {
		t.Fatalf("initStack: %v", err)
	}
	defer func() {
		if r.stack != nil {
			r.stack.Destroy()
		}
		if r.link != nil {
			r.link.Close()
			r.link.Drain()
		}
	}()

	var rec tcpip.TCPRecovery
	if e := r.stack.TransportProtocolOption(tcp.ProtocolNumber, &rec); e != nil {
		t.Fatalf("TransportProtocolOption(TCPRecovery): %s", e)
	}
	var sack tcpip.TCPSACKEnabled
	if e := r.stack.TransportProtocolOption(tcp.ProtocolNumber, &sack); e != nil {
		t.Fatalf("TransportProtocolOption(TCPSACKEnabled): %s", e)
	}
	if !bool(sack) {
		t.Fatalf("expected SACK enabled true, got %v", sack)
	}

	if runtime.GOOS == "windows" {
		if rec != tcpip.TCPRecovery(0) {
			t.Fatalf("windows expected TCPRecovery(0), got %v", rec)
		}
	} else {
		if rec != tcpip.TCPRACKLossDetection {
			t.Fatalf("non-windows (%s) expected default TCPRACKLossDetection(%v), got %v", runtime.GOOS, tcpip.TCPRACKLossDetection, rec)
		}
		opt := tcpip.TCPRecovery(0)
		if e := r.stack.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); e != nil {
			t.Fatalf("SetTransportProtocolOption(TCPRecovery(0)): %s", e)
		}
		var gotRec tcpip.TCPRecovery
		if e := r.stack.TransportProtocolOption(tcp.ProtocolNumber, &gotRec); e != nil {
			t.Fatalf("readback TransportProtocolOption(TCPRecovery): %s", e)
		}
		if gotRec != tcpip.TCPRecovery(0) {
			t.Fatalf("readback expected TCPRecovery(0), got %v", gotRec)
		}
		var gotSack tcpip.TCPSACKEnabled
		if e := r.stack.TransportProtocolOption(tcp.ProtocolNumber, &gotSack); e != nil {
			t.Fatalf("readback TransportProtocolOption(TCPSACKEnabled): %s", e)
		}
		if !bool(gotSack) {
			t.Fatalf("expected SACK still true after TCPRecovery(0), got %v", gotSack)
		}
	}
}
