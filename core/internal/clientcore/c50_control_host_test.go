package clientcore

import (
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/clientegress"
	"net"
	"strconv"
	"testing"
	"time"
)

// Real Host and production preview route; the fetch seam only pauses network
// work to deterministically observe lifecycle cancellation. No token/UAC mock.
func TestC50ControlNilPolicyPreviewCanceledWithoutProxyHint(t *testing.T) {
	h, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	entered := make(chan context.Context, 1)
	done := make(chan *Error, 1)
	h.fullFetch = func(ctx context.Context, _ string, p *clientegress.Policy, _ int64) ([]byte, error) {
		if p != nil {
			t.Error("ordinary request unexpectedly acquired a policy")
		}
		entered <- ctx
		<-ctx.Done()
		return nil, ctx.Err()
	}
	go func() {
		_, e := h.previewSubscription(context.Background(), json.RawMessage(`{"url":"https://example.com/ordinary","full_only":true}`))
		done <- e
	}()
	var request context.Context
	select {
	case request = <-entered:
	case <-time.After(time.Second):
		t.Fatal("preview never admitted")
	}
	h.mu.Lock()
	h.cancelBootstrapLocked()
	if request.Err() == nil {
		h.mu.Unlock()
		t.Fatal("activation returned before nested child cancellation")
	}
	h.mu.Unlock()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("canceled preview accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("download blocked Host lifecycle")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fullPending != nil || len(h.fullCandidates) != 0 {
		t.Fatal("canceled preview published state")
	}
}

func TestC50ControlBootstrapSynchronousCancelAndParent(t *testing.T) {
	h := &Host{}
	type key struct{}
	parent, cancel := context.WithTimeout(context.WithValue(context.Background(), key{}, "preserved"), time.Second)
	defer cancel()
	h.mu.Lock()
	first, stop := h.bootstrapContextLocked(parent)
	second, stop2 := h.bootstrapContextLocked(parent)
	h.mu.Unlock()
	defer stop()
	defer stop2()
	if first.Value(key{}) != "preserved" {
		t.Fatal("parent values lost")
	}
	if _, ok := first.Deadline(); !ok {
		t.Fatal("parent budget lost")
	}
	nested, end := context.WithTimeout(first, time.Second)
	defer end()
	h.mu.Lock()
	h.cancelBootstrapLocked()
	if first.Err() == nil || second.Err() == nil || nested.Err() == nil {
		h.mu.Unlock()
		t.Fatal("only asynchronously canceled a request")
	}
	next, stop3 := h.bootstrapContextLocked(context.Background())
	h.mu.Unlock()
	defer stop3()
	if next.Err() != nil {
		t.Fatal("new ordinary lifecycle inherited stale cancellation")
	}
	cancel()
	if first.Err() == nil {
		t.Fatal("parent cancellation lost")
	}
}

func TestC50ControlFrozenSwitchBlocksBootstrapEvenWithNilPolicy(t *testing.T) {
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	n, _ := strconv.Atoi(port)
	var s clientegress.Switch
	s.FreezeNew()
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), hostEgressKey{}, hostEgressRequest{switcher: &s, ordinary: true}), time.Second)
	defer cancel()
	// A real loopback listener makes a missing Switch hook observable without
	// connecting to any external host or sending target/proxy bytes.
	if c, e := dialBootstrap(ctx, "example.com:443", &bootstrapProxy{Host: "127.0.0.1", Port: uint16(n)}, nil, nil, nil); e == nil {
		c.Close()
		t.Fatal("frozen nil-policy request dialed")
	}
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Millisecond))
	if c, e := listener.Accept(); e == nil {
		c.Close()
		t.Fatal("old ordinary route opened a socket while Switch frozen")
	}
}

func TestC50ControlSnapshotGuardNeverInfersOrdinary(t *testing.T) {
	var s clientegress.Switch
	contextFor := func(ordinary bool) context.Context {
		p, g, f := s.PolicySnapshot()
		return context.WithValue(context.Background(), hostEgressKey{}, hostEgressRequest{switcher: &s, policy: p, generation: g, ordinary: ordinary, frozen: f})
	}
	if checkHostEgress(contextFor(false)) == nil {
		t.Fatal("nil controlled policy fell back to direct")
	}
	ordinary := contextFor(true)
	if checkHostEgress(ordinary) != nil {
		t.Fatal("explicit ordinary mode lost")
	}
	s.FreezeNew()
	if checkHostEgress(ordinary) == nil || checkHostEgress(contextFor(true)) == nil {
		t.Fatal("nil fence hidden")
	}
	s.ReleasePhysical()
	if checkHostEgress(contextFor(true)) != nil {
		t.Fatal("clean explicit ordinary release lost")
	}
	p := clientegress.Blocked()
	s.Replace(p)
	failed := contextFor(false)
	if checkHostEgress(failed) == nil {
		t.Fatal("failed policy admitted")
	}
	s.ReleasePhysical()
	if checkHostEgress(failed) == nil {
		t.Fatal("same generation 0 but different policy accepted")
	}
}

func TestC50ControlIconWithoutProxyHintSharesLifecycle(t *testing.T) {
	h, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	entered := make(chan context.Context, 1)
	done := make(chan error, 1)
	h.iconFetch = func(ctx context.Context, _ string) ([]byte, error) {
		entered <- ctx
		<-ctx.Done()
		return nil, ctx.Err()
	}
	go func() { _, e := h.fetchIcon(context.Background(), "https://example.com/icon.png"); done <- e }()
	var request context.Context
	select {
	case request = <-entered:
	case <-time.After(time.Second):
		t.Fatal("icon fetch not entered")
	}
	h.mu.Lock()
	h.cancelBootstrapLocked()
	if request.Err() == nil {
		h.mu.Unlock()
		t.Fatal("icon not synchronously canceled")
	}
	h.mu.Unlock()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("old icon download accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("icon download blocked lifecycle")
	}
}
