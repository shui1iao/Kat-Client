package clientcore

import (
	"bufio"
	"fmt"
	"github.com/shui1iao/Kat/internal/clientegress"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestEgressTransitionClosesOnlyOwnFlowsAndPreservesDocument(t *testing.T) {
	target, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := target.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	h := newHost(t)
	text := fixture(t, map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}})
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	client, e := net.Dial("tcp4", portAddress(h.doc.client.HTTPPort))
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target.Addr(), target.Addr())
	br := bufio.NewReader(client)
	line, e := br.ReadString('\n')
	if e != nil || line != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatal("tunnel")
	}
	br.ReadString('\n')
	peer := <-accepted
	defer peer.Close()
	// Test-injected policy exercises non-disruptive egressSwitch transition, not Windows APIs.
	pol := clientegress.Blocked()
	h.mu.Lock()
	old := h.server
	_, de := h.transitionEgressLocked(pol, pol.Options)
	h.mu.Unlock()
	if de != nil {
		t.Fatal(de)
	}
	if h.server != old || h.egressGeneration != 1 || !h.localReady {
		t.Fatal("egress switch did not preserve server/listeners or update generation")
	}
	saved, e := os.ReadFile(h.path)
	if e != nil || string(saved) != text {
		t.Fatal("egress contaminated raw")
	}
	// A separate listener was not stopped; ownership is not name/UID based.
	c, e := net.Dial("tcp4", target.Addr().String())
	if e != nil {
		t.Fatal("unrelated listener affected")
	}
	c.Close()
}
func TestPublicNonWindowsEgressCannotMutate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-Windows")
	}
	h := newHost(t)
	if _, e := h.EgressSet(clientegress.Options{Schema: clientegress.Schema, Enabled: true}); e == nil || e.Code != "unsupported_platform" {
		t.Fatal("non-Windows mutation", e)
	}
	v := h.EgressGet().(clientegress.View)
	if v.Enabled || v.Ready || v.Generation != 0 {
		t.Fatal("fake egress state")
	}
}
