package kernel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/group"
)

// blackholeTCP accepts TCP and stalls until closed, simulating a dead/hanging proxy node (5s timeout).
func startBlackholeTCP(t *testing.T) (host string, port int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() {
		close(done)
		_ = ln.Close()
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				<-done
				_ = conn.Close()
			}(c)
		}
	}()
	ap := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", ap.Port
}

func TestDesktopStartupStreamingProbeUnblocksGroupsAndNestedDependenciesBeforeDeadNodeTimeout(t *testing.T) {
	probeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			time.Sleep(90 * time.Millisecond)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer probeSrv.Close()

	bhHost, bhPort := startBlackholeTCP(t)

	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Security = &SecurityOptions{AllowLoopback: true}
	c.SetClientUnifiedDelay(true)
	c.Outbounds = []OutboundConfig{
		{Name: "dead-0", Type: "socks5", Server: bhHost, Port: uint16(bhPort)},
	}
	lazyFalse := false
	fiveSec := outbound.Duration(5 * time.Second)
	c.Groups = []GroupConfig{
		{
			Name:    "Child-URLTest",
			Type:    "url-test",
			Members: []string{"dead-0", "direct"},
			Lazy:    &lazyFalse,
			Probe:   &group.ProbeOptions{URL: probeSrv.URL + "/generate_204", Timeout: fiveSec},
		},
		{
			Name:    "Child-Smart",
			Type:    "smart",
			Members: []string{"dead-0", "direct"},
			Lazy:    &lazyFalse,
			Probe:   &group.ProbeOptions{URL: probeSrv.URL + "/generate_204", Timeout: fiveSec},
		},
		{
			Name:    "Top-Nested",
			Type:    "url-test",
			Members: []string{"Child-URLTest", "Child-Smart"},
			Lazy:    &lazyFalse,
			Probe:   &group.ProbeOptions{URL: probeSrv.URL + "/generate_204", Timeout: fiveSec},
		},
	}

	started := time.Now()
	s, err := Start(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())

	// Even though dead-0 hangs for the full 5s probe timeout, all three desktop groups
	// (including Top-Nested waiting on both Child-URLTest and Child-Smart) must become
	// usable with a healthy selection in well under 1 second!
	deadline := time.Now().Add(900 * time.Millisecond)
	for {
		snaps := s.GroupSnapshots()
		readyCount := 0
		for _, g := range snaps {
			switch g.Name {
			case "Child-URLTest", "Child-Smart":
				if g.Current == "direct" {
					readyCount++
				}
			case "Top-Nested":
				if g.Current == "Child-URLTest" || g.Current == "Child-Smart" {
					readyCount++
				}
			}
		}
		if readyCount == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("groups remained blocked behind 5s dead node after %v: %+v", time.Since(started), s.GroupSnapshots())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Verify real business TCP traffic through Top-Nested also succeeds immediately without waiting 5s on dead-0!
	dialCtx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	conn, err := s.rt.nodes["Top-Nested"].DialTCP(dialCtx, outbound.Addr{Host: "127.0.0.1", Port: uint16(probeSrv.Listener.Addr().(*net.TCPAddr).Port)})
	if err != nil {
		t.Fatalf("business TCP dial through Top-Nested blocked or failed behind dead-0: %v", err)
	}
	_ = conn.Close()

	if elapsed := time.Since(started); elapsed >= 1500*time.Millisecond {
		t.Fatalf("expected sub-second readiness & traffic admission despite 5s dead node, took %v", elapsed)
	}
}
