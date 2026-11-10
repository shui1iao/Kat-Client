package clientcore

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/kernel"
)

// Exercise Host.probe and its epoch/timestamp projection with an actual SOCKS
// root, a cold Via url-test and three silent SOCKS peers. All traffic is local.
func viaSettingsKernel(t *testing.T, url string) map[string]any {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	var conns []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go io.Copy(io.Discard, c)
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
	})
	k := settingsKernel(t)
	outs := k["outbounds"].([]any)
	outs[0].(map[string]any)["via"] = "dep"
	members := []string{}
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("silent-%d", i)
		members = append(members, name)
		outs = append(outs, map[string]any{"name": name, "type": "socks5", "server": "127.0.0.1", "port": ln.Addr().(*net.TCPAddr).Port})
	}
	members = append(members, "direct")
	k["outbounds"] = outs
	k["groups"] = append(k["groups"].([]any), map[string]any{"name": "dep", "type": "url-test", "members": members, "probe": map[string]any{"url": url + "/health", "timeout": "300ms", "interval": "1h"}})
	return k
}

func TestProbeSettingsViaPreparationAndEpoch(t *testing.T) {
	for _, action := range []string{"complete", "cancel", "reload", "stop"} {
		t.Run(action, func(t *testing.T) {
			ready := make(chan struct{}, 1)
			var targets atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					select {
					case ready <- struct{}{}:
					default:
					}
				} else {
					targets.Add(1)
					time.Sleep(20 * time.Millisecond)
				}
				w.WriteHeader(204)
			}))
			defer target.Close()
			h, _ := startSettings(t, viaSettingsKernel(t, target.URL), map[string]any{"probe_url": target.URL + "/target", "probe_timeout": "100ms", "probe_round_timeout": "1500ms", "probe_concurrency": 2})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type answer struct {
				r any
				e *Error
			}
			done := make(chan answer, 1)
			start := time.Now()
			go func() { r, e := h.probe(ctx, false, "p", ""); done <- answer{r, e} }()
			waitSignal(t, ready)
			// Client lazy now performs startup health before the manual call;
			// let the manual goroutine enter its captured readiness window.
			time.Sleep(20 * time.Millisecond)
			switch action {
			case "cancel":
				cancel()
			case "reload":
				if _, e := h.Reload(); e != nil {
					t.Fatal(e)
				}
			case "stop":
				if _, e := h.Stop(); e != nil {
					t.Fatal(e)
				}
			}
			var a answer
			select {
			case a = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("Host leaked preparation context/WG")
			}
			if a.e != nil {
				t.Fatal(a.e)
			}
			r := a.r.(kernel.ProbeResult)
			h.mu.Lock()
			stored, exists := h.probes["p"]
			h.mu.Unlock()
			if action == "complete" {
				if r.ProbeMS == nil || r.Error != "" || !exists || stored.At != r.At || targets.Load() != 1 || time.Since(start) < 280*time.Millisecond {
					t.Fatalf("Host did not separate readiness/target or commit exact sample: %+v", r)
				}
			} else {
				if exists || targets.Load() != 0 || r.ErrorCode != "PROBE_CANCELED" || (r.ErrorStage != "dependency" && r.ErrorStage != "queue") {
					t.Fatalf("canceled/reloaded preparation committed late result: %+v", r)
				}
			}
		})
	}
}
