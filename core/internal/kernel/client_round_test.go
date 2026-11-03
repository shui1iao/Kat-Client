package kernel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound/group"
)

// Both members execute the real HTTP prober; p uses an actual loopback Kat
// SOCKS outbound. The handler holds the second response to expose partial-round
// updates without substituting artificial timings for HTTP measurements.
func TestClientControlManualRound(t *testing.T) {
	for _, tc := range []struct {
		name, kind, action, fixed string
		status                    int
	}{
		{name: "smart-complete", kind: "smart", status: 204},
		{name: "url-test-fixed", kind: "url-test", fixed: "direct", status: 204},
		{name: "smart-all-failed", kind: "smart", status: 500},
		{name: "smart-cancel", kind: "smart", action: "cancel", status: 204},
		{name: "smart-reload", kind: "smart", action: "reload", status: 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			release := make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			entered := make(chan struct{})
			var requests atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if requests.Add(1) == 2 {
					close(entered)
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				}
				w.WriteHeader(tc.status)
			}))
			defer target.Close()
			upcfg := socksCfg("127.0.0.1:0")
			upcfg.DNS = &DNSOptions{Server: "system"}
			up, e := Start(upcfg)
			if e != nil {
				t.Fatal(e)
			}
			defer up.Close(context.Background())
			c := socksCfg("127.0.0.1:0")
			c.DNS = &DNSOptions{Server: "system"}
			lazy := true
			c.Outbounds = []OutboundConfig{{Name: "p", Type: "socks5", Server: "127.0.0.1", Port: uint16(up.Addresses()[0].(*net.TCPAddr).Port)}}
			c.Groups = []GroupConfig{
				{Name: "target", Type: tc.kind, Members: []string{"direct", "p"}, Lazy: &lazy, Fixed: tc.fixed, Priority: map[string]float64{"direct": 4}, Probe: &group.ProbeOptions{URL: target.URL}},
				{Name: "other", Type: "url-test", Members: []string{"direct", "p"}, Probe: &group.ProbeOptions{URL: target.URL}},
			}
			s, e := Start(c)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close(context.Background())
			defer func() { cancel(); unblock() }()
			old := s.current()
			type answer struct {
				results []ProbeResult
				err     error
			}
			done := make(chan answer, 1)
			go func() { rs, e := s.ProbeGroup(ctx, "target", target.URL); done <- answer{rs, e} }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("second real HTTP request did not arrive")
			}
			// Allow the first response to finish while the other worker stays blocked.
			// Neither member may become visible as a partially committed manual round.
			for range 20 {
				for _, g := range s.GroupSnapshots() {
					for _, m := range g.Members {
						if m.Probed {
							t.Fatal("partial manual round committed before all HTTP results")
						}
					}
				}
				time.Sleep(time.Millisecond)
			}
			if tc.action == "cancel" {
				cancel()
			}
			if tc.action == "reload" {
				c.Groups[0].Fixed = "direct"
				c.Groups[0].Priority = map[string]float64{"direct": 0.25}
				if _, e := s.ApplyConfig(c); e != nil {
					t.Fatal(e)
				}
				if s.current() == old {
					t.Fatal("reload did not install a new generation")
				}
			}
			if tc.action != "cancel" {
				unblock()
			}
			var a answer
			select {
			case a = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("manual round worker did not exit")
			}
			if a.err != nil || len(a.results) != 2 || a.results[0].Name != "direct" || a.results[1].Name != "p" {
				t.Fatal("IPC-order results changed")
			}
			if tc.action != "" {
				for _, g := range s.GroupSnapshots() {
					for _, m := range g.Members {
						if m.Probed {
							t.Fatal("canceled/superseded round updated current generation")
						}
					}
				}
				for _, g := range old.rt.groups {
					for _, m := range g.(group.Snapshotter).Snapshot().Members {
						if m.Probed {
							t.Fatal("late/canceled round committed health")
						}
					}
				}
				if tc.action == "cancel" && a.results[0].Error == "" && a.results[1].Error == "" {
					t.Fatal("cancellation fabricated successful HTTP results")
				}
				return
			}
			snapshots := s.GroupSnapshots()
			for _, g := range snapshots {
				for i, m := range g.Members {
					if g.Name == "other" {
						if m.Probed {
							t.Fatal("probe propagated to another group")
						}
						continue
					}
					if !m.Probed || m.ProbeOK != (tc.status < 500) {
						t.Fatal("real HTTP health not recorded")
					}
					r := a.results[i]
					if tc.status >= 500 {
						if r.Error == "" || r.ProbeMS != nil || m.ProbeLatency != 0 {
							t.Fatal("failed HTTP round fabricated success")
						}
					} else {
						if r.Error != "" || r.ProbeMS == nil || float64(m.ProbeLatency)/float64(time.Millisecond) != *r.ProbeMS || !m.ProbeAt.Equal(r.At) {
							t.Fatal("snapshot does not contain the real HTTP sample")
						}
					}
				}
				if g.Name == "target" && tc.status < 500 {
					want := tc.fixed
					// Smart v2 bootstrap: displayed probe times weight, no +40ms reliability prior.
					if want == "" {
						want = "direct"
						if *a.results[1].ProbeMS < *a.results[0].ProbeMS*4 {
							want = "p"
						}
					}
					if g.Current != want {
						t.Fatalf("complete weighted round current=%s, want %s", g.Current, want)
					}
				}
			}
			if tc.status < 500 {
				if r, e := s.ProbeNode(ctx, "direct", target.URL); e != nil || r.ProbeMS == nil {
					t.Fatal("real single-node HTTP probe failed")
				}
				for _, g := range s.GroupSnapshots() {
					if g.Name == "other" {
						for _, m := range g.Members {
							if m.Probed {
								t.Fatal("node probe propagated group health")
							}
						}
					}
				}
			}
		})
	}
}
