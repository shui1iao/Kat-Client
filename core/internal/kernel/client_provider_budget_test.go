package kernel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClientProviderRequestDeadline(t *testing.T) {
	body := "socks5://127.0.0.1:1#fixture-node\n"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wait" {
			<-r.Context().Done()
			return
		}
		fmt.Fprint(w, body)
	}))
	defer target.Close()
	for _, budget := range []time.Duration{0, time.Second, 90 * time.Second, 300 * time.Second} {
		t.Run(budget.String(), func(t *testing.T) {
			want := budget
			if want == 0 {
				want = defaultProviderTimeout
			}
			c := socksCfg("127.0.0.1:0")
			c.DNS = &DNSOptions{Server: "system"}
			c.Log = &LogOptions{Level: "error"}
			cache := filepath.Join(t.TempDir(), "fixture.cache")
			if e := os.WriteFile(cache, []byte(body), 0600); e != nil {
				t.Fatal(e)
			}
			c.Providers = []ProviderConfig{{Name: "sub", Type: "http", URL: target.URL, Path: cache, Timeout: Duration(budget), Interval: Duration(time.Hour)}}
			s, e := Start(c)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close(context.Background())
			p := s.core.providers["sub"]
			outer, cancel := context.WithTimeout(context.Background(), want+time.Second)
			defer cancel()
			observed := false
			b, e := p.fetchRequest(outer, func(client *http.Client, r *http.Request) (*http.Response, error) {
				d, ok := r.Context().Deadline()
				if !ok || time.Until(d) < want-500*time.Millisecond || time.Until(d) > want {
					t.Fatal("actual request deadline truncated or missing")
				}
				observed = true
				return client.Do(r) // real loopback HTTP, not a synthetic response
			})
			if e != nil || !observed || string(b) != body {
				t.Fatal("real HTTP seam path failed")
			}
			// A shorter caller deadline always wins over the selected provider budget.
			short, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer stop()
			p.fetchRequest(short, func(client *http.Client, r *http.Request) (*http.Response, error) {
				d, ok := r.Context().Deadline()
				if !ok || time.Until(d) > 100*time.Millisecond {
					t.Fatal("caller deadline lost")
				}
				return client.Do(r)
			})
		})
	}
}

func TestClientProviderActualTimeoutKeepsPrevious(t *testing.T) {
	body := "socks5://127.0.0.1:1#fixture-retained\n"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer target.Close()
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Log = &LogOptions{Level: "error"}
	cache := filepath.Join(t.TempDir(), "fixture.cache")
	os.WriteFile(cache, []byte(body), 0600)
	c.Providers = []ProviderConfig{{Name: "sub", Type: "http", URL: target.URL, Path: cache, Timeout: Duration(time.Second), Interval: Duration(time.Hour)}}
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	gen := s.StatsView().Reload.Generation
	start := time.Now()
	if _, e := s.RefreshProvider(context.Background(), "sub"); e == nil {
		t.Fatal("timeout fabricated successful refresh")
	}
	if elapsed := time.Since(start); elapsed < 900*time.Millisecond || elapsed > 2*time.Second {
		t.Fatal("configured request timeout not observed")
	}
	if s.StatsView().Reload.Generation != gen {
		t.Fatal("failed refresh replaced generation")
	}
	if b, _ := os.ReadFile(cache); string(b) != body {
		t.Fatal("failed refresh lost previous cache")
	}
	if p := s.core.providers["sub"]; !p.loaded || len(p.res.Nodes) != 1 {
		t.Fatal("failed refresh lost previous nodes")
	}
}
