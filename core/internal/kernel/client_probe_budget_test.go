package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"net/http"
	"net/http/httptest"
	"strings"

	"testing"
	"time"
)

// Real loopback SS -> SOCKS -> HTTP. The last Via member is usable, the other
// three are accepted silent SS peers. No external subscription or network.

func newProbePolicy(t *testing.T, d time.Duration) *ManualProbePolicy {
	t.Helper()
	p, e := NewManualProbePolicy(d, 1)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func probeCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}
func assertGoodDependency(t *testing.T, s *Server) {
	t.Helper()
	snap := s.GroupSnapshots()[0]
	if snap.Current != "good-last" {
		t.Fatalf("did not keep full-round healthy choice: %s", snap.Current)
	}
	for i, m := range snap.Members {
		if !m.Probed || m.ProbeOK != (i == 3) {
			t.Fatal("partial or fabricated dependency health")
		}
	}
}

func TestManualProbeWithoutViaUnchanged(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(204)
	}))
	defer target.Close()
	c := socksCfg("127.0.0.1:0")
	c.Security = &SecurityOptions{AllowLoopback: true}
	s := groupsStart(t, c)
	policy := newProbePolicy(t, 100*time.Millisecond)
	for _, path := range []string{"/ok", "/slow"} {
		before := time.Now()
		r, e := s.ProbeNodeWithPolicy(probeCtx(t, time.Second), "direct", target.URL+path, policy)
		elapsed := time.Since(before)
		if e != nil {
			t.Fatal(e)
		}
		if path == "/ok" {
			if r.ProbeMS == nil {
				t.Fatal("ordinary direct probe failed")
			}
		} else if r.ErrorCode != "PROBE_TARGET_TIMEOUT" || elapsed < 80*time.Millisecond || elapsed > 500*time.Millisecond {
			t.Fatal("ordinary node timeout changed")
		}
	}
}

func TestProbeFailureCategoriesNeverEchoRawError(t *testing.T) {
	for _, tc := range []struct {
		stage string
		err   error
		code  string
	}{{"dependency", fmt.Errorf("https://user:password@private.invalid/token: %w", context.DeadlineExceeded), "PROBE_DEPENDENCY_UNREADY"}, {"target", fmt.Errorf("private password=SECRET: %w", context.DeadlineExceeded), "PROBE_TARGET_TIMEOUT"}, {"target", errors.New("private token=SECRET"), "PROBE_FAILED"}, {"queue", context.DeadlineExceeded, "PROBE_QUEUE_TIMEOUT"}, {"dependency", context.Canceled, "PROBE_CANCELED"}} {
		var r ProbeResult
		setProbeFailure(&r, tc.stage, tc.err)
		b, _ := json.Marshal(r)
		if r.ErrorCode != tc.code || strings.Contains(string(b), "private") || strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "https") {
			t.Fatal("unsafe or ambiguous probe error")
		}
	}
}

// Readiness failure is not an HTTP health sample of the root. Incomplete
// manual group rounds must not mark the otherwise untested root unhealthy.
