package kernel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/outbound/group"
)

func TestClientURLTestManualNodeAndGroupProbeForwardMeasurement(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer target.Close()
	lazy := true
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Security = &SecurityOptions{AllowLoopback: true}
	c.Groups = []GroupConfig{{Name: "auto", Type: "url-test", Members: []string{"direct"}, Lazy: &lazy, Probe: &group.ProbeOptions{URL: target.URL, ClientHead: true}}}
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	if e := s.prepareManualProbe(context.Background(), "auto"); e != nil {
		t.Fatal(e)
	}
	policy, e := NewManualProbePolicy(5*time.Second, 2)
	if e != nil {
		t.Fatal(e)
	}
	policy.SetUnifiedDelay(true)
	for round := range 3 {
		node, e := s.ProbeNodeWithPolicy(context.Background(), "direct", target.URL, policy)
		if e != nil || node.ProbeMS == nil || node.ColdMS == nil || node.Error != "" {
			t.Fatal("real node measurement missing", e, node)
		}
		assertProbe := func(r ProbeResult) {
			t.Helper()
			snap := s.GroupSnapshots()[0]
			m := snap.Members[0]
			if !m.Probed || !m.ProbeOK || float64(m.ProbeLatency)/float64(time.Millisecond) != *r.ProbeMS || !m.ProbeAt.Equal(r.At) {
				t.Fatal("ordinary probe not forwarded", round, m, r)
			}

		}
		assertProbe(node)
		rs, e := s.ProbeGroupWithPolicy(context.Background(), "auto", target.URL, policy)
		if e != nil || len(rs) != 1 || rs[0].ProbeMS == nil || rs[0].ColdMS == nil || rs[0].Error != "" {
			t.Fatal("real group measurement missing", e, rs)
		}
		assertProbe(rs[0])
	}
}
