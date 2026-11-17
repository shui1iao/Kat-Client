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

func TestSelectAndSingleNodeProbeUnblockSiblingColdSmartAndURLTestGroups(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer target.Close()
	// Simulate desktop client where group URL is gstatic default, user probes via client URL (e.g. cloudflare)
	// on a Select group or single node, and sibling HK groups (Smart & URLTest) have an unprobed second member.
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Security = &SecurityOptions{AllowLoopback: true}
	c.SetClientUnifiedDelay(true)
	c.Outbounds = []OutboundConfig{
		{Name: "dead-hk", Type: "socks5", Server: "127.0.0.1", Port: 1},
	}
	lazy := true
	c.Groups = []GroupConfig{
		{Name: "Proxy", Type: "select", Members: []string{"direct", "dead-hk"}},
		{Name: "HK-Smart", Type: "smart", Members: []string{"direct", "dead-hk"}, Lazy: &lazy, Probe: &group.ProbeOptions{URL: target.URL}},
		{Name: "HK-URLTest", Type: "url-test", Members: []string{"dead-hk", "direct"}, Lazy: &lazy, Probe: &group.ProbeOptions{URL: target.URL}},
	}
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())

	policy, e := NewManualProbePolicy(5*time.Second, 100)
	if e != nil {
		t.Fatal("100 concurrency rejected:", e)
	}
	policy.SetUnifiedDelay(true)

	// Single-node probe on "direct" (only 1 of 2 members in HK-Smart & HK-URLTest!) with a different client probe URL:
	r, e := s.ProbeNodeWithPolicy(context.Background(), "direct", target.URL, policy)
	if e != nil || r.ProbeMS == nil {
		t.Fatal("single node probe failed:", e, r)
	}
	for _, snap := range s.GroupSnapshots() {
		if snap.Name == "HK-Smart" || snap.Name == "HK-URLTest" {
			if snap.Current != "direct" {
				t.Fatalf("%s remained stuck with Current=%q instead of selecting probed healthy member direct", snap.Name, snap.Current)
			}
		}
	}

	// Also verify Select group batch probe forwards member latency to sibling groups:
	c2 := c
	s2, e := Start(c2)
	if e != nil {
		t.Fatal(e)
	}
	defer s2.Close(context.Background())
	selectSub := GroupConfig{Name: "ProxyOnlyGood", Type: "select", Members: []string{"direct"}}
	c2.Groups = append(c2.Groups, selectSub)
	s2.Close(context.Background())
	s3, e := Start(c2)
	if e != nil {
		t.Fatal(e)
	}
	defer s3.Close(context.Background())
	rs, e := s3.ProbeGroupWithPolicy(context.Background(), "ProxyOnlyGood", target.URL, policy)
	if e != nil || len(rs) != 1 || rs[0].ProbeMS == nil {
		t.Fatal("Select group probe failed:", e, rs)
	}
	for _, snap := range s3.GroupSnapshots() {
		if snap.Name == "HK-Smart" || snap.Name == "HK-URLTest" {
			if snap.Current != "direct" {
				t.Fatalf("after Select group probe, %s Current=%q, want direct", snap.Name, snap.Current)
			}
		}
	}
}
