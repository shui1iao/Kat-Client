package kernel

import (
	"context"

	"github.com/shui1iao/Kat/internal/outbound/group"

	"net/http"
	"net/http/httptest"

	"testing"
)

func TestClientControlRealProbe(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer target.Close()
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Security = &SecurityOptions{AllowLoopback: true}
	c.Groups = []GroupConfig{{Name: "auto", Type: "url-test", Members: []string{"direct"}, Probe: &group.ProbeOptions{URL: target.URL}}}
	s, e := Start(c)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	r, e := s.ProbeNode(context.Background(), "direct", target.URL)
	if e != nil || r.ProbeMS == nil || r.Error != "" {
		t.Fatal("real node HTTP probe failed")
	}
	rs, e := s.ProbeGroup(context.Background(), "auto", target.URL)
	if e != nil || len(rs) != 1 || rs[0].ProbeMS == nil {
		t.Fatal("real group HTTP probe failed")
	}
	snap := s.GroupSnapshots()
	if len(snap) != 1 || !snap[0].Members[0].Probed || !snap[0].Members[0].ProbeOK {
		t.Fatal("manual result not in core state")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, e = s.ProbeNode(ctx, "direct", target.URL)
	if e != nil || r.ProbeMS != nil || r.Error == "" {
		t.Fatal("canceled probe")
	}
	if _, e = s.ProbeNode(context.Background(), "auto", target.URL); e == nil {
		t.Fatal("node probe accepted a group")
	}
}
