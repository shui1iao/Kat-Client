package route

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// Representative constructed fixture, not a user's captured configuration.
// This assertion intentionally fails against the preserved pre-change Offline.
func TestRuleInspectorBaselineUnknownSetPort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "S.json")
	body := `{"version":1,"rules":[{"port_range":[":443"]}]}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	o := Options{RuleSets: []RuleSetOptions{{Name: "S", Format: "sing-box-json", Path: path}}, Rules: []Rule{{RuleSet: "S", Action: "reject"}}, Final: "direct"}
	e, err := NewEngine(o, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for _, port := range []uint16{443, 8443} {
		d, err := e.Decide(context.Background(), Metadata{IP: netip.MustParseAddr("192.0.2.1"), Port: port, Network: "tcp"}, nil)
		t.Logf("real Decide port=%d decision=%+v err=%v", port, d, err)
		if err != nil || (port == 443 && (d.Kind != Reject || d.Rule != 1)) || (port == 8443 && (d.Kind != Direct || d.Rule != 0)) {
			t.Fatal("real matcher premise failed")
		}
	}
	got, err := e.Offline(o, "192.0.2.1")
	t.Logf("Offline=%+v err=%v; required=unknown", got, err)
	if err != nil || got.Status != "unknown" {
		t.Fatalf("unknown target port must block rule #1; got=%+v err=%v", got, err)
	}
}
