package kernel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProgrammaticApplyRetainsProviderRebuildSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source")
	os.WriteFile(path, []byte(providerURI("a", 1234)), 0600)
	c := socksCfg("127.0.0.1:0")
	c.Providers = []ProviderConfig{{Name: "p", Type: "file", Path: path, Interval: Duration(time.Hour)}}
	c.Groups = []GroupConfig{{Name: "pick", Type: "select", Use: []string{"p"}}}
	c.Routing = &RoutingOptions{Final: "pick"}
	s := groupsStart(t, c)
	if _, e := s.ApplyConfig(c); e != nil {
		t.Fatal(e)
	}
	gen := s.StatsView().Reload.Generation
	os.WriteFile(path, []byte(providerURI("b", 1235)), 0600)
	if _, e := s.RefreshProvider(context.Background(), "p"); e != nil {
		t.Fatal("programmatic ApplyConfig lost source required by refresh", e)
	}
	if s.StatsView().Reload.Generation != gen+1 || len(s.SelectGroups()[0].Members) != 1 {
		t.Fatal("refresh not committed once")
	}
}
