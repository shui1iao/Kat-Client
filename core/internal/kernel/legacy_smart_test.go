package kernel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/shui1iao/Kat/internal/outbound/group"
)

func TestRestoredSmartKernelDecodeCreatesNativeRuntime(t *testing.T) {
	c := socksCfg("127.0.0.1:0")
	c.DNS = &DNSOptions{Server: "system"}
	c.Groups = []GroupConfig{{Name: "kept-name", Type: "url-test", Members: []string{"direct"}, Fixed: "direct", Priority: map[string]float64{"direct": 1.5}, Probe: &group.ProbeOptions{URL: "http://127.0.0.1:9/"}}}
	b, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	legacy := strings.Replace(string(b), `"type":"url-test"`, `"type":"smart","smart":{"scope":"site"}`, 1)
	decoded, e := DecodeConfig([]byte(legacy))
	if e != nil {
		t.Fatal(e)
	}
	if decoded.Groups[0].Type != "smart" {
		t.Fatal(decoded.Groups)
	}
	s, e := Start(decoded)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(context.Background())
	if snap := s.GroupSnapshots(); len(snap) != 1 || snap[0].Name != "kept-name" || snap[0].Type != "smart" || snap[0].Fixed != "direct" || snap[0].Current != "direct" || snap[0].Members[0].Priority != 1.5 {
		t.Fatal(snap)
	}
	if _, e := DecodeConfig([]byte(strings.Replace(legacy, `"scope":"site"`, `"unknown":true`, 1))); e == nil {
		t.Fatal("unknown legacy field accepted")
	}
}
