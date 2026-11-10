package clientcore

// Representative constructed inputs only. A test-only reflection fixture fills
// kernel's private cfg/rt/refs fields without calling Start or opening a socket.
// Reflection changes fixture memory only, never production code or live state.
import (
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/route"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func riWritable(v reflect.Value) reflect.Value {
	return reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
}
func riHost(t *testing.T, mode string) *Host {
	t.Helper()
	e, err := route.NewEngine(route.Options{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	s := &kernel.Server{}
	v := reflect.ValueOf(s).Elem()
	riWritable(v.FieldByName("core")).Set(reflect.New(v.FieldByName("core").Type().Elem()))
	riWritable(v.FieldByName("core").Elem().FieldByName("ctx")).Set(reflect.ValueOf(context.Background()))
	rt := reflect.New(v.FieldByName("rt").Type().Elem())
	riWritable(rt.Elem().FieldByName("engine")).Set(reflect.ValueOf(e))
	riWritable(v.FieldByName("rt")).Set(rt)
	cfg := kernel.Config{Routing: &kernel.RoutingOptions{Final: "direct"}, Limits: kernel.Limits{DialTimeout: kernel.Duration(5 * time.Second)}}
	cfg.SetClientIPv6(false)
	riWritable(v.FieldByName("cfg")).Set(reflect.ValueOf(cfg))
	riWritable(v.FieldByName("refs")).Addr().Interface().(*atomic.Int64).Store(1)
	return &Host{server: s, doc: document{client: Client{Mode: mode, IPv6: false}, ruleRouting: &kernel.RoutingOptions{Rules: []kernel.RouteRule{{DomainSuffix: "example.com", Outbound: "Proxy"}, {IPCIDR: "2001:db8::/32", Outbound: "Proxy"}}, Final: "Tail"}, config: kernel.Config{Routing: &kernel.RoutingOptions{Final: "DraftMustNotParticipate"}}, text: `{"kernel":{"routing":{"final":"DraftMustNotParticipate"}}}`}}
}
func riRequest(h *Host, raw string) (any, *Error) {
	return h.Request(context.Background(), "rules.test", json.RawMessage(raw))
}
func TestRuleInspectorAPIStrictFields(t *testing.T) {
	h := riHost(t, "rule")
	tests := []struct{ name, raw, path string }{
		{"unknown", `{"target":"example.com","typo":true}`, "params"},
		{"duplicate", `{"target":"example.com","target":"other.example"}`, "params"},
		{"duplicate-escaped", `{"target":"example.com","targ\u0065t":"other.example"}`, "params"},
		{"root-null", `null`, "params"}, {"root-array", `[]`, "params"}, {"trailing-json", `{"target":"example.com"}{}`, "params"},
		{"missing-target", `{}`, "target"}, {"empty-target", `{"target":""}`, "target"},
		{"invalid-target", `{"target":"https://a_b.example.com/"}`, "target"},
		{"conflict-default", `{"target":"https://example.com/","target_port":8443}`, "target_port"},
		{"conflict-explicit", `{"target":"https://example.com:8443/","target_port":443}`, "target_port"},
		{"invalid-network", `{"target":"example.com","network":"tls"}`, "network"},
		{"invalid-protocol", `{"target":"example.com","protocol":"tcp"}`, "protocol"},
		{"invalid-source-ip", `{"target":"example.com","source_ip":"localhost"}`, "source_ip"},
		{"source-zone", `{"target":"example.com","source_ip":"fe80::1%eth0"}`, "source_ip"},
		{"process-path", `{"target":"example.com","process_name":"/bin/app"}`, "process_name"},
		{"inbound-name", `{"target":"example.com","inbound_name":"has space"}`, "inbound_name"},
		{"inbound-type", `{"target":"example.com","inbound_type":"not-a-type"}`, "inbound_type"},
	}
	for _, field := range []string{"target", "network", "process_name", "source_ip", "inbound_name", "inbound_type", "protocol"} {
		for _, bad := range []string{"null", "1", "true", "[]", "{}"} {
			raw := `{"target":"example.com",` + `"` + field + `":` + bad + `}`
			if field == "target" {
				raw = `{"target":` + bad + `}`
			}
			tests = append(tests, struct{ name, raw, path string }{field + "-" + bad, raw, field})
		}
	}
	for _, field := range []string{"target_port", "source_port", "inbound_port"} {
		for _, bad := range []string{"null", "0", "-1", "65536", "1.5", `"443"`, "true", "[]", "{}"} {
			tests = append(tests, struct{ name, raw, path string }{field + "-" + bad, `{"target":"example.com","` + field + `":` + bad + `}`, field})
		}
	}
	tests = append(tests, struct{ name, raw, path string }{"oversize", `{"target":"` + strings.Repeat("a", 33<<10) + `"}`, "params"})
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := riRequest(h, tc.raw)
			t.Logf("error=%+v", err)
			if err == nil || err.Code != "invalid_params" || err.Path != tc.path {
				t.Fatalf("expected invalid_params/%s got %+v", tc.path, err)
			}
		})
	}
	// Structural errors are not mislabeled as runtime errors, even while stopped.
	stopped := &Host{}
	_, err := riRequest(stopped, `{"target":"example.com","target_port":null}`)
	if err == nil || err.Path != "target_port" {
		t.Fatal(err)
	}
	_, err = riRequest(stopped, `{"target":"example.com"}`)
	if err == nil || err.Code != "core_not_running" || err.Path != "runtime" {
		t.Fatal(err)
	}
	stopped.server = &kernel.Server{}
	_, err = riRequest(stopped, `{"target":"example.com"}`)
	if err == nil || err.Code != "rule_test_unavailable" || err.Path != "runtime" {
		t.Fatal(err)
	}
	h.doc.ruleRouting = &kernel.RoutingOptions{Rules: []kernel.RouteRule{{Domain: "bad..domain", Action: "reject"}}}
	_, err = riRequest(h, `{"target":"example.com"}`)
	if err == nil || err.Code != "rule_test_unavailable" || err.Path != "runtime" {
		t.Fatal(err)
	}
}
func TestRuleInspectorAPIModeProjectionNoDraftAndIPv6(t *testing.T) {
	for _, mode := range []string{"rule", "global", "direct"} {
		t.Run(mode, func(t *testing.T) {
			h := riHost(t, mode)
			for _, target := range []string{"https://example.com/", "2001:db8::1"} {
				before, _ := json.Marshal([]any{h.doc.ruleRouting, h.doc.config, h.doc.text, h.doc.client})
				v, err := riRequest(h, `{"target":"`+target+`"}`)
				if err != nil {
					t.Fatal(err)
				}
				m := v.(map[string]any)
				g := m["result"].(route.TargetResult)
				t.Logf("mode=%s response=%+v result=%+v", mode, m, g)
				if m["mode"] != mode || m["simulation"] != "target" || m["ipv6_enabled"] != false || g.Policy != "Proxy" || g.Status != "matched" {
					t.Fatal(m, g)
				}
				if (target == "2001:db8::1") != (len(g.AdmissionWarnings) == 1) {
					t.Fatal(g)
				}
				after, _ := json.Marshal([]any{h.doc.ruleRouting, h.doc.config, h.doc.text, h.doc.client})
				if string(before) != string(after) {
					t.Fatal("accepted document mutated")
				}
			}
			// Metadata travels through real Request -> clientcore -> kernel -> route.
			h.doc.ruleRouting = &kernel.RoutingOptions{Rules: []kernel.RouteRule{{Network: "udp", RouteRuleExt: kernel.RouteRuleExt{}, Action: "reject"}}, Final: "Tail"}
			v, err := riRequest(h, `{"target":"https://example.com/","network":"UDP","protocol":"QUIC","process_name":"APP.EXE","source_ip":"::ffff:198.51.100.2","source_port":65535,"inbound_name":"local","inbound_type":"socks","inbound_port":1080}`)
			if err != nil {
				t.Fatal(err)
			}
			g := v.(map[string]any)["result"].(route.TargetResult)
			if g.Policy != "reject" || g.Known.Network != "udp" || g.Known.Protocol != "quic" || g.Known.ProcessName != "app.exe" || g.Known.SourceIP != "198.51.100.2" || g.Known.SourcePort != 65535 || g.Known.InboundType != "socks5" {
				t.Fatal(g)
			}
		})
	}
}

// Strict API fields must have one canonical spelling; case-fold aliases must
// not silently override the user's first supplied value. Keep genuine failures.
func TestRuleInspectorAPIExactKeysRejectAmbiguity(t *testing.T) {
	h := riHost(t, "rule")
	h.doc.ruleRouting = &kernel.RoutingOptions{Rules: []kernel.RouteRule{{Network: "udp", Action: "reject"}}, Final: "Tail"}
	control, controlErr := riRequest(h, `{"target":"example.com","network":"udp"}`)
	if controlErr != nil || control.(map[string]any)["result"].(route.TargetResult).Policy != "reject" {
		t.Fatal("canonical control", control, controlErr)
	}
	t.Logf("canonical network=udp control response=%+v", control)
	tests := []string{
		`{"Target":"example.com"}`,
		`{"target":"example.com","Target":"other.example"}`,
		`{"target":"example.com","network":"udp","Network":"tcp"}`,
	}
	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			v, err := riRequest(h, raw)
			t.Logf("input=%s response=%+v error=%+v", raw, v, err)
			if err == nil || err.Code != "invalid_params" || err.Path != "params" {
				t.Fatalf("noncanonical/ambiguous API key accepted: response=%+v error=%+v", v, err)
			}
		})
	}
}
