package clientcore

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/shui1iao/Kat/internal/kernel"
	"golang.org/x/net/dns/dnsmessage"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func uiRequest(t *testing.T, h *Host, method, raw string) any {
	t.Helper()
	v, e := h.Request(context.Background(), method, json.RawMessage(raw))
	if e != nil {
		t.Fatal(method, e)
	}
	return v
}
func uiJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestUIConnectionRingCursorCapacityAndClone(t *testing.T) {
	var r connectionRing
	if v := r.read(0, 200); len(v.Entries) != 0 || v.NextSeq != 0 || v.Dropped != 0 {
		t.Fatal(v)
	}
	chain := []string{"group", "node"}
	for i := 0; i < 2017; i++ {
		r.record(kernel.ConnectionEvent{Time: time.Now(), Network: "tcp", Target: "sensitive.example:443", Host: "sensitive.example", Chain: chain, Outcome: "ok"})
	}
	chain[0] = "changed"
	v := r.read(0, 500)
	if len(v.Entries) != 500 || v.Entries[0].Seq != 18 || v.NextSeq != 517 || v.Dropped != 17 || v.Entries[0].Chain[0] != "group" {
		t.Fatal(v.NextSeq, v.Dropped)
	}
	v.Entries[0].Chain[0] = "mutated"
	if r.read(0, 1).Entries[0].Chain[0] != "group" {
		t.Fatal("alias")
	}
	after := uint64(0)
	count := 0
	for {
		v = r.read(after, 500)
		if len(v.Entries) == 0 {
			break
		}
		count += len(v.Entries)
		after = v.NextSeq
	}
	if count != 2000 || after != 2017 || v.NextSeq != after {
		t.Fatal(count, after, v.NextSeq)
	}
	v = r.read(maxLogSeq, 200)
	if len(v.Entries) != 200 || v.Entries[0].Seq != 18 || v.NextSeq != 217 {
		t.Fatal("future cursor")
	}
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 300 {
				r.record(kernel.ConnectionEvent{Time: time.Now(), Chain: []string{}, Outcome: "error"})
				r.read(0, 200)
			}
		}()
	}
	wg.Wait()
	if r.read(0, 1).Dropped != 917 {
		t.Fatal("concurrent bound")
	}
}

func TestUIParamsAndStoppedSemantics(t *testing.T) {
	h := newHost(t)
	cases := map[string][]string{
		"connections.list":  {`{"closed_limit":0}`, `{"closed_limit":501}`, `{"closed_limit":null}`, `{"closed_limit":1.5}`, `{"closed_limit":"2"}`},
		"logs.connections":  {`{"after":-1}`, `{"after":9007199254740992}`, `{"after":null}`, `{"after":1.5}`, `{"after":"1"}`, `{"limit":0}`, `{"limit":501}`, `{"limit":null}`, `{"limit":"1"}`},
		"dns.query":         {`{"name":"example.com","type":"MX"}`, `{"name":"example.com","type":null}`, `{"name":"example.com","type":2}`, `{"name":3}`},
		"resources.list":    {`{"name":"bad"}`},
		"resources.refresh": {`{}`, `{"kind":"geosite","name":"x"}`, `{"kind":"provider","name":null}`},
	}
	for method, raws := range cases {
		for _, raw := range append(raws, `[]`, `null`, `{"unknown":true}`, `{"limit":1,"limit":2}`) {
			if _, e := h.Request(context.Background(), method, json.RawMessage(raw)); e == nil || e.Code != "invalid_params" {
				t.Fatal(method, raw, e)
			}
		}
	}
	c := uiRequest(t, h, "connections.list", `{}`).(map[string]any)
	if c["total"] != nil || len(c["active"].([]kernel.ConnInfo)) != 0 || len(c["closed"].([]kernel.ClosedConn)) != 0 {
		t.Fatal(c)
	}
	st := h.Status().(map[string]any)
	if st["connections"].(map[string]any)["total"] != nil || st["traffic"].(map[string]any)["rules_since"] != nil {
		t.Fatal(st)
	}
	if _, e := h.Request(context.Background(), "dns.query", json.RawMessage(`{"name":"example.com"}`)); e == nil || e.Code != "core_not_running" {
		t.Fatal(e)
	}
	if _, e := h.Request(context.Background(), "dns.query", json.RawMessage(`{}`)); e == nil || e.Code != "invalid_name" {
		t.Fatal(e)
	}
	if _, e := h.Request(context.Background(), "resources.refresh", json.RawMessage(`{"kind":"rule_set","name":"r"}`)); e == nil || e.Code != "core_not_running" {
		t.Fatal(e)
	}
	for _, m := range []string{"dns.query", "resources.refresh"} {
		if requestBudget(m) != 305*time.Second {
			t.Fatal(m)
		}
	}
}

func TestUISniffStrictProjectionAndSourceRoundTrips(t *testing.T) {
	h := newHost(t)
	old := fixture(t, map[string]any{})
	if _, e := applyLegacyFixture(h, old); e != nil {
		t.Fatal(e)
	}
	got := h.Document().(map[string]any)["text"].(string)
	if got != old {
		t.Fatal("old document changed")
	}
	if _, e := applyLegacyFixture(h, got); e != nil || h.doc.text != old || h.doc.config.Inbounds[0].Sniff != nil {
		t.Fatal("old round trip", e)
	}
	for _, block := range []string{`null`, `true`, `"true"`, `[]`, `{}`, `{"enabled":true}`, `{"enabled":1,"override_destination":false}`, `{"enabled":true,"override_destination":null}`, `{"enabled":true,"override_destination":"false"}`, `{"enabled":true,"override_destination":false,"unknown_ports":"80"}`} {
		raw := strings.Replace(old, `"client":{`, `"client":{"sniff":`+block+`,`, 1)
		if e := h.Validate(raw); e == nil {
			t.Fatal("invalid sniff accepted", block)
		}
		if _, e := applyLegacyFixture(h, raw); e == nil || h.doc.text != old {
			t.Fatal("invalid apply modified source", block)
		}
	}
	for _, enabled := range []bool{false, true} {
		for _, override := range []bool{false, true} {
			text := strings.Replace(old, `"client":{`, fmt.Sprintf(`"client":{"sniff":{"enabled":%t,"override_destination":%t},`, enabled, override), 1)
			if _, e := applyLegacyFixture(h, text); e != nil {
				t.Fatal(e)
			}
			if h.doc.text != text || h.doc.client.Sniff == nil || h.doc.client.Sniff.Enabled != enabled {
				t.Fatal("sniff source lost")
			}
			in := h.doc.config.Inbounds[0]
			if enabled {
				if in.Sniff == nil || in.Sniff.TCPPorts != "80,443,8080,8443" || in.Sniff.UDPPorts != "443" || in.Sniff.Timeout != kernel.Duration(300*time.Millisecond) || in.Sniff.OverrideDestination != override {
					t.Fatal(in.Sniff)
				}
			} else if in.Sniff != nil {
				t.Fatal("disabled changed runtime")
			}
			var tree any
			if err := json.Unmarshal([]byte(text), &tree); err != nil {
				t.Fatal(err)
			}
			y, err := yaml.Marshal(tree)
			if err != nil {
				t.Fatal(err)
			}
			if _, e := applyLegacyFixture(h, string(y), FormatYAML); e != nil {
				t.Fatal(e)
			}
			if h.doc.text != string(y) || h.doc.client.Sniff.Enabled != enabled || h.doc.client.Sniff.OverrideDestination != override {
				t.Fatal("YAML lost sniff")
			}
			b, err := yamlJSON(y)
			if err != nil {
				t.Fatal(err)
			}
			if _, e := applyLegacyFixture(h, string(b), FormatJSON); e != nil || !reflect.DeepEqual(h.doc.client.Sniff, &ClientSniff{Enabled: enabled, OverrideDestination: override}) {
				t.Fatal("YAML/JSON lost sniff", e)
			}
		}
	}
}

func TestUIRealConnectionEventsStatusAndStop(t *testing.T) {
	h := newHost(t)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "body") }))
	defer target.Close()
	text := fixture(t, map[string]any{"security": map[string]any{"allow_loopback": true}, "dns": map[string]any{"server": "system"}, "routing": map[string]any{"rules": []any{map[string]any{"domain": "rejected.invalid", "action": "reject"}}}})
	if _, e := applyLegacyFixture(h, text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	proxy, _ := url.Parse("http://" + portAddress(h.doc.client.HTTPPort))
	tr := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}
	r, e := client.Get(target.URL)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, r.Body)
	r.Body.Close()
	if r, e = client.Get("http://rejected.invalid/"); e == nil {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	end := time.Now().Add(3 * time.Second)
	var logs ConnectionLogsReply
	for time.Now().Before(end) {
		logs = uiRequest(t, h, "logs.connections", `{}`).(ConnectionLogsReply)
		v := uiRequest(t, h, "connections.list", `{}`).(map[string]any)
		if len(logs.Entries) >= 2 && len(v["closed"].([]kernel.ClosedConn)) >= 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	ok, rejected := false, false
	for _, v := range logs.Entries {
		if v.Outcome == "ok" && len(v.Chain) > 0 {
			ok = true
		}
		if v.Outcome == "rejected" && v.Code == "rejected" {
			rejected = true
		}
	}
	if !ok || !rejected {
		t.Fatal(logs)
	}
	h.mu.Lock()
	view := h.server.ClientStatusView()
	sn := view.Cumulative
	total := h.server.TotalConnections()
	h.mu.Unlock()
	st := h.Status().(map[string]any)
	traffic := st["traffic"].(map[string]any)
	if uiJSON(traffic["rules"]) != uiJSON(sn.Rules) || traffic["rules_since"] == nil || st["connections"].(map[string]any)["total"] != total {
		t.Fatal("status changed label/order/total")
	}
	byTarget := map[string]uint64{}
	for _, row := range traffic["rule_targets"].([]map[string]any) {
		byTarget[row["name"].(string)] = row["hits"].(uint64)
	}
	if byTarget["direct"] != 1 || byTarget["reject"] != 1 {
		t.Fatal("rule targets did not use final/direct/reject actual decisions", byTarget)
	}
	counts := st["connections"].(map[string]any)
	if counts["tcp"] != view.TCP || counts["udp"] != view.UDP {
		t.Fatal("TCP/UDP counters do not match runtime snapshot")
	}
	// The detailed log must never be copied into logs.get or persistence.
	if strings.Contains(uiJSON(uiRequest(t, h, "logs.get", `{}`)), "rejected.invalid") {
		t.Fatal("private log polluted safe logs")
	}
	before := h.connectionLogs.read(0, 500)
	if _, e := h.Stop(); e != nil {
		t.Fatal(e)
	}
	if uiJSON(h.connectionLogs.read(0, 500)) != uiJSON(before) {
		t.Fatal("stop cleared connection logs")
	}
	v := uiRequest(t, h, "connections.list", `{}`).(map[string]any)
	if v["total"] != nil || len(v["closed"].([]kernel.ClosedConn)) != 0 {
		t.Fatal(v)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	v = uiRequest(t, h, "connections.list", `{}`).(map[string]any)
	if len(v["closed"].([]kernel.ClosedConn)) != 0 {
		t.Fatal("restart retained history")
	}
	entries, _ := os.ReadDir(h.workspace)
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "connection") || strings.Contains(entry.Name(), "log") {
			t.Fatal("memory history written", entry.Name())
		}
	}
}

func TestUIResourcesNoCredentialsAndLocalUnsupported(t *testing.T) {
	h := newHost(t)
	dir := t.TempDir()
	rules := filepath.Join(dir, "r.txt")
	provider := filepath.Join(dir, "p.json")
	if e := os.WriteFile(rules, []byte("+.example.com\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(provider, []byte(`socks5://127.0.0.1:9#node`), 0600); e != nil {
		t.Fatal(e)
	}
	text := fixture(t, map[string]any{
		"providers": []any{map[string]any{"name": "local", "type": "file", "path": provider}},
		"rule_sets": []any{map[string]any{"name": "ads", "format": "domain", "path": rules}, map[string]any{"name": "remote", "format": "domain", "path": filepath.Join(dir, "missing"), "url": "https://127.0.0.1:1/private?token=SECRET"}},
		"geoip":     map[string]any{"path": filepath.Join(dir, "country.mmdb")}, "asn": map[string]any{"path": filepath.Join(dir, "asn.mmdb")},
	})
	if _, e := applyLegacyFixture(h, text); e != nil {
		t.Fatal(e)
	}
	stopped := uiJSON(uiRequest(t, h, "resources.list", `{}`))
	for _, secret := range []string{"SECRET", "token", "private", dir, provider} {
		if strings.Contains(stopped, secret) {
			t.Fatal("stopped leak", secret)
		}
	}
	if !strings.Contains(stopped, `"state":"pending"`) {
		t.Fatal(stopped)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	out := uiJSON(uiRequest(t, h, "resources.list", `{}`))
	for _, secret := range []string{"SECRET", "token", "private", dir, "url", "path", "last_error"} {
		if strings.Contains(out, secret) {
			t.Fatal("running leak", secret, out)
		}
	}
	if !strings.Contains(out, `"kind":"rule_set","name":"ads"`) || !strings.Contains(out, `"entries":1`) || !strings.Contains(out, `"state":"missing"`) {
		t.Fatal(out)
	}
	if r, e := h.Request(context.Background(), "resources.refresh", json.RawMessage(`{"kind":"rule_set","name":"ads"}`)); e != nil || r.(map[string]any)["action"] != "reloaded" {
		t.Fatal(r, e)
	}
	for _, raw := range []string{`{"kind":"geoip","name":"geoip"}`, `{"kind":"asn","name":"asn"}`} {
		if _, e := h.Request(context.Background(), "resources.refresh", json.RawMessage(raw)); e == nil || e.Code != "resource_refresh_failed" {
			t.Fatal(raw, e)
		}
	}
	if _, e := h.Request(context.Background(), "resources.refresh", json.RawMessage(`{"kind":"rule_set","name":"unknown"}`)); e == nil || e.Code != "unsupported" {
		t.Fatal(e)
	}
	if _, e := h.Request(context.Background(), "resources.refresh", json.RawMessage(`{"kind":"rule_set","name":"remote"}`)); e == nil || (e.Code != "resource_refresh_failed" && e.Code != "subscription_resource_failed") || strings.Contains(uiJSON(e), "SECRET") {
		t.Fatal(e)
	}
	// Standalone legacy provider methods are no longer a client capability.
	if _, e := h.Request(context.Background(), "provider.refresh", json.RawMessage(`{"name":"local"}`)); e == nil || e.Code != "unknown_method" {
		t.Fatal(e)
	}
	if _, e := h.Request(context.Background(), "resources.refresh", json.RawMessage(`{"kind":"provider","name":"local"}`)); e == nil || e.Code != "invalid_params" {
		t.Fatal(e)
	}
	if strings.Contains(out, `"kind":"provider"`) {
		t.Fatal("legacy provider leaked as a client resource", out)
	}
}

func TestUIDNSPublicChainResultAndErrorCodes(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, addr, e := pc.ReadFrom(buf)
			if e != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil || len(m.Questions) != 1 {
				continue
			}
			q := m.Questions[0]
			out := dnsmessage.Message{Header: dnsmessage.Header{ID: m.ID, Response: true, RecursionAvailable: true}, Questions: m.Questions}
			if q.Name.String() == "negative.example." {
				out.Header.RCode = dnsmessage.RCodeNameError
			} else if q.Type == dnsmessage.TypeA {
				out.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}}}}
			}
			wire, e := out.Pack()
			if e == nil {
				pc.WriteTo(wire, addr)
			}
		}
	}()
	t.Cleanup(func() { pc.Close(); <-done })
	h := newHost(t)
	text := fixture(t, map[string]any{"dns": map[string]any{"servers": []string{pc.LocalAddr().String()}}})
	if _, e := applyLegacyFixture(h, text); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	a := uiRequest(t, h, "dns.query", `{"name":"Query.Example."}`).(kernel.DNSQueryReply)
	if a.Name != "query.example" || a.Server != "UDP "+pc.LocalAddr().String() || a.Cached || len(a.Addresses) != 1 || a.Addresses[0].Addr != "192.0.2.1" {
		t.Fatal(a)
	}
	b := uiRequest(t, h, "dns.query", `{"name":"query.example","type":"AAAA"}`).(kernel.DNSQueryReply)
	if b.Cached || b.Server != "IPv6 已关闭" || len(b.Addresses) != 0 {
		t.Fatal(b)
	}
	for _, tc := range []struct{ raw, code string }{{`{"name":"bad name"}`, "invalid_name"}, {`{"name":"negative.example"}`, "dns_failed"}} {
		if _, e := h.Request(context.Background(), "dns.query", json.RawMessage(tc.raw)); e == nil || e.Code != tc.code {
			t.Fatal(tc, e)
		}
	}
}

func TestUIDNSStopCancelsAndDrainsInFlight(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(chan struct{}, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			_, _, e := pc.ReadFrom(b)
			if e != nil {
				return
			}
			select {
			case seen <- struct{}{}:
			default:
			}
		}
	}()
	t.Cleanup(func() { pc.Close(); <-done })
	h := newHost(t)
	if _, e := applyLegacyFixture(h, fixture(t, map[string]any{"dns": map[string]any{"servers": []string{pc.LocalAddr().String()}}, "limits": map[string]any{"dial_timeout": "10s"}})); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	result := make(chan *Error, 1)
	go func() {
		_, e := h.Request(context.Background(), "dns.query", json.RawMessage(`{"name":"wait.example"}`))
		result <- e
	}()
	select {
	case <-seen:
	case <-time.After(time.Second):
		t.Fatal("query never reached configured DNS")
	}
	started := time.Now()
	if _, e := h.Stop(); e != nil {
		t.Fatal(e)
	}
	if time.Since(started) > time.Second {
		t.Fatal("stop failed to cancel operation")
	}
	select {
	case e := <-result:
		if e == nil || e.Code != "dns_failed" {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("stop failed to finish canceled request")
	}
}
