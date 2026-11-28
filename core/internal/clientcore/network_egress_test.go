package clientcore

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/provider"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestK2IPv6DocumentMigrationAndCompatibility(t *testing.T) {
	for _, format := range []DocumentFormat{FormatJSON, FormatYAML} {
		dir := t.TempDir()
		text := strings.Replace(initialDocument, `,"ipv6":false`, "", 1)
		if format == FormatYAML {
			text = yamlFixture(17890, 17891)
		}
		path := filepath.Join(dir, format.filename())
		if e := os.WriteFile(path, []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
		h, e := Open(dir)
		if e != nil {
			t.Fatal(e)
		}
		if h.doc.client.IPv6 || !h.doc.config.IPv6Disabled() {
			t.Fatal("migration not applied")
		}
		backup, e := os.ReadFile(filepath.Join(dir, "client-before-c16-network."+string(format)))
		if e != nil || string(backup) != text {
			t.Fatal("exact backup", e)
		}
		report, e := os.ReadFile(filepath.Join(dir, "c16-network-migration.json"))
		if e != nil || !strings.Contains(string(report), "client.ipv6=false") {
			t.Fatal("migration report", e)
		}
		root, _ := sourceJSON(h.doc)
		var cl map[string]json.RawMessage
		_ = json.Unmarshal(root["client"], &cl)
		cl["ipv6"] = rawJSON(true)
		root["client"] = rawJSON(cl)
		next, e := renderSubscriptionSource(h.doc, root)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := h.Apply(next, format); e != nil {
			t.Fatal(e)
		}
		h.Close()
		h, e = Open(dir)
		if e != nil {
			t.Fatal(e)
		}
		if !h.doc.client.IPv6 || h.doc.config.IPv6Disabled() {
			t.Fatal("one-time migration reset explicit later choice")
		}
		h.Close()
	}
	for _, value := range []string{"null", `"false"`, "0", "[]", "{}"} {
		text := strings.Replace(initialDocument, `"ipv6":false`, `"ipv6":`+value, 1)
		if _, e := parseDocument(text, t.TempDir()); e == nil {
			t.Fatal("accepted", value)
		}
	}
	if d, e := parseDocument(strings.Replace(initialDocument, `,"ipv6":false`, "", 1), t.TempDir()); e != nil || d.client.IPv6 {
		t.Fatal("old document compatibility", e)
	}
}
func TestK2DownloadPolicyAndClearIPC(t *testing.T) {
	h, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	ctx, done := h.ipContext(context.Background())
	defer done()
	if !ipDisabled(ctx) || ipNetwork(ctx) != "ip4" {
		t.Fatal("default downloads not v4")
	}
	h.setIPPolicy(false)
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("old download epoch not canceled")
	}
	if _, e := h.Request(context.Background(), "dns.cache.clear", json.RawMessage(`{}`)); e == nil || e.Code != "core_not_running" {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	v, failure := h.Request(context.Background(), "dns.cache.clear", json.RawMessage(`{}`))
	if failure != nil || v.(map[string]any)["cleared"] != 0 {
		t.Fatal(v, failure)
	}
	if _, e := h.Request(context.Background(), "dns.cache.clear", json.RawMessage(`{"unknown":true}`)); e == nil {
		t.Fatal("invalid clear params")
	}
}

func TestK2YAMLMihomoPolicyRetainsDeclarationOrder(t *testing.T) {
	text := yamlFixture(17890, 17891) + "\n"
	text = strings.Replace(text, "  dns: {server: system}", "  dns:\n    server: system\n    nameserver-policy:\n      +.example.com: 1.1.1.1\n      a.example.com: 8.8.8.8", 1)
	d, e := parseDocument(text, t.TempDir(), FormatYAML)
	if e != nil {
		t.Fatal(e)
	}
	rules, err := kernel.DecodeMihomoDNSPolicy(d.config.DNS.NameserverPolicy)
	if err != nil || len(rules) != 2 || rules[0].Match != "domain_suffix" {
		t.Fatal(rules, err)
	}
	if d.text != text {
		t.Fatal("source rewritten")
	}
}

func TestK2DNSDocumentStyleAndExclusion(t *testing.T) {
	native := strings.Replace(yamlFixture(17890, 17891), "  dns: {server: system}", `  dns:
    server: system
    rules:
      - {match: domain_suffix, domain: example.com, servers: [1.1.1.1, 8.8.8.8]}
      - {match: keyword, domain: internal, servers: [9.9.9.9, 'tcp://1.0.0.1:53']}
      - {match: domain, domain: exact.test, servers: [8.8.4.4]}
    hosts: {'*.local.test': [192.0.2.1, '2001:db8::1']}`, 1)
	projection, err := yamlJSON([]byte(native))
	if err != nil {
		t.Fatal(err)
	}
	h := newHost(t)
	var before []kernel.DNSRule
	for _, f := range []DocumentFormat{FormatJSON, FormatYAML, FormatJSON, FormatYAML} {
		text := native
		if f == FormatJSON {
			text = string(projection)
		}
		if _, failure := h.Apply(text, f); failure != nil {
			t.Fatal(f, failure)
		}
		if h.doc.text != text || h.doc.format != f {
			t.Fatal("source export changed", f)
		}
		if h.doc.config.DNS.NameserverPolicy != nil || len(h.doc.config.DNS.Rules) != 3 || h.doc.config.DNS.Rules[1].Match != "keyword" {
			t.Fatal("keyword was converted", f, h.doc.config.DNS)
		}
		if before != nil && !reflect.DeepEqual(before, h.doc.config.DNS.Rules) {
			t.Fatal("format switch changed keyword rules")
		}
		before = h.doc.config.DNS.Rules
		root, _ := sourceJSON(h.doc)
		var kernelSource map[string]json.RawMessage
		_ = json.Unmarshal(root["kernel"], &kernelSource)
		var dns map[string]json.RawMessage
		_ = json.Unmarshal(kernelSource["dns"], &dns)
		if dns["rules"] == nil || dns["nameserver-policy"] != nil {
			t.Fatal("source representation lost", f)
		}
	}
	policy := strings.Replace(yamlFixture(17890, 17891), "  dns: {server: system}", `  dns:
    server: system
    nameserver-policy:
      +.example.com: [1.1.1.1, 8.8.8.8]
      exact.test: 9.9.9.9`, 1)
	policyJSON, err := yamlJSON([]byte(policy))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []DocumentFormat{FormatJSON, FormatYAML} {
		text := policy
		if f == FormatJSON {
			text = string(policyJSON)
		}
		if _, failure := h.Apply(text, f); failure != nil {
			t.Fatal(f, failure)
		}
		rules, err := kernel.DecodeMihomoDNSPolicy(h.doc.config.DNS.NameserverPolicy)
		if err != nil || len(rules) != 2 || rules[0].Match != "domain_suffix" || len(rules[0].Servers) != 2 || rules[1].Match != "domain" {
			t.Fatal("policy import", f, rules, err)
		}
		if h.doc.text != text || len(h.doc.config.DNS.Rules) != 0 {
			t.Fatal("policy export spelling changed", f)
		}
	}
	mixed := strings.Replace(native, "    rules:\n", "    nameserver-policy: {'+.example.com': 1.1.1.1}\n    rules:\n", 1)
	mixedJSON, err := yamlJSON([]byte(mixed))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []DocumentFormat{FormatJSON, FormatYAML} {
		text := mixed
		if f == FormatJSON {
			text = string(mixedJSON)
		}
		if _, failure := parseDocument(text, t.TempDir(), f); failure == nil {
			t.Fatal("rules and nameserver-policy both accepted", f)
		}
	}
}

// A normal TCP half-close finishes the request, not the response stream.
func TestC46HTTPConnectPreservesResponseAfterUploadEOF(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	request := []byte("request body complete")
	reply := bytes.Repeat([]byte("response after request EOF\n"), 4096)
	serverDone := make(chan error, 1)
	go func() {
		c, e := target.Accept()
		if e != nil {
			serverDone <- e
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		got, e := io.ReadAll(c)
		if e == nil && !bytes.Equal(got, request) {
			e = fmt.Errorf("request changed")
		}
		if e == nil {
			_, e = c.Write(reply)
		}
		serverDone <- e
	}()
	up, err := kernel.Start(kernel.Config{Inbounds: []kernel.Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0"}}, Security: &kernel.SecurityOptions{AllowLoopback: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close(context.Background())
	b, err := newHTTPBridge(0, up.Addresses()[0].(*net.TCPAddr).Port, func(e kernel.ClientLogEvent) {
		if d := e.Diagnostic; d != nil {
			t.Logf("bridge seq=%v action=%s direction=%s trigger=%s category=%s", d.ObservationSeq, d.Action, d.Direction, d.Trigger, d.Category)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	b.start()
	defer b.close()
	conn, err := net.Dial("tcp4", b.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	dst := target.Addr().String()
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dst, dst)
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("CONNECT: %v", err)
	}
	if _, err = conn.Write(request); err != nil {
		t.Fatal(err)
	}
	if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(br)
	serverErr := <-serverDone
	if readErr != nil || serverErr != nil || !bytes.Equal(got, reply) {
		t.Fatalf("half-close truncated response: got=%d want=%d read=%v target=%v", len(got), len(reply), readErr, serverErr)
	}
}

func TestC46HTTPBridgeCloseStillCancelsTunnel(t *testing.T) {
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	ready := make(chan struct{})
	targetDone := make(chan error, 1)
	go func() {
		c, e := target.Accept()
		if e != nil {
			targetDone <- e
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		var one [1]byte
		_, e = io.ReadFull(c, one[:])
		if e == nil {
			close(ready)
			_, e = io.Copy(io.Discard, c)
		}
		targetDone <- e
	}()
	up, err := kernel.Start(kernel.Config{Inbounds: []kernel.Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0"}}, Security: &kernel.SecurityOptions{AllowLoopback: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close(context.Background())
	b, err := newHTTPBridge(0, up.Addresses()[0].(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	b.start()
	defer b.close()
	conn, err := net.Dial("tcp4", b.listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	dst := target.Addr().String()
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", dst, dst)
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("CONNECT: %v", err)
	}
	if _, err = conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("target did not receive ordinary payload")
	}
	closed := make(chan struct{})
	go func() { b.close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("bridge shutdown did not cancel active tunnel")
	}
	if _, err = br.ReadByte(); err == nil {
		t.Fatal("tunnel remained open")
	}
	select {
	case <-targetDone:
	case <-time.After(3 * time.Second):
		t.Fatal("target side did not close")
	}
}

// Real Host and production preview route; the fetch seam only pauses network
// work to deterministically observe lifecycle cancellation. No token/UAC mock.
func TestC50ControlNilPolicyPreviewCanceledWithoutProxyHint(t *testing.T) {
	h, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	entered := make(chan context.Context, 1)
	done := make(chan *Error, 1)
	h.fullFetch = func(ctx context.Context, _ string, p *clientegress.Policy, _ int64) ([]byte, error) {
		if p != nil {
			t.Error("ordinary request unexpectedly acquired a policy")
		}
		entered <- ctx
		<-ctx.Done()
		return nil, ctx.Err()
	}
	go func() {
		_, e := h.previewSubscription(context.Background(), json.RawMessage(`{"url":"https://example.com/ordinary","full_only":true}`))
		done <- e
	}()
	var request context.Context
	select {
	case request = <-entered:
	case <-time.After(time.Second):
		t.Fatal("preview never admitted")
	}
	h.mu.Lock()
	h.cancelBootstrapLocked()
	if request.Err() == nil {
		h.mu.Unlock()
		t.Fatal("activation returned before nested child cancellation")
	}
	h.mu.Unlock()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("canceled preview accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("download blocked Host lifecycle")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fullPending != nil || len(h.fullCandidates) != 0 {
		t.Fatal("canceled preview published state")
	}
}

func TestC50ControlBootstrapSynchronousCancelAndParent(t *testing.T) {
	h := &Host{}
	type key struct{}
	parent, cancel := context.WithTimeout(context.WithValue(context.Background(), key{}, "preserved"), time.Second)
	defer cancel()
	h.mu.Lock()
	first, stop := h.bootstrapContextLocked(parent)
	second, stop2 := h.bootstrapContextLocked(parent)
	h.mu.Unlock()
	defer stop()
	defer stop2()
	if first.Value(key{}) != "preserved" {
		t.Fatal("parent values lost")
	}
	if _, ok := first.Deadline(); !ok {
		t.Fatal("parent budget lost")
	}
	nested, end := context.WithTimeout(first, time.Second)
	defer end()
	h.mu.Lock()
	h.cancelBootstrapLocked()
	if first.Err() == nil || second.Err() == nil || nested.Err() == nil {
		h.mu.Unlock()
		t.Fatal("only asynchronously canceled a request")
	}
	next, stop3 := h.bootstrapContextLocked(context.Background())
	h.mu.Unlock()
	defer stop3()
	if next.Err() != nil {
		t.Fatal("new ordinary lifecycle inherited stale cancellation")
	}
	cancel()
	if first.Err() == nil {
		t.Fatal("parent cancellation lost")
	}
}

func TestC50ControlFrozenSwitchBlocksBootstrapEvenWithNilPolicy(t *testing.T) {
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	n, _ := strconv.Atoi(port)
	var s clientegress.Switch
	s.FreezeNew()
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), hostEgressKey{}, hostEgressRequest{switcher: &s, ordinary: true}), time.Second)
	defer cancel()
	// A real loopback listener makes a missing Switch hook observable without
	// connecting to any external host or sending target/proxy bytes.
	if c, e := dialBootstrap(ctx, "example.com:443", &bootstrapProxy{Host: "127.0.0.1", Port: uint16(n)}, nil, nil, nil); e == nil {
		c.Close()
		t.Fatal("frozen nil-policy request dialed")
	}
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Millisecond))
	if c, e := listener.Accept(); e == nil {
		c.Close()
		t.Fatal("old ordinary route opened a socket while Switch frozen")
	}
}

func TestC50ControlSnapshotGuardNeverInfersOrdinary(t *testing.T) {
	var s clientegress.Switch
	contextFor := func(ordinary bool) context.Context {
		p, g, f := s.PolicySnapshot()
		return context.WithValue(context.Background(), hostEgressKey{}, hostEgressRequest{switcher: &s, policy: p, generation: g, ordinary: ordinary, frozen: f})
	}
	if checkHostEgress(contextFor(false)) == nil {
		t.Fatal("nil controlled policy fell back to direct")
	}
	ordinary := contextFor(true)
	if checkHostEgress(ordinary) != nil {
		t.Fatal("explicit ordinary mode lost")
	}
	s.FreezeNew()
	if checkHostEgress(ordinary) == nil || checkHostEgress(contextFor(true)) == nil {
		t.Fatal("nil fence hidden")
	}
	s.ReleasePhysical()
	if checkHostEgress(contextFor(true)) != nil {
		t.Fatal("clean explicit ordinary release lost")
	}
	p := clientegress.Blocked()
	s.Replace(p)
	failed := contextFor(false)
	if checkHostEgress(failed) == nil {
		t.Fatal("failed policy admitted")
	}
	s.ReleasePhysical()
	if checkHostEgress(failed) == nil {
		t.Fatal("same generation 0 but different policy accepted")
	}
}

func TestC50ControlIconWithoutProxyHintSharesLifecycle(t *testing.T) {
	h, e := Open(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	entered := make(chan context.Context, 1)
	done := make(chan error, 1)
	h.iconFetch = func(ctx context.Context, _ string) ([]byte, error) {
		entered <- ctx
		<-ctx.Done()
		return nil, ctx.Err()
	}
	go func() { _, e := h.fetchIcon(context.Background(), "https://example.com/icon.png"); done <- e }()
	var request context.Context
	select {
	case request = <-entered:
	case <-time.After(time.Second):
		t.Fatal("icon fetch not entered")
	}
	h.mu.Lock()
	h.cancelBootstrapLocked()
	if request.Err() == nil {
		h.mu.Unlock()
		t.Fatal("icon not synchronously canceled")
	}
	h.mu.Unlock()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("old icon download accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("icon download blocked lifecycle")
	}
}

func TestR6ProxyHostnameBypassesFakeIPResolverOnce(t *testing.T) {
	for _, target := range []string{"sub.siaoz.com:443", "8.8.8.8:443", "raw.githubusercontent.com:443"} {
		t.Run(target, func(t *testing.T) {
			resolveCalls, dials, verified := 0, 0, 0
			var received string
			peerDone := make(chan struct{})
			c, e := dialBootstrapIO(context.Background(), target, &bootstrapProxy{Host: "127.0.0.1", Port: 7890}, nil, func(context.Context, string) ([]netip.Addr, error) {
				resolveCalls++
				return checkedImportAddresses([]netip.Addr{netip.MustParseAddr("198.18.0.42")}, nil)
			}, nil,
				func(context.Context, *net.Dialer, string) (net.Conn, error) {
					dials++
					a, b := net.Pipe()
					go func() {
						defer close(peerDone)
						defer b.Close()
						req, err := http.ReadRequest(bufio.NewReader(b))
						if err == nil {
							received = req.Host
							b.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
						}
					}()
					return a, nil
				}, func(net.Conn) error { verified++; return nil })
			if e != nil {
				t.Fatal(e)
			}
			c.Close()
			<-peerDone
			if received != target || resolveCalls != 0 || dials != 1 || verified != 1 {
				t.Fatal(received, resolveCalls, dials, verified)
			}
		})
	}
}
func TestR6ProxyPrivateLiteralAndLocalhostRefusedBeforeIO(t *testing.T) {
	for _, target := range []string{"10.1.2.3:443", "198.18.1.2:443", "[::1]:443", "127.0.0.1:443", "localhost:443", "foo.localhost:443", "LOCALHOST:443", "Foo.Localhost.:443", "localhost.:443"} {
		_, e := dialBootstrapIO(context.Background(), target, &bootstrapProxy{Host: "127.0.0.1", Port: 7890}, nil, func(context.Context, string) ([]netip.Addr, error) {
			t.Fatal("resolved forbidden target")
			return nil, nil
		}, nil, func(context.Context, *net.Dialer, string) (net.Conn, error) {
			t.Fatal("dialed forbidden target")
			return nil, nil
		}, func(net.Conn) error { t.Fatal("verified forbidden target"); return nil })
		assertDetail(t, e, "resolve", "address_refused")
	}
}
func TestR6DirectFakeIPClassificationStillRefusesAllReserved(t *testing.T) {
	for _, tc := range []struct{ ip, category string }{{"198.18.0.0", "fake_ip"}, {"198.18.1.42", "fake_ip"}, {"198.19.255.255", "fake_ip"}, {"10.0.0.1", "address_refused"}, {"127.0.0.1", "address_refused"}, {"198.20.0.1", ""}, {"142.91.102.205", ""}, {"192.0.2.1", "address_refused"}, {"::1", "address_refused"}} {
		ips, e := checkedImportAddresses([]netip.Addr{netip.MustParseAddr(tc.ip)}, nil)
		if tc.category == "" {
			if e != nil || len(ips) != 1 {
				t.Fatal(tc, e)
			}
			continue
		}
		assertDetail(t, e, "resolve", tc.category)
		if ips != nil {
			t.Fatal("refused destination leaked through")
		}
	}
	// The same exact resolver-result check propagates through HTTP error
	// wrapping and resource detail without becoming a generic connect failure.
	for _, tc := range []struct{ ip, category string }{{"198.18.22.1", "fake_ip"}, {"10.1.1.1", "address_refused"}} {
		_, e := fetchImportBounded(context.Background(), "https://sub.siaoz.com", nil, func(tr *http.Transport) http.RoundTripper {
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				_, err := checkedImportAddresses([]netip.Addr{netip.MustParseAddr(tc.ip)}, nil)
				return nil, err
			})
		}, 1024)
		assertDetail(t, e, "resolve", tc.category)
		d := resourceError(context.Background(), "subscription", 0, "download", "connect", "unknown", e)
		if d.Code != "subscription_fetch_failed" || d.Detail.Category != tc.category || d.Detail.Route != "direct" {
			t.Fatal(d)
		}
	}
}

func TestR11ResourceRouteMainSavedModeDependenciesRunningKernel(t *testing.T) {
	for _, running := range []bool{false, true} {
		for _, proxy := range []bool{false, true} {
			h := fullHost(t)
			if _, e := h.Apply(fixture(t, map[string]any{})); e != nil {
				t.Fatal(e)
			}
			if running {
				if _, e := h.Start(); e != nil {
					t.Fatal(e)
				}
			}
			var main, resources int
			h.fullFetch = func(ctx context.Context, url string, _ *clientegress.Policy, _ int64) ([]byte, error) {
				k, _ := ctx.Value(resourceKernelKey{}).(bool)
				if strings.Contains(url, "main.yaml") {
					main++
					if k || bootstrapFrom(ctx) != nil {
						t.Error("main ignored saved route")
					}
					return []byte(strings.Replace(fullFixture, "rules:\n", "rule-providers:\n  r: {type: http, behavior: domain, url: 'https://example.org/rules.yaml'}\nrules:\n  - RULE-SET,r,pick\n", 1)), nil
				}
				resources++
				if k != running {
					t.Error("resource wrong route")
				}
				if !running && ((bootstrapFrom(ctx) != nil) != proxy) {
					t.Error("stopped resource ignored saved route")
				}
				return []byte("payload:\n - example.org\n"), nil
			}
			p := map[string]any{"url": "https://example.org/main.yaml"}
			if proxy {
				p["_system_proxy"] = &bootstrapProxy{Host: "127.0.0.1", Port: 7890}
				p["_egress"] = &bootstrapEgress{}
			}
			_, e := h.previewSubscription(context.Background(), rawJSON(p))
			if e != nil || main != 1 || resources != 1 {
				t.Fatal("routes not fully exercised", e, main, resources)
			}
		}
	}
}
func TestR11RuntimeResourceRealRegisteredSOCKSAndRouteFailure(t *testing.T) {
	h := fullHost(t)
	var calls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		io.WriteString(w, "payload: [example.org]")
	}))
	defer target.Close()
	doc := fixture(t, map[string]any{"security": map[string]any{"allow_loopback": true}, "routing": map[string]any{"final": "reject"}})
	if _, e := h.Apply(doc); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	ctx := context.WithValue(context.Background(), resourceKernelKey{}, true)
	const resource = "https://resource-fixture.invalid/file"
	_, err := h.fetchFull(ctx, resource, nil, 1024)
	if err == nil || calls.Load() != 0 {
		t.Fatal("resource silently bypassed kernel rules")
	}
	e := resourceError(ctx, "rule_set", 2, "download", "connect", "unknown", err)
	b, _ := json.Marshal(e)
	if !strings.Contains(string(b), "kernel_rules") {
		t.Fatal("actual route missing")
	}
	if _, e := h.Stop(); e != nil {
		t.Fatal(e)
	}
	_, err = h.fetchFull(ctx, resource, nil, 1024)
	if err == nil {
		t.Fatal("lost runtime silently fell back")
	}
	doc = fixture(t, map[string]any{"security": map[string]any{"allow_loopback": true}, "routing": map[string]any{"final": "direct"}})
	if _, e := h.Apply(doc); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	// A resource may no longer use the loopback HTTP endpoint as a
	// successful Direct fixture, even if normal client traffic allows it.
	if _, err = h.fetchFull(ctx, target.URL, nil, 1024); err == nil || calls.Load() != 0 {
		t.Fatal("private resource accepted")
	}
	// Exercise the same no-TUN, registered SOCKS transport with a permitted
	// ordinary asset. No deployment or public network is required.
	out, err := h.fetchKernelAsset(context.Background(), target.URL, 1024)
	if err != nil || string(out) != "payload: [example.org]" || calls.Load() != 1 {
		t.Fatal("no TUN direct rule SOCKS route failed", err)
	}
	if h.egress != nil {
		t.Fatal("test unexpectedly depended on TUN")
	}
}
func TestR11IconFailureLogNoTunAndStageGroupSurvives(t *testing.T) {
	h := fullHost(t)
	doc := fixture(t, map[string]any{"groups": []any{map[string]any{"name": "HK", "type": "select", "members": []string{"direct"}}}})
	if _, e := h.Apply(doc); e != nil {
		t.Fatal(e)
	}
	h.iconFetch = func(context.Context, string) ([]byte, error) { return nil, dl("connect", "timeout") }
	h.getIcon(context.Background(), rawJSON(map[string]any{"url": "https://example.org/icon?token=SECRET", "group": "HK"}))
	b, _ := json.Marshal(h.logs.read(0, 500))
	if !strings.Contains(string(b), "HK") || !strings.Contains(string(b), "icon_connect_failed") || !strings.Contains(string(b), "timeout") || strings.Contains(string(b), "SECRET") {
		t.Fatal("missing private-safe exported failure")
	}
}

func TestR11LocalResourcesFreshSkipAndExpiredOfflineKeepAccepted(t *testing.T) {
	h := fullHost(t)
	config := strings.Replace(fullFixture, "rules:\n", "rule-providers:\n  r: {type: http, behavior: domain, url: 'https://example.org/rules.yaml', interval: 3600}\nrules:\n  - RULE-SET,r,pick\n", 1)
	calls := 0
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		calls++
		return []byte("payload: [example.org]"), nil
	}
	p := fullPreview(t, h, config, "")
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	if calls != 1 {
		t.Fatal(calls)
	}
	root, _ := sourceJSON(h.doc)
	owners, _ := subscriptionsOf(root)
	id := owners[0].ID
	if len(owners[0].Resources) != 1 {
		t.Fatal("not persisted")
	}
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		calls++
		return nil, dl("connect", "timeout")
	}
	p = fullPreview(t, h, config, id)
	if calls != 1 {
		t.Fatal("fresh local resource fetched again")
	}
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal(e)
	}
	root, _ = sourceJSON(h.doc)
	owners, _ = subscriptionsOf(root)
	for key, v := range owners[0].Resources {
		v.Updated -= 7200
		owners[0].Resources[key] = v
	}
	root["subscriptions"] = rawJSON(owners)
	text := string(rawJSON(root))
	if _, e := h.Apply(text); e != nil {
		t.Fatal(e)
	}
	p = fullPreview(t, h, config, id)
	if calls != 2 {
		t.Fatal("expired resource not retried")
	}
	if _, e := h.Apply(p.Text); e != nil {
		t.Fatal("offline refresh discarded old valid resource", e)
	}
	workspace := h.workspace
	h.Close()
	fresh, e := Open(workspace)
	if e != nil {
		t.Fatal("offline restart cannot load local rule", e)
	}
	defer fresh.Close()
	if len(fresh.doc.config.RuleSets) == 0 {
		t.Fatal("local rules missing")
	}
}

// Opt-in authorized real input. Never include URL queries, node endpoints or
// credentials in failures/reports. The core, rules and actual SOCKS path are real.
func TestR12AuthorizedResourceRoute(t *testing.T) {
	file := os.Getenv("KAT_R12_PRIVATE_SOURCE")
	if file == "" {
		t.Skip("authorized real input not supplied")
	}
	b, e := os.ReadFile(file)
	if e != nil {
		t.Fatal("private input unavailable")
	}
	h := fullHost(t)
	v, er := h.previewSubscription(context.Background(), rawJSON(map[string]any{"text": string(b)}))
	if er != nil {
		t.Fatalf("initial direct import failed: %s detail=%+v", er.Code, er.Detail)
	}
	p := v.(subscriptionPreview)
	if dir := os.Getenv("KAT_R12_PRIVATE_DIR"); dir != "" {
		os.WriteFile(dir+"/core-source.json", []byte(p.Text), 0600)
	}
	if len(p.Issues) > 0 {
		t.Fatal("real subscription conversion issues")
	}
	if _, er = h.Apply(p.Text, p.Format); er != nil {
		t.Fatal("real subscription apply failed", er.Code)
	}
	if _, er = h.Start(); er != nil {
		t.Fatal("real core start failed", er.Code)
	}
	report := map[string]any{"nodes": len(h.doc.config.Outbounds), "groups": len(h.doc.config.Groups), "rules": h.doc.config.Routing.Rules}
	// The rules contain only matcher/target names, not source URLs or credentials.
	rows := []map[string]any{}
	full, err := provider.ParseFull(b, h.doc.client.ProbeURL)
	if err != nil {
		t.Fatal("real provider parse failed")
	}
	for i, rs := range full.RuleSets {
		if i != 3 {
			continue
		}
		u, _ := url.Parse(rs.URL)
		row := map[string]any{"ordinal": i + 1, "host": u.Hostname(), "path": u.Path}
		before := h.connectionLogs.read(0, 500).NextSeq
		start := time.Now()
		_, err := h.fetchKernelAsset(context.Background(), rs.URL, 16<<20)
		row["elapsed_ms"] = time.Since(start).Milliseconds()
		if err != nil {
			row["kernel_error"] = safeFailure(context.Background(), "connect", err).Error()
		} else {
			row["kernel_success"] = true
		}
		row["connection_events"] = h.connectionLogs.read(before, 500).Entries
		row["connections"], _ = h.listConnections(rawJSON(map[string]any{"closed_limit": 30}))
		ctx := context.WithValue(context.Background(), resourceKernelKey{}, false)
		start = time.Now()
		_, err = h.fetchFull(ctx, rs.URL, nil, 16<<20)
		row["direct_elapsed_ms"] = time.Since(start).Milliseconds()
		if err != nil {
			row["direct_error"] = safeFailure(context.Background(), "connect", err).Error()
		} else {
			row["direct_success"] = true
		}
		ctx = context.WithValue(context.Background(), resourceKernelKey{}, true)
		start = time.Now()
		out, fallbackErr := h.fetchSubscriptionResource(ctx, rs.URL, nil, 16<<20)
		row["fallback_elapsed_ms"] = time.Since(start).Milliseconds()
		row["fallback_success"] = fallbackErr == nil && len(out) > 0
		if fallbackErr != nil {
			t.Fatal("authorized running resource fallback still failed")
		}
		rows = append(rows, row)
	}
	report["resources"] = rows
	data, _ := json.MarshalIndent(report, "", "  ")
	// Full report is task-private; a separate allow-list projection is delivered.
	if out := os.Getenv("KAT_R12_PRIVATE_REPORT"); out != "" {
		os.WriteFile(out, data, 0600)
	}
	t.Log("real subscription route exercised; report kept private for safe projection")
}

func TestR12ResourceFallbackRoutes(t *testing.T) {
	for _, tc := range []struct {
		name                               string
		running, savedProxy, optionalProxy bool
		failFirst                          bool
		want                               []string
	}{
		{"kernel fails direct succeeds", true, false, false, true, []string{"kernel_rules", "direct"}},
		{"direct timeout avoided kernel succeeds", true, false, false, false, []string{"kernel_rules"}},
		{"kernel fails saved static succeeds", true, true, false, true, []string{"kernel_rules", "windows_static_http"}},
		{"stopped direct fails static succeeds", false, false, true, true, []string{"direct", "windows_static_http"}},
		{"stopped direct succeeds", false, false, true, false, []string{"direct"}},
		{"stopped saved proxy succeeds no duplicate", false, true, true, false, []string{"windows_static_http"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := fullHost(t)
			ctx := context.WithValue(context.Background(), resourceKernelKey{}, tc.running)
			proxy := &bootstrapProxy{Host: "127.0.0.1", Port: 7890}
			if tc.savedProxy {
				ctx = context.WithValue(ctx, bootstrapKey{}, proxy)
			}
			if tc.optionalProxy {
				ctx = context.WithValue(ctx, resourceProxyKey{}, proxy)
			}
			got := []string{}
			h.fullFetch = func(c context.Context, _ string, _ *clientegress.Policy, _ int64) ([]byte, error) {
				got = append(got, resourceRoute(c))
				if tc.failFirst && len(got) == 1 {
					return nil, dl("connect", "timeout")
				}
				if !tc.failFirst && tc.running && resourceRoute(c) != "kernel_rules" {
					return nil, dl("connect", "timeout")
				}
				return []byte("payload: [example.org]"), nil
			}
			b, _, e := h.subscriptionResource(ctx, nil, "https://example.org/rules", 0, nil, 1024)
			if e != nil || len(b) == 0 || strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("wrong fallback: %v %v", got, e)
			}
		})
	}
}
func TestR12AllResourceRoutesFailPreservesAcceptedAndReportsBoth(t *testing.T) {
	h := fullHost(t)
	if _, e := h.Apply(fixture(t, map[string]any{})); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	before := h.doc.text
	calls := []string{}
	h.fullFetch = func(ctx context.Context, _ string, _ *clientegress.Policy, _ int64) ([]byte, error) {
		calls = append(calls, resourceRoute(ctx))
		if resourceRoute(ctx) == "kernel_rules" {
			return nil, dl("connect", "connect_failed")
		}
		return nil, dl("connect", "timeout")
	}
	text := strings.Replace(fullFixture, "rules:\n", "rule-providers:\n  r: {type: http, behavior: domain, url: 'https://example.org/rules.yaml'}\nrules:\n  - RULE-SET,r,pick\n", 1)
	_, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"text": text}))
	if e == nil || e.Code != "subscription_resource_failed" || h.doc.text != before || h.fullPending != nil {
		t.Fatal("failure did not preserve accepted", e)
	}
	d := e.Detail
	if d.Route != "direct" || d.Category != "timeout" || d.FirstAttempt == nil || d.FirstAttempt.Route != "kernel_rules" || d.FirstAttempt.Category != "connect_failed" {
		t.Fatalf("wrong actual error routes: %+v", d)
	}
	if strings.Join(calls, ",") != "kernel_rules,direct" {
		t.Fatal(calls)
	}
	b, _ := json.Marshal(e)
	if strings.Contains(string(b), "https://") || strings.Contains(string(b), "rules.yaml") {
		t.Fatal("private transport fields leaked")
	}
}
func TestR12ResourcesFallbackIndependentlyAndMainRetainsSavedRoute(t *testing.T) {
	h := fullHost(t)
	if _, e := h.Apply(fixture(t, map[string]any{})); e != nil {
		t.Fatal(e)
	}
	if _, e := h.Start(); e != nil {
		t.Fatal(e)
	}
	calls := map[string][]string{}
	text := strings.Replace(fullFixture, "rules:\n", "rule-providers:\n  r: {type: http, behavior: domain, url: 'https://example.org/r.yaml'}\n  s: {type: http, behavior: domain, url: 'https://example.org/s.yaml'}\nrules:\n  - RULE-SET,r,pick\n", 1)
	h.fullFetch = func(ctx context.Context, u string, _ *clientegress.Policy, _ int64) ([]byte, error) {
		calls[u] = append(calls[u], resourceRoute(ctx))
		if strings.Contains(u, "main") {
			return []byte(text), nil
		}
		if strings.Contains(u, "r.yaml") && resourceRoute(ctx) == "kernel_rules" {
			return nil, dl("connect", "connect_failed")
		}
		return []byte("payload: [example.org]"), nil
	}
	_, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"url": "https://example.org/main.yaml"}))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Join(calls["https://example.org/main.yaml"], ",") != "direct" || strings.Join(calls["https://example.org/r.yaml"], ",") != "kernel_rules,direct" || strings.Join(calls["https://example.org/s.yaml"], ",") != "kernel_rules" {
		t.Fatal(calls)
	}
}
func TestR12ResourceFallbackNeverResurrectsCanceledPreview(t *testing.T) {
	h := fullHost(t)
	ctx, cancel := context.WithCancel(context.Background())
	ctx = context.WithValue(ctx, resourceKernelKey{}, true)
	calls := 0
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		calls++
		cancel()
		return nil, context.Canceled
	}
	_, e := h.fetchSubscriptionResource(ctx, "https://example.org/r", nil, 1024)
	if !errors.Is(e, context.Canceled) || calls != 1 {
		t.Fatal("canceled request retried", e, calls)
	}
}
func TestR12StoppedUnavailableStaticDoesNotRetrySameRoute(t *testing.T) {
	for _, savedProxy := range []bool{false, true} {
		h := fullHost(t)
		ctx := context.Background()
		if savedProxy {
			ctx = context.WithValue(ctx, bootstrapKey{}, &bootstrapProxy{Host: "127.0.0.1", Port: 7890})
			ctx = context.WithValue(ctx, resourceProxyKey{}, bootstrapFrom(ctx))
		}
		calls := 0
		h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
			calls++
			return nil, dl("connect", "timeout")
		}
		_, e := h.fetchSubscriptionResource(ctx, "https://example.org/r", nil, 1024)
		if e == nil || calls != 1 {
			t.Fatal("missing/duplicate static retried", calls)
		}
	}
}
