package clientcore

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/clientdiag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestK3RealLocalSOCKSRuleAndForcedGroup(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("credentials")
		}
		w.Write([]byte("ip=203.0.113.9\nloc=JP\n"))
	}))
	defer target.Close()
	k := settingsKernel(t)
	k["groups"] = []any{map[string]any{"name": "Final", "type": "select", "members": []string{"direct", "p"}, "selected": "direct"}, map[string]any{"name": "Exit", "type": "select", "members": []string{"p"}, "selected": "p"}}
	k["routing"] = map[string]any{"rules": []any{map[string]any{"ip_cidr": "127.0.0.0/8", "outbound": "Final"}}, "final": "reject"}
	h, before := startSettings(t, k, nil)
	for _, group := range []string{"", "Exit"} {
		client, tr, obs, e := diagnosticHTTP(h.server, h.doc.client.SOCKSPort, group)
		if e != nil {
			t.Fatal(e)
		}
		pool := x509.NewCertPool()
		pool.AddCert(target.Certificate())
		tr.TLSClientConfig = target.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		tr.TLSClientConfig.RootCAs = pool
		p, e := fetchDiagnostic(client)(context.Background(), "GET", target.URL)
		if e != nil {
			t.Fatal(e)
		}
		ip, region, e := clientdiag.Trace(p.Body)
		if e != nil || ip != "203.0.113.9" || region != "JP" {
			t.Fatal(ip, region, e)
		}
		ci, same := obs.snapshot()
		want := []string{"Final", "direct"}
		if group != "" {
			want = []string{"Exit", "p"}
		}
		if !same || !reflect.DeepEqual(ci.Chain, want) {
			t.Fatal(ci.Chain, want)
		}
		tr.CloseIdleConnections()
	}
	if h.doc.text != before {
		t.Fatal("diagnostic mutated selection/document")
	}
	if _, _, _, e := diagnosticHTTP(h.server, h.doc.client.SOCKSPort, "Missing"); e != nil {
		t.Fatal("registration validates only after owned socket")
	}
}
func TestK3CachedReadNoRequestsAndStrictParams(t *testing.T) {
	h := newHost(t)
	v, e := h.Request(context.Background(), "diagnostics.network", json.RawMessage(`{"kind":"unlock","run":false}`))
	if e != nil || v.(*diagnosticReply) != nil {
		t.Fatal(v, e)
	}
	for _, p := range []string{`{"kind":"unknown"}`, `{"kind":"exit","urls":["https://a"]}`, `{"kind":"connectivity","urls":["http://a"]}`, `{"kind":"unlock","_override":"x"}`} {
		if _, e := h.diagnosticsNetwork(context.Background(), []byte(p)); e == nil {
			t.Fatal(p)
		}
	}
	h.diagCache = map[string]*diagnosticReply{"unlock": {At: time.Now(), Items: []diagnosticRow{{Name: "Gemini", Verdict: clientdiag.Verdict{Result: "blocked"}}}}}
	v, e = h.diagnosticsNetwork(context.Background(), []byte(`{"kind":"unlock","run":false}`))
	if e != nil || v.(*diagnosticReply).Items[0].Result != "blocked" {
		t.Fatal(v, e)
	}
	if requestBudget("diagnostics.network") != 70*time.Second {
		t.Fatal("transport ceiling too short")
	}
}

// All public hostnames terminate at one local TLS fixture via a tiny SOCKS peer.
// Kat's own listener, rules, nested group chain and HTTP transport remain real.
func TestK3BatchFourWorkersCacheAndRealRules(t *testing.T) {
	var active, peak, hits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); now > old && !peak.CompareAndSwap(old, now); old = peak.Load() {
		}
		hits.Add(1)
		time.Sleep(15 * time.Millisecond)
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("credentials")
		}
		if strings.Contains(r.Host, "cloudflare") {
			w.Write([]byte("ip=203.0.113.9\nloc=JP\n"))
		} else {
			w.Write([]byte("public fixture unknown page"))
		}
	}))
	defer target.Close()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 2)
				if _, e := io.ReadFull(c, b); e != nil {
					return
				}
				methods := make([]byte, int(b[1]))
				if _, e := io.ReadFull(c, methods); e != nil {
					return
				}
				c.Write([]byte{5, 0})
				head := make([]byte, 4)
				if _, e := io.ReadFull(c, head); e != nil {
					return
				}
				n := 0
				switch head[3] {
				case 1:
					n = 4
				case 4:
					n = 16
				case 3:
					if _, e := io.ReadFull(c, b[:1]); e != nil {
						return
					}
					n = int(b[0])
				default:
					return
				}
				if _, e := io.CopyN(io.Discard, c, int64(n+2)); e != nil {
					return
				}
				up, e := net.Dial("tcp", target.Listener.Addr().String())
				if e != nil {
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				done := make(chan struct{})
				go func() { io.Copy(up, c); up.Close(); close(done) }()
				io.Copy(c, up)
				c.Close()
				<-done
			}()
		}
	}()
	k := map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}, "outbounds": []any{map[string]any{"name": "FixtureNode", "type": "socks5", "server": "127.0.0.1", "port": ln.Addr().(*net.TCPAddr).Port}}, "groups": []any{map[string]any{"name": "Final", "type": "select", "members": []string{"FixtureNode"}, "selected": "FixtureNode"}}, "routing": map[string]any{"rules": []any{map[string]any{"domain_suffix": "google.com", "outbound": "Final"}}, "final": "Final"}}
	h, before := startSettings(t, k, nil)
	h.diagTransport = func(tr *http.Transport) http.RoundTripper {
		tr.TLSClientConfig = target.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		tr.TLSClientConfig.ServerName = "example.com"
		return tr
	}
	v, er := h.diagnosticsNetwork(context.Background(), []byte(`{"kind":"connectivity","run":true,"urls":["https://custom.example/check"]}`))
	if er != nil {
		t.Fatal(er)
	}
	r := v.(*diagnosticReply)
	if len(r.Items) != 5 || peak.Load() > 4 || peak.Load() < 2 {
		t.Fatal(len(r.Items), peak.Load())
	}
	wantNames := []string{"Google", "Telegram", "GitHub", "Cloudflare", "https://custom.example/check"}
	for i, want := range wantNames {
		if r.Items[i].Name != want {
			t.Fatalf("connectivity target %d: got %q, want %q", i, r.Items[i].Name, want)
		}
	}
	for _, row := range r.Items {
		if row.Result != "ok" || !reflect.DeepEqual(row.Chain, []string{"Final", "FixtureNode"}) {
			t.Fatal(row)
		}
	}
	if !strings.Contains(r.Items[0].Rule, "domain_suffix") {
		t.Fatal("not actual rules", r.Items[0])
	}
	n := hits.Load()
	v, er = h.diagnosticsNetwork(context.Background(), []byte(`{"kind":"connectivity","run":false}`))
	if er != nil || hits.Load() != n || v.(*diagnosticReply).At != r.At {
		t.Fatal("cache made requests", er)
	}
	v, er = h.diagnosticsNetwork(context.Background(), []byte(`{"kind":"exit","run":true}`))
	if er != nil {
		t.Fatal(er)
	}
	exit := v.(*diagnosticReply).Items
	if len(exit) != 1 || exit[0].IP != "203.0.113.9" || exit[0].Node != "FixtureNode" {
		t.Fatal(exit)
	}
	if h.doc.text != before {
		t.Fatal("mutated selection")
	}
}

// Opt-in smoke only. Never part of ordinary/offline acceptance tests.
func TestK3DirectSmokeOptional(t *testing.T) {
	path := os.Getenv("KAT_K3_DIRECT_SMOKE")
	if path == "" {
		t.Skip("explicit Hytron direct smoke only")
	}
	h, _ := startSettings(t, map[string]any{"dns": map[string]any{"server": "system"}, "groups": []any{map[string]any{"name": "Final", "type": "select", "members": []string{"direct"}, "selected": "direct"}}, "routing": map[string]any{"final": "Final"}}, nil)
	results := map[string]any{}
	for _, kind := range []string{"unlock", "connectivity", "exit"} {
		v, e := h.diagnosticsNetwork(context.Background(), rawJSON(map[string]any{"kind": kind, "run": true}))
		if e != nil {
			results[kind] = e
		} else {
			results[kind] = v
		}
	}
	b, e := json.MarshalIndent(results, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}

func TestK3CacheSurvivesReopenWithoutNetwork(t *testing.T) {
	h := newHost(t)
	r := &diagnosticReply{At: time.Now().UTC().Truncate(time.Second), Items: []diagnosticRow{{Name: "Gemini", Verdict: clientdiag.Verdict{Result: "blocked"}, Chain: []string{"Final", "direct"}}}}
	if e := h.saveDiagnosticCache("unlock", r); e != nil {
		t.Fatal(e)
	}
	workspace := h.workspace
	if e := h.Close(); e != nil {
		t.Fatal(e)
	}
	next, e := Open(workspace)
	if e != nil {
		t.Fatal(e)
	}
	defer next.Close()
	v, er := next.diagnosticsNetwork(context.Background(), []byte(`{"kind":"unlock","run":false}`))
	if er != nil || !v.(*diagnosticReply).At.Equal(r.At) || v.(*diagnosticReply).Items[0].Result != "blocked" {
		t.Fatal(v, er)
	}
	if next.server != nil {
		t.Fatal("cache read started kernel")
	}
}

func TestAnonymousCacheResultContract(t *testing.T) {
	for _, kind := range []string{"unlock", "connectivity", "exit"} {
		for _, result := range []string{"unlocked", "blocked", "originals", "ok", "failed", "unknown", "challenge", "invalid"} {
			t.Run(kind+"/"+result, func(t *testing.T) {
				h := newHost(t)
				r := &diagnosticReply{At: time.Now().UTC().Truncate(time.Second), Items: []diagnosticRow{{Name: "Gemini", Verdict: clientdiag.Verdict{Result: result, Reason: "previous-static-reason"}, Chain: []string{}}}}
				if e := h.saveDiagnosticCache(kind, r); e != nil {
					t.Fatal(e)
				}
				path := filepath.Join(h.workspace, "network-diagnostic-"+kind+".json")
				before, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				v, er := h.diagnosticsNetwork(context.Background(), rawJSON(map[string]any{"kind": kind, "run": false}))
				if er != nil {
					t.Fatal(er)
				}
				got := v.(*diagnosticReply)
				allowed := result != "invalid" && (kind == "unlock" || (result != "unknown" && result != "challenge"))
				if allowed {
					if got == nil || got.Items[0].Result != result || got.Items[0].Reason != "previous-static-reason" || !got.At.Equal(r.At) {
						t.Fatal("old/new cache reclassified or lost", got)
					}
				} else if got != nil {
					t.Fatal("accepted invalid result for cache kind", got)
				}
				after, e := os.ReadFile(path)
				if e != nil || string(before) != string(after) || h.server != nil {
					t.Fatal("read rewrote cache or started kernel", e)
				}
			})
		}
	}
}
