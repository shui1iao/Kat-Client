package clientcore

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shui1iao/Kat/internal/clientdiag"
)

func publicNetflixSample(t *testing.T) []byte {
	t.Helper()
	b, e := os.ReadFile("../clientdiag/testdata/netflix-hk-20261102.html.gz")
	if e != nil {
		t.Fatal(e)
	}
	r, e := gzip.NewReader(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	raw, e := io.ReadAll(r)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	if len(raw) != 2354153 || hex.EncodeToString(sum[:]) != "8a49a8df740122bdaf7489dd07e8734c94cee0bbf6f22d158a55ee7fad8b0869" {
		t.Fatal("real public response changed")
	}
	if bytes.Index(raw, []byte("netflix.reactContext = ")) != 2126432 {
		t.Fatal("regression no longer covers metadata beyond old cap")
	}
	return raw
}
func writeDiagnosticGzip(t *testing.T, w http.ResponseWriter, b []byte) {
	t.Helper()
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	gz := gzip.NewWriter(w)
	// Overflow cases intentionally close the client early. The assertions are
	// on received bytes / parsing, not on the expected server-side reset.
	_, _ = gz.Write(b)
	_ = gz.Close()
}
func TestAnonymousActualNetflixSizeAndDecompressedBoundary(t *testing.T) {
	raw := publicNetflixSample(t)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := raw
		switch r.URL.Path {
		case "/exact":
			b = append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), clientdiag.NetflixBodyLimit-len(raw))...)
		case "/over":
			b = append(append([]byte(nil), raw...), bytes.Repeat([]byte(" "), clientdiag.NetflixBodyLimit+1-len(raw))...)
		}
		// Gzip wire bytes are much smaller; the cap must apply AFTER decompression.
		writeDiagnosticGzip(t, w, b)
	}))
	defer target.Close()
	for _, c := range []struct {
		name, path string
		limit      int
		ok         bool
	}{{"old cap rejects actual response", "/", clientdiag.BodyLimit, false}, {"Netflix admits actual response", "/", clientdiag.ResponseLimit("Netflix"), true}, {"exact four MiB", "/exact", clientdiag.NetflixBodyLimit, true}, {"four MiB plus one", "/over", clientdiag.NetflixBodyLimit, false}, {"other services still two MiB", "/", clientdiag.ResponseLimit("Disney+"), false}} {
		t.Run(c.name, func(t *testing.T) {
			fetch := fetchDiagnosticLimit(target.Client(), c.limit)
			v := clientdiag.Detect(context.Background(), "Netflix", func(ctx context.Context, m, _ string) (clientdiag.Page, error) {
				return fetch(ctx, m, target.URL+c.path)
			})
			if v.HTTPStatus != 200 {
				t.Fatal("lost HTTP on body failure", v)
			}
			if c.ok {
				if v.Result != "unlocked" || v.Region != "HK" {
					t.Fatal("real anonymous ALLOW metadata unreadable", v)
				}
			} else if v.Result != "failed" || !strings.Contains(v.Reason, "[body_limit]") {
				t.Fatal("limit failed open", v)
			}
		})
	}
}

func TestAnonymousTLSAndTimeoutFailureStages(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("public fixture")) }))
	target.Config.ErrorLog = log.New(io.Discard, "", 0)
	defer target.Close()
	secure := &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: clientdiag.Redirect}
	v := clientdiag.Detect(context.Background(), "Netflix", func(ctx context.Context, m, _ string) (clientdiag.Page, error) {
		return fetchDiagnostic(secure)(ctx, m, target.URL)
	})
	if v.Result != "failed" || !strings.Contains(v.Reason, "[tls]") || v.HTTPStatus != 0 {
		t.Fatal("certificate verification disabled/lost", v)
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/body" {
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
		}
		<-r.Context().Done()
	}))
	defer slow.Close()
	for _, path := range []string{"/headers", "/body"} {
		tr := &http.Transport{Proxy: nil, ResponseHeaderTimeout: 20 * time.Millisecond}
		client := &http.Client{Transport: tr}
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		v := clientdiag.Detect(ctx, "Netflix", func(ctx context.Context, m, _ string) (clientdiag.Page, error) {
			return fetchDiagnostic(client)(ctx, m, slow.URL+path)
		})
		cancel()
		tr.CloseIdleConnections()
		if v.Result != "failed" || !strings.Contains(v.Reason, "Netflix 匿名地区元数据") || !strings.Contains(v.Reason, "[timeout]") {
			t.Fatal(path, v)
		}
		if path == "/body" && v.HTTPStatus != 200 {
			t.Fatal("body timeout lost headers", v)
		}
	}
}

// One tiny loopback SOCKS peer maps all public fixture hostnames to local TLS.
// Kat still performs real SOCKS admission, domain rules and node attribution.
func diagnosticFixtureSOCKS(t *testing.T, target string) int {
	t.Helper()
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
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
				if _, e := io.CopyN(io.Discard, c, int64(b[1])); e != nil {
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
				up, e := net.Dial("tcp", target)
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
	return ln.Addr().(*net.TCPAddr).Port
}
func TestAnonymousBatchRealRulesMultiExitAndSafeCache(t *testing.T) {
	raw := publicNetflixSample(t)
	var hits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Method != "GET" {
			t.Error("anonymous request leaked session or used a device flow")
		}
		// Every response attempts to set a cookie; no subsequent request may send it.
		w.Header().Set("Set-Cookie", "anonymous_test=must_not_replay; Path=/")
		switch {
		case strings.Contains(r.Host, "api.openai.com"):
			io.WriteString(w, `{"requires_cookie_consent":false}`)
		case strings.Contains(r.Host, "chat.openai.com"):
			io.WriteString(w, "ip=203.0.113.9\nloc=SG\n")
		case strings.Contains(r.Host, "gemini.google.com"):
			w.WriteHeader(403)
			io.WriteString(w, "<title>Just a moment</title>cf-chl-check")
		case strings.Contains(r.Host, "claude.ai"):
			if r.URL.Path == "/cdn-cgi/trace" {
				io.WriteString(w, "ip=203.0.113.9\nloc=HK\n")
			} else {
				io.WriteString(w, `<!DOCTYPE html><html><body><div id="root"></div></body></html>`)
			}
		case strings.Contains(r.Host, "www.google.com"):
			io.WriteString(w, `<!DOCTYPE html><html><body><script>const _bar_=[null,2,1,200,"HKG"]</script></body></html>`)
		case strings.Contains(r.Host, "www.youtube.com"):
			io.WriteString(w, `<!DOCTYPE html><html><body>YouTube Premium ad-free <script>{"countryCode":"HK"}</script></body></html>`)
		case strings.Contains(r.Host, "netflix.com"):
			writeDiagnosticGzip(t, w, raw)
		case strings.Contains(r.Host, "disneyplus.com"):
			io.WriteString(w, `window.langRegionRedirectProps = {"location":"HK","hasContent":true,"countriesConfig":{"HK":{"commerce":{"defaultProduct":{"NU":{"skuList":["public-product"]}}}}}};`)
		default:
			io.WriteString(w, "<h1>About service</h1> Premium ad-free")
		}
	}))
	defer target.Close()
	port := diagnosticFixtureSOCKS(t, target.Listener.Addr().String())
	k := map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}, "outbounds": []any{map[string]any{"name": "NodeA", "type": "socks5", "server": "127.0.0.1", "port": port}, map[string]any{"name": "NodeB", "type": "socks5", "server": "127.0.0.1", "port": port}}, "groups": []any{map[string]any{"name": "Final", "type": "select", "members": []string{"NodeA"}, "selected": "NodeA"}}, "routing": map[string]any{"rules": []any{map[string]any{"domain": "chat.openai.com", "outbound": "NodeB"}}, "final": "Final"}}
	h, before := startSettings(t, k, nil)
	h.diagTransport = func(tr *http.Transport) http.RoundTripper {
		if tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
			t.Error("production TLS disabled")
		}
		tr.TLSClientConfig = target.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		tr.TLSClientConfig.ServerName = "example.com"
		return tr
	}
	value, e := h.diagnosticsNetwork(context.Background(), json.RawMessage(`{"kind":"unlock","run":true}`))
	if e != nil {
		t.Fatal(e)
	}
	r := value.(*diagnosticReply)
	if len(r.Items) != len(clientdiag.Services) {
		t.Fatal("lost jobs")
	}
	rows := map[string]diagnosticRow{}
	for _, row := range r.Items {
		rows[row.Name] = row
		if row.Node == "" || len(row.Chain) == 0 || row.HTTP == 0 {
			t.Fatal("lost real rule/HTTP", row)
		}
	}
	if x := rows["ChatGPT"]; x.Result != "unknown" || !strings.Contains(x.Reason, "[egress]") || x.Node != "NodeB" {
		t.Fatal("combined different exit evidence", x)
	}
	if x := rows["Gemini"]; x.Result != "challenge" || x.HTTP != 403 || !strings.Contains(x.Reason, "[challenge]") {
		t.Fatal("lost HTTP/cause", x)
	}
	if x := rows["Claude"]; x.Result != "unlocked" || x.Region != "HK" {
		t.Fatal(x)
	}
	if x := rows["Google"]; x.Result != "unlocked" || x.Region != "HK" {
		t.Fatal(x)
	}
	if x := rows["YouTube"]; x.Result != "unlocked" || x.Region != "HK" {
		t.Fatal(x)
	}
	if x := rows["Netflix"]; x.Result != "unlocked" || x.Region != "HK" || x.Node != "NodeA" || !strings.Contains(x.Reason, "[anonymous]") {
		t.Fatal("real large sample not consumed through actual SOCKS", x)
	}
	if x := rows["Disney+"]; x.Result != "unlocked" || x.Region != "HK" {
		t.Fatal(x)
	}
	if h.doc.text != before {
		t.Fatal("changed rules/selections/source")
	}
	n := hits.Load()
	_, e = h.diagnosticsNetwork(context.Background(), json.RawMessage(`{"kind":"unlock","run":false}`))
	if e != nil || hits.Load() != n {
		t.Fatal("cached read probed", e)
	}
	workspace := h.workspace
	if e := h.Close(); e != nil {
		t.Fatal(e)
	}
	next, err := Open(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	cached, e := next.diagnosticsNetwork(context.Background(), json.RawMessage(`{"kind":"unlock","run":false}`))
	if e != nil {
		t.Fatal(e)
	}
	payload, err := json.Marshal(cached)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(payload, []byte(`"http_status":403`)) || !bytes.Contains(payload, []byte("[challenge]")) || !bytes.Contains(payload, []byte("Gemini 匿名入口")) || bytes.Contains(payload, []byte("must_not_replay")) || next.server != nil || hits.Load() != n {
		t.Fatal("cache lost status/stage/cause or leaked cookies/probed")
	}
}

// Explicitly opt-in. Exactly one unlock batch, no connectivity/exit follow-up,
// no user configuration or proxy credentials, and no retries to obtain green.
func TestAnonymousDirectSmokeOptional(t *testing.T) {
	path := os.Getenv("KAT_ANONYMOUS_DIRECT_SMOKE")
	if path == "" {
		t.Skip("explicit single Hytron direct path only")
	}
	h, _ := startSettings(t, map[string]any{"dns": map[string]any{"server": "system"}, "groups": []any{map[string]any{"name": "ResearchDirect", "type": "select", "members": []string{"direct"}, "selected": "direct"}}, "routing": map[string]any{"final": "ResearchDirect"}}, nil)
	var mu sync.Mutex
	observations := []map[string]any{}
	h.diagTransport = func(tr *http.Transport) http.RoundTripper {
		return diagnosticObserveRT(func(req *http.Request) (*http.Response, error) {
			resp, err := tr.RoundTrip(req)
			row := map[string]any{"host": req.URL.Hostname(), "path": req.URL.EscapedPath()}
			if err != nil {
				row["failure"] = clientdiag.FailureReason(err)
				mu.Lock()
				observations = append(observations, row)
				mu.Unlock()
				return resp, err
			}
			row["http_status"] = resp.StatusCode
			row["uncompressed"] = resp.Uncompressed
			resp.Body = &diagnosticCountBody{ReadCloser: resp.Body, onClose: func(n int64) { row["read_bytes"] = n; mu.Lock(); observations = append(observations, row); mu.Unlock() }}
			return resp, nil
		})
	}
	value, e := h.diagnosticsNetwork(context.Background(), json.RawMessage(`{"kind":"unlock","run":true}`))
	if e != nil {
		t.Fatal(e)
	}
	mu.Lock()
	out, err := json.MarshalIndent(map[string]any{"scope": "Hytron direct via real local Kat SOCKS; synthetic no-credential research config; not Bero; one batch, no retries/cookies/accounts", "reply": value, "http_observations": observations}, "", "  ")
	mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, out, 0600); err != nil {
		t.Fatal(err)
	}
}

type diagnosticObserveRT func(*http.Request) (*http.Response, error)

func (f diagnosticObserveRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type diagnosticCountBody struct {
	io.ReadCloser
	n       int64
	onClose func(int64)
}

func (b *diagnosticCountBody) Read(p []byte) (int, error) {
	n, e := b.ReadCloser.Read(p)
	b.n += int64(n)
	return n, e
}
func (b *diagnosticCountBody) Close() error { e := b.ReadCloser.Close(); b.onClose(b.n); return e }

func TestAnonymousFetchBodyErrorRetainsStatusWithoutPartialBody(t *testing.T) {
	client := &http.Client{Transport: diagnosticObserveRT(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(diagnosticBrokenReader{}), Request: r}, nil
	})}
	p, e := fetchDiagnostic(client)(context.Background(), "GET", "https://example.com/")
	if !errors.Is(e, io.ErrUnexpectedEOF) || p.Status != 200 || p.Body != "" {
		t.Fatal("lost response headers or exposed partial body", p.Status, e)
	}
}

type diagnosticBrokenReader struct{}

func (diagnosticBrokenReader) Read(p []byte) (int, error) {
	return copy(p, "partial"), io.ErrUnexpectedEOF
}

func TestAnonymousCanceledBatchKeepsPreviousCache(t *testing.T) {
	h, _ := startSettings(t, map[string]any{"dns": map[string]any{"server": "system"}, "routing": map[string]any{"final": "direct"}}, nil)
	old := &diagnosticReply{At: time.Now().UTC(), Items: []diagnosticRow{{Name: "Netflix", Verdict: clientdiag.Verdict{Result: "failed", Reason: "prior"}, HTTP: 403}}}
	h.diagCache = map[string]*diagnosticReply{"unlock": old}
	entered := make(chan struct{}, 1)
	h.diagTransport = func(tr *http.Transport) http.RoundTripper {
		return diagnosticObserveRT(func(req *http.Request) (*http.Response, error) {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-req.Context().Done()
			return nil, req.Context().Err()
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan *Error, 1)
	go func() { _, e := h.diagnosticsNetwork(ctx, json.RawMessage(`{"kind":"unlock","run":true}`)); done <- e }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancellation reported success")
		}
	case <-time.After(time.Second):
		t.Fatal("batch ignored cancellation")
	}
	if h.diagCache["unlock"] != old {
		t.Fatal("canceled batch replaced last good terminal cache")
	}
}

func TestAnonymousFourServiceEvidenceViaRealSOCKS(t *testing.T) {
	// All 7 services retain their semantic positive through SOCKS/TLS/rules.
	// None of these fixtures constitutes a public-egress live pass.
	b, e := os.ReadFile("../clientdiag/testdata/unlock.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []struct {
		Service, Want string
		Pages         []struct {
			URL, Body, Location string
			Status              int
		}
	}
	if e = json.Unmarshal(b, &cases); e != nil {
		t.Fatal(e)
	}
	type reply struct {
		body, location string
		status         int
	}
	pages := map[string]reply{}
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.Service] || c.Want != "unlocked" {
			continue
		}
		seen[c.Service] = true
		for _, p := range c.Pages {
			u, e := url.Parse(p.URL)
			if e != nil {
				t.Fatal(e)
			}
			pages[u.Hostname()+u.EscapedPath()] = reply{p.Body, p.Location, p.Status}
		}
	}
	raw := publicNetflixSample(t)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Error("non-anonymous request")
		}
		if strings.Contains(r.Host, "netflix.com") {
			writeDiagnosticGzip(t, w, raw)
			return
		}
		p, ok := pages[r.Host+r.URL.EscapedPath()]
		if !ok {
			t.Error("unexpected public fixture path", r.Host, r.URL.EscapedPath())
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Location", p.location)
		w.WriteHeader(p.status)
		io.WriteString(w, p.body)
	}))
	defer target.Close()
	port := diagnosticFixtureSOCKS(t, target.Listener.Addr().String())
	k := map[string]any{"dns": map[string]any{"server": "system"}, "security": map[string]any{"allow_loopback": true}, "outbounds": []any{map[string]any{"name": "FixtureNode", "type": "socks5", "server": "127.0.0.1", "port": port}}, "groups": []any{map[string]any{"name": "Final", "type": "select", "members": []string{"FixtureNode"}, "selected": "FixtureNode"}}, "routing": map[string]any{"final": "Final"}}
	h, before := startSettings(t, k, nil)
	h.diagTransport = func(tr *http.Transport) http.RoundTripper {
		tr.TLSClientConfig = target.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		tr.TLSClientConfig.ServerName = "example.com"
		return tr
	}
	value, err := h.diagnosticsNetwork(context.Background(), json.RawMessage(`{"kind":"unlock","run":true}`))
	if err != nil {
		t.Fatal(err)
	}
	rows := value.(*diagnosticReply).Items
	if len(rows) != len(clientdiag.Services) {
		t.Fatal("lost positive jobs")
	}
	for _, r := range rows {
		if r.Result != "unlocked" || r.HTTP != 200 || r.Region == "" || r.Node != "FixtureNode" || !strings.Contains(r.Reason, "[anonymous]") {
			t.Fatal("positive failed through actual SOCKS", r)
		}
	}
	if h.doc.text != before {
		t.Fatal("positive batch changed source / choices")
	}
}
