package clientcore

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/provider"
	"golang.org/x/net/proxy"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func assertDetail(t *testing.T, e error, stage, category string) {
	t.Helper()
	var f *downloadFailure
	if !errors.As(e, &f) || f.stage != stage || f.category != category {
		t.Fatalf("classification: got %v expected %s/%s", e, stage, category)
	}
}
func TestBootstrapFetchClassificationAndNoSecrets(t *testing.T) {
	for _, v := range []struct {
		stage string
		err   error
		want  string
	}{{"resolve", errors.New("https://secret.invalid/token-secret"), "dns_failed"}, {"connect", syscall.ECONNREFUSED, "connect_failed"}, {"connect", context.DeadlineExceeded, "timeout"}, {"body_read", context.Canceled, "canceled"}} {
		e := safeFailure(context.Background(), v.stage, v.err)
		assertDetail(t, e, v.stage, v.want)
		d := resourceError(context.Background(), "rule_set", 2, "download", v.stage, "unknown", e)
		b, _ := json.Marshal(d)
		if strings.Contains(string(b), "secret") {
			t.Fatal("raw cause leaked")
		}
		if d.Detail.Ordinal != 2 {
			t.Fatal("ordinal lost")
		}
	}
	for _, code := range []int{302, 403, 404, 429, 503} {
		_, e := fetchImportBounded(context.Background(), "https://example.com/token-secret", nil, func(tr *http.Transport) http.RoundTripper {
			return roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader("token-secret")), Header: make(http.Header)}, nil
			})
		}, 8)
		category := "http_status"
		if code == 302 {
			category = "redirect_refused"
		}
		assertDetail(t, e, "http_status", category)
	}
	_, e := checkedImportAddresses([]netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, nil)
	assertDetail(t, e, "resolve", "address_refused")
	_, e = fetchImportBounded(context.Background(), "https://example.com", nil, func(tr *http.Transport) http.RoundTripper {
		return roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("123456789")), Header: make(http.Header)}, nil
		})
	}, 8)
	assertDetail(t, e, "body_read", "size_limit")
}

// Real HTTP CONNECT + end-to-end TLS using only local controlled I/O.
// Public destination checking and original-host TLS remain production code.
func TestBootstrapEmptyCacheDirectFailsProxyTLSImports(t *testing.T) { bootstrapTransport(t, false) }
func TestBootstrapTUNOnControlledRuntimePath(t *testing.T)           { bootstrapTransport(t, true) }
func bootstrapTransport(t *testing.T, captured bool) {
	var calls atomic.Int32
	var tlsName atomic.Value
	fixture := strings.Replace(fullFixture, "rules:\n", `rule-providers:
  external: {type: http, behavior: domain, format: yaml, url: 'https://raw.githubusercontent.com/rules.yaml'}
rules:
  - RULE-SET,external,pick
`, 1)
	content := map[string][]byte{"example.com/": []byte(fixture), "raw.githubusercontent.com/rules.yaml": []byte("payload: [example.net]\n")}
	expectedCalls, expectedNodes := int32(2), 1
	if dir := os.Getenv("KAT_BOOTSTRAP_PRIVATE"); dir != "" {
		source, err := os.ReadFile(filepath.Join(dir, "source.yaml"))
		if err != nil {
			t.Fatal("private source unavailable")
		}
		content["example.com/"] = source
		h := fullHost(t)
		urls, err := parseAuthorizedResourceOrder(source, h.doc.client.ProbeURL)
		if err != nil {
			t.Fatal("private parse")
		}
		for i, u := range append(urls, subscriptionGeoURL, subscriptionASNURL) {
			file := "ruleset-" + strconv.Itoa(i+1) + ".yaml"
			if i == 8 {
				file = "country.mmdb"
			}
			if i == 9 {
				file = "asn.mmdb"
			}
			b, e := os.ReadFile(filepath.Join(dir, file))
			if e != nil {
				t.Fatal("private resource unavailable")
			}
			parts := strings.TrimPrefix(u, "https://")
			content[parts] = b
		}
		expectedCalls, expectedNodes = 11, 22
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.TLS.ServerName != r.Host {
			t.Error("original TLS/Host mismatch")
		}
		tlsName.Store(r.TLS.ServerName)
		key := r.Host + r.URL.Path
		if r.Host == "example.com" {
			key = "example.com/"
		}
		b, ok := content[key]
		if !ok {
			t.Error("unexpected private resource route")
			http.Error(w, "not found", 404)
			return
		}
		w.Write(b)
	}))
	server.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName != "example.com" && hello.ServerName != "raw.githubusercontent.com" {
			t.Error("SNI lost")
		}
		return nil, nil
	}}
	server.TLS.Certificates = []tls.Certificate{bootstrapTestCertificate(t)}
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	var upstream func() (net.Conn, error) = func() (net.Conn, error) { return net.Dial("tcp", server.Listener.Addr().String()) }
	var controlled atomic.Int32
	if captured {
		// Linux model of the existing tun2socks->Kat SOCKS handoff, not a fake
		// tun boolean. Real SOCKS, routing, and production ClientEgress hook execute.
		cfg := kernel.Config{Inbounds: []kernel.Inbound{{Protocol: "socks5", Listen: "127.0.0.1:0"}}, Security: &kernel.SecurityOptions{AllowLoopback: true}, DNS: &kernel.DNSOptions{Server: "system"}}
		cfg.SetClientEgress(&kernel.ClientEgress{Control: func(_ context.Context, _ string, address string, _ syscall.RawConn) error {
			if address != server.Listener.Addr().String() {
				return errors.New("unexpected model destination")
			}
			controlled.Add(1)
			return nil
		}, Bootstrap: func(context.Context, string, string) ([]netip.Addr, error) {
			return nil, errors.New("unexpected model DNS")
		}})
		runtime, e := kernel.Start(cfg)
		if e != nil {
			t.Fatal(e)
		}
		defer runtime.Close(context.Background())
		dialer, e := proxy.SOCKS5("tcp", runtime.Addresses()[0].String(), nil, proxy.Direct)
		if e != nil {
			t.Fatal(e)
		}
		upstream = func() (net.Conn, error) { return dialer.Dial("tcp", server.Listener.Addr().String()) }
	}
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || (r.Host != "example.com:443" && r.Host != "raw.githubusercontent.com:443") {
			t.Errorf("unchecked CONNECT destination %q", r.Host)
			http.Error(w, "refused", 400)
			return
		}
		remote, e := upstream()
		if e != nil {
			t.Error("local TLS unavailable")
			return
		}
		defer remote.Close()
		conn, rw, e := w.(http.Hijacker).Hijack()
		if e != nil {
			t.Error("hijack")
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		rw.Flush()
		done := make(chan struct{})
		go func() { io.Copy(remote, rw); remote.Close(); close(done) }()
		io.Copy(conn, remote)
		conn.Close()
		<-done
	}))
	defer proxy.Close()
	pa := proxy.Listener.Addr().(*net.TCPAddr)
	endpoint := &bootstrapProxy{Host: "127.0.0.1", Port: uint16(pa.Port)}
	resolve := func(context.Context, string) ([]netip.Addr, error) {
		t.Error("proxy target resolver must not be called (fake-IP DNS)")
		return checkedImportAddresses([]netip.Addr{netip.MustParseAddr("198.18.0.1")}, nil)
	}
	var verified atomic.Int32
	seam := func(tr *http.Transport) http.RoundTripper {
		tr.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if bootstrapFrom(ctx) == nil {
				return nil, dl("connect", "connect_failed")
			}
			return dialBootstrapIO(ctx, address, endpoint, nil, resolve, nil, func(ctx context.Context, d *net.Dialer, a string) (net.Conn, error) {
				return d.DialContext(ctx, "tcp", a)
			}, func(net.Conn) error { verified.Add(1); return nil })
		}
		return tr
	}
	h := fullHost(t)
	before := h.doc.text
	h.fullFetch = func(ctx context.Context, url string, p *clientegress.Policy, limit int64) ([]byte, error) {
		return fetchImportBounded(ctx, url, p, seam, limit)
	}
	_, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"url": "https://example.com/token-secret", "full_only": true}))
	if e == nil || e.Detail == nil || e.Detail.Category != "connect_failed" || h.doc.text != before || calls.Load() != 0 {
		t.Fatal("empty-cache direct failure mutated state or contacted TLS")
	}
	v, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"url": "https://example.com/token-secret", "full_only": true, "_system_proxy": endpoint}))
	if e != nil {
		t.Fatal(e)
	}
	p := v.(subscriptionPreview)
	if h.doc.text != before {
		t.Fatal("preparation committed")
	}
	if _, e = h.Apply(p.Text, p.Format); e != nil {
		t.Fatal(e)
	}
	if calls.Load() != expectedCalls || verified.Load() != expectedCalls || tlsName.Load() == nil || len(h.doc.config.Outbounds) != expectedNodes {
		t.Fatal("actual proxy/TLS import not completed")
	}
	if captured && controlled.Load() != expectedCalls {
		t.Fatal("captured path bypassed actual controlled kernel出口")
	}
	// Same actual TLS tunnel, untrusted certificate: must still fail closed.
	_, err := fetchImportBounded(context.WithValue(context.Background(), bootstrapKey{}, endpoint), "https://example.com", nil, func(tr *http.Transport) http.RoundTripper { seam(tr); tr.TLSClientConfig = nil; return tr }, 1024)
	assertDetail(t, err, "tls", "tls_certificate")
}

func TestBootstrapSelfLoopUnknownPeerAndMixedDNS(t *testing.T) {
	endpoint := &bootstrapProxy{Host: "127.0.0.1", Port: 8123}
	res := func(context.Context, string) ([]netip.Addr, error) {
		return checkedImportAddresses([]netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil)
	}
	dials := 0
	dial := func(context.Context, *net.Dialer, string) (net.Conn, error) {
		dials++
		a, b := net.Pipe()
		go func() { defer b.Close(); x := make([]byte, 1); b.Read(x) }()
		return a, nil
	}
	// A matching configured port is not identity evidence. Both configured
	// and unrelated ports reach exact connected-peer verification.
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, port := range []uint16{7890, 8123} {
			endpoint := &bootstrapProxy{Host: host, Port: port}
			seen := false
			_, e := dialBootstrapIO(context.Background(), "example.com:443", endpoint, nil, res, []int{7890, 7891}, dial, func(net.Conn) error { seen = true; return dl("proxy_connect", "proxy_identity_unknown") })
			assertDetail(t, e, "proxy_connect", "proxy_identity_unknown")
			if !seen {
				t.Fatal("configured port incorrectly treated as self")
			}
		}
	}
	var e error
	for _, category := range []string{"self_loop", "proxy_identity_unknown"} {
		_, e = dialBootstrapIO(context.Background(), "example.com:443", endpoint, nil, res, nil, dial, func(net.Conn) error { return dl("proxy_connect", category) })
		assertDetail(t, e, "proxy_connect", category)
	}
	// Mixed target DNS remains refused for the direct route; the proxy never
	// consults target DNS, as exercised by the real tunnel tests above.
	_, e = checkedImportAddresses([]netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("::1")}, nil)
	assertDetail(t, e, "resolve", "address_refused")
}
func TestBootstrapConnectHTTPBoundsAndCancellation(t *testing.T) {
	for _, v := range []struct {
		header, category string
		status           int
	}{{"HTTP/1.1 407 Auth required\r\n\r\n", "proxy_auth_required", 407}, {"HTTP/1.1 403 Refused\r\n\r\n", "proxy_http", 403}, {"HTTP/1.1 200 OK\r\nX: " + strings.Repeat("a", 64<<10) + "\r\n\r\n", "header_limit", 0}, {"not-http\r\n\r\n", "proxy_protocol", 0}} {
		a, b := net.Pipe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer b.Close()
			r := bufio.NewReader(b)
			for {
				line, e := r.ReadString('\n')
				if e != nil {
					return
				}
				if line == "\r\n" {
					break
				}
			}
			io.WriteString(b, v.header)
		}()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, e := connectBootstrap(ctx, a, "8.8.8.8:443")
		cancel()
		a.Close()
		<-done
		assertDetail(t, e, "proxy_connect", v.category)
	}
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := connectBootstrap(ctx, a, "8.8.8.8:443"); done <- e }()
	cancel()
	select {
	case e := <-done:
		assertDetail(t, e, "proxy_connect", "canceled")
	case <-time.After(time.Second):
		t.Fatal("cancel ignored")
	}
	// Header reader must leave the first tunnel byte untouched.
	a, b = net.Pipe()
	go func() {
		defer b.Close()
		r := bufio.NewReader(b)
		for {
			l, e := r.ReadString('\n')
			if e != nil {
				return
			}
			if l == "\r\n" {
				break
			}
		}
		io.WriteString(b, "HTTP/1.1 200 OK\r\n\r\nX")
	}()
	c, e := connectBootstrap(context.Background(), a, "8.8.8.8:443")
	if e != nil {
		t.Fatal(e)
	}
	x := make([]byte, 1)
	io.ReadFull(c, x)
	c.Close()
	if string(x) != "X" {
		t.Fatal("tunnel byte consumed")
	}
}

func TestBootstrapResourceDiagnosticsAndStageFailureRetainsOld(t *testing.T) {
	fixture := strings.Replace(fullFixture, "rules:\n", `rule-providers:
  one: {type: http, behavior: classical, format: yaml, url: https://example.com/one}
  two: {type: http, behavior: classical, format: yaml, url: https://example.com/two}
rules:
`, 1)
	for _, failure := range []string{"download", "format", "write"} {
		h := fullHost(t)
		before := h.doc.text
		call := 0
		h.fullFetch = func(ctx context.Context, u string, p *clientegress.Policy, l int64) ([]byte, error) {
			call++
			if call == 2 {
				if failure == "download" {
					return nil, dl("http_status", "redirect_refused")
				}
				if failure == "format" {
					return []byte("payload: broken"), nil
				}
			}
			return []byte("payload: ['DOMAIN,example.com']"), nil
		}
		if failure == "write" {
			h.stageWrite = func(string, []byte) error {
				return &os.PathError{Op: "write", Path: "/private/token-secret", Err: syscall.ENOSPC}
			}
		}
		_, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"text": fixture, "full_only": true}))
		if e == nil || e.Detail == nil || e.Detail.Resource != "rule_set" {
			t.Fatal("missing typed resource detail")
		}
		if failure != "write" && e.Detail.Ordinal != 2 {
			t.Fatal("declaration ordinal lost")
		}
		if failure == "write" && (e.Detail.Stage != "stage_write" || e.Detail.Category != "disk_full") {
			t.Fatal("write classification lost")
		}
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), "token-secret") || strings.Contains(string(b), "example.com") {
			t.Fatal("private input leaked")
		}
		if h.doc.text != before || h.fullPending != nil {
			t.Fatal("failure accepted state")
		}
		dirs, _ := filepath.Glob(filepath.Join(h.workspace, "subscription-*"))
		if len(dirs) != 0 {
			t.Fatal("stage leaked")
		}
	}
	for _, kind := range []string{"geoip", "asn"} {
		h := fullHost(t)
		rule := "GEOIP,CN,pick"
		if kind == "asn" {
			rule = "IP-ASN,13335,pick"
		}
		fixture := strings.Replace(fullFixture, "DOMAIN,example.org,pick", rule, 1)
		h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
			return nil, dl("resolve", "dns_failed")
		}
		_, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"text": fixture, "full_only": true}))
		if e == nil || e.Detail == nil || e.Detail.Resource != kind || e.Detail.Stage != "resolve" {
			t.Fatal("DB detail lost")
		}
	}
	h := fullHost(t)
	_, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"text": "socks5://127.0.0.1:1", "full_only": true}))
	if e == nil || e.Code != "subscription_format_unsupported" {
		t.Fatal("nodes fallback remained")
	}
	_, e = h.previewSubscription(context.Background(), rawJSON(map[string]any{"text": initialDocument, "full_only": true}))
	if e == nil || e.Code != "subscription_native_config" {
		t.Fatal("native import must remain draft workflow")
	}
}

func TestBootstrapAuthorizedSnapshotAllResourcesProductionSemantics(t *testing.T) {
	dir := os.Getenv("KAT_BOOTSTRAP_PRIVATE")
	if dir == "" {
		t.Skip("authorized private source not supplied")
	}
	source, e := os.ReadFile(filepath.Join(dir, "source.yaml"))
	if e != nil {
		t.Fatal("private source unavailable")
	}
	h := fullHost(t)
	calls := 0
	var mu sync.Mutex
	// Actual authorized bytes, unchanged. Mapping by production ParseFull declaration order.
	f, err := parseAuthorizedResourceOrder(source, h.doc.client.ProbeURL)
	if err != nil {
		t.Fatal("authorized source invalid")
	}
	h.fullFetch = func(ctx context.Context, url string, p *clientegress.Policy, limit int64) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		file := ""
		if url == subscriptionGeoURL {
			file = "country.mmdb"
		} else if url == subscriptionASNURL {
			file = "asn.mmdb"
		} else {
			for i, u := range f {
				if u == url {
					file = "ruleset-" + strconv.Itoa(i+1) + ".yaml"
				}
			}
		}
		if file == "" {
			return nil, errors.New("unexpected private resource")
		}
		return os.ReadFile(filepath.Join(dir, file))
	}
	v, de := h.previewSubscription(context.Background(), rawJSON(map[string]any{"text": string(source), "full_only": true}))
	if de != nil {
		t.Fatalf("authorized full prepare failed code=%s detail=%+v", de.Code, de.Detail)
	}
	p := v.(subscriptionPreview)
	if p.Counts["nodes"] != 22 || p.Counts["groups"] != 9 || p.Counts["rules"] != 14 || p.Counts["match"] != 1 || p.Counts["rule_sets"] != 8 || calls != 10 {
		t.Fatal("real resource graph/counts mismatch")
	}
	if _, de := h.Apply(p.Text, p.Format); de != nil {
		t.Fatal("authorized full apply failed")
	}
	if h.doc.config.GeoIP == nil || h.doc.config.ASN == nil {
		t.Fatal("DB lost")
	}
}

func parseAuthorizedResourceOrder(b []byte, probe string) ([]string, error) {
	f, e := provider.ParseFull(b, probe)
	if e != nil {
		return nil, e
	}
	urls := []string{}
	for _, r := range f.RuleSets {
		urls = append(urls, r.URL)
	}
	return urls, nil
}

func bootstrapTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"example.com", "raw.githubusercontent.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}
func TestBootstrapIPCResourceDetailRoundTrip(t *testing.T) {
	h := fullHost(t)
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		return nil, &downloadFailure{stage: "http_status", category: "http_status", status: 403}
	}
	frame := `{"id":"diagnostic","method":"subscription.preview","params":{"url":"https://example.com/token-secret","full_only":true}}` + "\n"
	var out strings.Builder
	if e := h.Serve(context.Background(), strings.NewReader(frame), &out); e != nil {
		t.Fatal("IPC serve")
	}
	// EOF cancels in-flight work, so use a live pipe until the response is produced.
	in, w := io.Pipe()
	var response strings.Builder
	done := make(chan struct{})
	go func() { h.Serve(context.Background(), in, &response); close(done) }()
	w.Write([]byte(frame))
	time.Sleep(20 * time.Millisecond)
	w.Close()
	<-done
	var r Response
	if json.Unmarshal([]byte(response.String()), &r) != nil || r.Error == nil || r.Error.Detail == nil {
		t.Fatal("IPC detail missing")
	}
	if strings.Contains(response.String(), "token-secret") {
		t.Fatal("IPC secret leak")
	}
}

func TestBootstrapPeerOwnerIPv4IPv6AmbiguityAndSelf(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		local, peer := netip.MustParseAddrPort("127.0.0.1:23456"), netip.MustParseAddrPort("127.0.0.1:8123")
		size := 24
		if ipv6 {
			local = netip.MustParseAddrPort("[::1]:23456")
			peer = netip.MustParseAddrPort("[::1]:8123")
			size = 56
		}
		row := func(pid uint32) []byte {
			v := make([]byte, size)
			if !ipv6 {
				binary.LittleEndian.PutUint32(v, 5)
				a, b := peer.Addr().As4(), local.Addr().As4()
				copy(v[4:8], a[:])
				binary.BigEndian.PutUint16(v[8:10], peer.Port())
				copy(v[12:16], b[:])
				binary.BigEndian.PutUint16(v[16:18], local.Port())
				binary.LittleEndian.PutUint32(v[20:24], pid)
			} else {
				a, b := peer.Addr().As16(), local.Addr().As16()
				copy(v[:16], a[:])
				binary.BigEndian.PutUint16(v[20:22], peer.Port())
				copy(v[24:40], b[:])
				binary.BigEndian.PutUint16(v[44:46], local.Port())
				binary.LittleEndian.PutUint32(v[48:52], 5)
				binary.LittleEndian.PutUint32(v[52:56], pid)
			}
			return v
		}
		table := func(rows ...[]byte) []byte {
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, uint32(len(rows)))
			for _, r := range rows {
				b = append(b, r...)
			}
			return b
		}
		if e := bootstrapPeerOwner(table(row(42)), ipv6, local, peer, 99); e != nil {
			t.Fatal("external peer refused")
		}
		assertDetail(t, bootstrapPeerOwner(table(row(99)), ipv6, local, peer, 99), "proxy_connect", "self_loop")
		for _, b := range [][]byte{table(), table(row(0)), table(row(42), row(43)), {255, 255, 255, 255}} {
			assertDetail(t, bootstrapPeerOwner(b, ipv6, local, peer, 99), "proxy_connect", "proxy_identity_unknown")
		}
		stale := netip.AddrPortFrom(peer.Addr(), 8124)
		assertDetail(t, bootstrapPeerOwner(table(row(42)), ipv6, local, stale, 99), "proxy_connect", "proxy_identity_unknown")
	}
}

func TestBootstrapEgressLifecycleCancelsWithoutHoldingHostLock(t *testing.T) {
	for _, mutation := range []string{"stop", "egress"} {
		t.Run(mutation, func(t *testing.T) {
			h := fullHost(t)
			before := h.doc.text
			entered := make(chan struct{})
			done := make(chan *Error, 1)
			h.fullFetch = func(ctx context.Context, _ string, _ *clientegress.Policy, _ int64) ([]byte, error) {
				close(entered)
				<-ctx.Done()
				return nil, safeFailure(ctx, "connect", ctx.Err())
			}
			go func() {
				_, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"url": "https://example.com", "full_only": true, "_system_proxy": &bootstrapProxy{Host: "127.0.0.1", Port: 7890}, "_egress": bootstrapEgress{Generation: 0, Enabled: false}}))
				done <- e
			}()
			<-entered
			changed := make(chan struct{})
			go func() {
				h.mu.Lock()
				if mutation == "stop" {
					h.stopLocked()
				} else {
					h.transitionEgressLocked(nil, clientegress.Options{})
				}
				h.mu.Unlock()
				close(changed)
			}()
			select {
			case <-changed:
			case <-time.After(time.Second):
				t.Fatal("download blocked lifecycle mutation")
			}
			select {
			case e := <-done:
				if e == nil || e.Detail == nil || e.Detail.Category != "canceled" {
					t.Fatal("lifecycle cancel lost safe detail")
				}
			case <-time.After(time.Second):
				t.Fatal("download not canceled")
			}
			if h.doc.text != before || h.fullPending != nil {
				t.Fatal("cancel mutated source or leaked stage")
			}
		})
	}
	h := fullHost(t)
	calls := 0
	h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
		calls++
		return []byte(fullFixture), nil
	}
	_, e := h.previewSubscription(context.Background(), rawJSON(map[string]any{"url": "https://example.com", "full_only": true, "_system_proxy": &bootstrapProxy{Host: "127.0.0.1", Port: 7890}, "_egress": bootstrapEgress{Generation: 99, Enabled: false}}))
	if e == nil || e.Detail == nil || e.Detail.Category != "egress_unavailable" || calls != 0 {
		t.Fatal("stale snapshot admitted network")
	}
}

func TestBootstrapExternalConfiguredAndOtherPortsIPv4IPv6Success(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "::1"} {
		for _, port := range []uint16{7890, 8123} {
			verified := 0
			received := make(chan bool, 1)
			dial := func(context.Context, *net.Dialer, string) (net.Conn, error) {
				a, b := net.Pipe()
				go func() {
					defer b.Close()
					b.SetDeadline(time.Now().Add(time.Second))
					r := bufio.NewReader(b)
					line, e := r.ReadString('\n')
					if e != nil || line != "CONNECT 8.8.8.8:443 HTTP/1.1\r\n" {
						received <- false
						return
					}
					for {
						line, e = r.ReadString('\n')
						if e != nil {
							received <- false
							return
						}
						if line == "\r\n" {
							break
						}
					}
					io.WriteString(b, "HTTP/1.1 200 OK\r\n\r\n")
					received <- true
				}()
				return a, nil
			}
			c, e := dialBootstrapIO(context.Background(), "8.8.8.8:443", &bootstrapProxy{Host: host, Port: port}, nil, func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("literal target") }, []int{7890, 7891}, dial, func(net.Conn) error { verified++; return nil })
			if e != nil {
				t.Fatal("external configured/non-conflicting port was refused")
			}
			c.Close()
			if verified != 1 || !<-received {
				t.Fatal("external verification/CONNECT skipped")
			}
		}
	}
}

// Deliberately delay AfterFunc propagation, while the captured lifecycle's Err
// becomes canceled synchronously. Publication must never depend on scheduling
// of the asynchronous child-context cancellation callback.
type delayedBootstrapLifecycle struct{ context.Context }

func (c delayedBootstrapLifecycle) Value(any) any                { return nil }
func (c delayedBootstrapLifecycle) AfterFunc(func()) func() bool { return func() bool { return true } }

func TestBootstrapStagePublicationRechecksLifecycleGenerationAndRequest(t *testing.T) {
	for _, mutation := range []string{"stop", "egress", "generation", "request", "request-direct"} {
		t.Run(mutation, func(t *testing.T) {
			h := fullHost(t)
			fixture := strings.Replace(fullFixture, "rules:\n", `rule-providers:
  one: {type: http, behavior: classical, format: yaml, url: https://example.com/one}
rules:
`, 1)
			h.fullFetch = func(context.Context, string, *clientegress.Policy, int64) ([]byte, error) {
				return []byte("payload: ['DOMAIN,example.com']"), nil
			}
			accepted := fullPreview(t, h, fixture, "")
			if _, e := h.Apply(accepted.Text, accepted.Format); e != nil {
				t.Fatal(e)
			}
			snapshot := func() string {
				t.Helper()
				files := map[string]string{}
				err := filepath.Walk(h.workspace, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if info.Mode().IsRegular() {
						b, e := os.ReadFile(path)
						if e != nil {
							return e
						}
						rel, _ := filepath.Rel(h.workspace, path)
						files[rel] = string(b)
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				b, _ := json.Marshal(files)
				return string(b)
			}
			beforeSource, beforeFiles := h.doc.text, snapshot()
			beforeDirs, err := filepath.Glob(filepath.Join(h.workspace, "subscription-*"))
			if err != nil {
				t.Fatal(err)
			}
			// Inject the scheduling delay only in lifecycle/standalone-generation cases.
			if mutation == "stop" || mutation == "egress" || mutation == "generation" {
				life, cancel := context.WithCancel(context.Background())
				h.bootstrapLife = delayedBootstrapLifecycle{life}
				h.bootstrapCancel = cancel
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var downloadCtx context.Context
			h.fullFetch = func(ctx context.Context, _ string, _ *clientegress.Policy, _ int64) ([]byte, error) {
				downloadCtx = ctx
				return []byte("payload: ['DOMAIN,changed.example.com']"), nil
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			h.stageWrite = func(path string, b []byte) error {
				once.Do(func() { close(entered); <-release })
				return exclusiveDocumentWrite(path, b)
			}
			type result struct {
				value any
				err   *Error
			}
			done := make(chan result, 1)
			params := map[string]any{"text": strings.Replace(fixture, "https://", "https://changed.", 1), "id": accepted.ID, "full_only": true}
			if mutation != "request-direct" {
				params["_system_proxy"] = &bootstrapProxy{Host: "127.0.0.1", Port: 7890}
				params["_egress"] = bootstrapEgress{Generation: h.egressGeneration, Enabled: false}
			}
			go func() { v, e := h.previewSubscription(ctx, rawJSON(params)); done <- result{v, e} }()
			released := false
			defer func() {
				if !released {
					close(release)
				}
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("stageWrite was not reached after download")
			}
			changed := make(chan struct{})
			go func() {
				h.mu.Lock()
				switch mutation {
				case "stop":
					h.bootstrapRequests = nil
					h.stopLocked()
				case "egress":
					h.bootstrapRequests = nil
					h.transitionEgressLocked(nil, clientegress.Options{})
				case "generation":
					h.egressGeneration++
				default:
					cancel()
				}
				h.mu.Unlock()
				close(changed)
			}()
			select {
			case <-changed:
			case <-time.After(time.Second):
				t.Fatal("stageWrite blocked lifecycle mutation")
			}
			if mutation == "stop" || mutation == "egress" || mutation == "generation" {
				if downloadCtx == nil || downloadCtx.Err() != nil {
					t.Fatal("test did not isolate delayed child cancellation")
				}
			}
			close(release)
			released = true
			select {
			case got := <-done:
				if got.value != nil || got.err == nil || got.err.Detail == nil {
					t.Fatal("invalidated stage published success/pending token")
				}
				expected := "canceled"
				if mutation == "generation" {
					expected = "egress_unavailable"
				}
				if got.err.Detail.Category != expected || got.err.Detail.Stage != "validate" {
					t.Fatalf("publication classification got %+v", got.err.Detail)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("publication did not finish")
			}
			if h.fullPending != nil || h.doc.text != beforeSource {
				t.Fatal("invalidated candidate changed source or retained pending")
			}
			afterDirs, err := filepath.Glob(filepath.Join(h.workspace, "subscription-*"))
			if err != nil {
				t.Fatal(err)
			}
			a, _ := json.Marshal(beforeDirs)
			b, _ := json.Marshal(afterDirs)
			if string(a) != string(b) {
				t.Fatal("rejected private stage leaked or accepted cache removed")
			}
			if snapshot() != beforeFiles {
				t.Fatal("accepted source/cache bytes changed")
			}
		})
	}
}
