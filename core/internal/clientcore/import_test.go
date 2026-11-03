package clientcore

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/direct"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"github.com/shui1iao/Kat/internal/provider"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestImportURLParametersAndPublicAddresses(t *testing.T) {
	h := newHost(t)
	for _, p := range []string{`{}`, `{"text":null}`, `{"url":null}`, `{"text":"x","url":"https://example.com"}`, `{"url":123}`, `{"url":"http://example.com"}`, `{"url":"https://a:b@example.com"}`, `{"url":"https://example.com/#token"}`, `{"url":"https://127.0.0.1/token-secret"}`, `{"url":"https://[::ffff:8.8.8.8]/"}`} {
		_, e := h.Request(context.Background(), "import.parse", []byte(p))
		if e == nil || e.Code != "invalid_params" || strings.Contains(e.Message, "token-secret") {
			t.Fatal("invalid params or secret error")
		}
	}
	for _, s := range []string{"0.0.0.1", "10.1.2.3", "100.64.1.2", "127.0.0.1", "169.254.1.1", "172.16.1.1", "192.0.0.1", "192.168.1.1", "192.0.2.1", "198.18.1.1", "198.51.100.1", "203.0.113.1", "224.1.1.1", "240.0.0.1", "::1", "fc00::1", "fe80::1", "2001:db8::1", "2002::1", "::ffff:8.8.8.8"} {
		if publicImportIP(netip.MustParseAddr(s)) {
			t.Fatal("special IP accepted")
		}
	}
	for _, s := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !publicImportIP(netip.MustParseAddr(s)) {
			t.Fatal("public IP refused")
		}
	}
	if !validImportURL("https://example.com/share?token=fixture") || validImportURL("https://example.com/"+strings.Repeat("x", 8192)) {
		t.Fatal("URL boundary")
	}
	// Actual checked production dialer refuses a literal private target without
	// touching the network; no second DNS resolution/dial fallback is possible.
	_, e := fetchImport(context.Background(), "https://example.invalid", nil, func(tr *http.Transport) http.RoundTripper {
		if tr.Proxy != nil || tr.TLSClientConfig != nil || tr.MaxResponseHeaderBytes != 64<<10 {
			t.Fatal("production transport security")
		}
		_, e := tr.DialContext(context.Background(), "tcp", "127.0.0.1:1")
		if e == nil {
			t.Fatal("private literal dialed")
		}
		return roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, fmt.Errorf("safe test") })
	})
	if e == nil {
		t.Fatal("seam failure")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestImportFetchRealHTTPSBoundedAndCanceled(t *testing.T) {
	var mode atomic.Int32
	var calls atomic.Int32
	started := make(chan struct{}, 1)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.UserAgent() != "clash.meta" {
			t.Error("UA")
		}
		switch mode.Load() {
		case 1:
			w.Header().Set("Location", "https://example.invalid/secret")
			w.WriteHeader(302)
		case 2:
			w.WriteHeader(503)
			fmt.Fprint(w, "secret-body")
		case 3:
			w.Header().Set("Content-Encoding", "gzip")
			g := gzip.NewWriter(w)
			io.Copy(g, io.LimitReader(zeroReader{}, provider.MaxSize+1))
			g.Close()
		case 4:
			started <- struct{}{}
			<-r.Context().Done()
		default:
			fmt.Fprint(w, "socks5://127.0.0.1:1#fixture")
		}
	}))
	defer s.Close()
	seam := func(tr *http.Transport) http.RoundTripper {
		tr.TLSClientConfig = s.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
		tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", s.Listener.Addr().String())
		}
		return tr
	}
	for _, m := range []int32{0, 1, 2, 3} {
		mode.Store(m)
		before := calls.Load()
		b, e := fetchImport(context.Background(), s.URL+"/token-secret", nil, seam)
		if (m == 0) != (e == nil) || calls.Load() != before+1 {
			t.Fatal("HTTPS/status/redirect/body bound")
		}
		if m == 0 && !bytes.Contains(b, []byte("socks5")) {
			t.Fatal("body")
		}
		if e != nil && strings.Contains(e.Error(), "secret") {
			t.Fatal("error leaked")
		}
	}
	mode.Store(4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, e := fetchImport(ctx, s.URL, nil, seam); done <- e }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("not started")
	}
	cancel()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancel success")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel ignored")
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
func TestImportResponseBudget(t *testing.T) {
	h := newHost(t)
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, " - {name: node%d, type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: '%s'}\n", i, strings.Repeat("<", 4096))
	}
	params, _ := json.Marshal(map[string]any{"text": b.String()})
	_, e := h.Request(context.Background(), "import.parse", params)
	if e == nil || e.Code != "import_too_large" {
		t.Fatal("oversized frame accepted")
	}
}
func TestImportAuthorizedCompleteDraftJSONYAML(t *testing.T) {
	path := os.Getenv("KAT_AUTHORIZED_SUBSCRIPTION")
	if path == "" {
		t.Skip("private input not supplied")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("private input unavailable")
	}
	h := newHost(t)
	params, _ := json.Marshal(map[string]any{"text": string(b)})
	reply, err := h.Request(context.Background(), "import.parse", params)
	if err != nil {
		t.Fatal("private import failed")
	}
	m := reply.(map[string]any)
	outs := m["outbounds"].([]outbound.Options)
	groups := m["dependency_groups"].([]group.Options)
	if len(outs) != 22 || len(groups) != 1 || len(groups[0].Members) != 4 || groups[0].Probe.URL != h.doc.client.ProbeURL {
		t.Fatal("private import closure")
	}
	var source struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if yaml.Unmarshal(b, &source) != nil {
		t.Fatal("private comparison")
	}
	obs, via := 0, 0
	for i, o := range outs {
		raw := source.Proxies[i]
		if o.Type != "shadowsocks" || o.Method != raw["cipher"] || o.UDP == nil || !*o.UDP || o.Server != fmt.Sprint(raw["server"]) || int(o.Port) != raw["port"] {
			t.Fatal("private server changed")
		}
		if o.Obfs != nil {
			obs++
			opts := raw["plugin-opts"].(map[string]any)
			if o.Obfs.Host != opts["host"] || o.Obfs.Mode != opts["mode"] {
				t.Fatal("private obfs changed")
			}
		}
		if o.Via != "" {
			via++
			if o.Via != groups[0].Name {
				t.Fatal("via lost")
			}
		}
		pw := o.Password
		if o.Key != "" {
			pw = o.Key
		}
		if pw != raw["password"] {
			t.Fatal("private credentials changed")
		}
	}
	if obs != 18 || via != 3 {
		t.Fatal("private options counts")
	}
	text := fixture(t, map[string]any{"outbounds": outs, "groups": groups})
	if h.Validate(text) != nil {
		t.Fatal("private JSON draft validation")
	}
	var tree any
	json.Unmarshal([]byte(text), &tree)
	yb, _ := yaml.Marshal(tree)
	if h.Validate(string(yb), FormatYAML) != nil {
		t.Fatal("private YAML draft validation")
	}
	if h.server != nil || h.doc.text != initialDocument {
		t.Fatal("import changed accepted state")
	}
	t.Log("private import: 22/18/3 + one 4-member group, original option equality, valid JSON/YAML drafts; no apply/start")
}
func TestImportCheckedResolutionAndLiteralSocket(t *testing.T) {
	good := netip.MustParseAddr("8.8.8.8")
	bad := netip.MustParseAddr("127.0.0.1")
	for _, a := range [][]netip.Addr{nil, {bad}, {good, bad}, {netip.MustParseAddr("::ffff:8.8.8.8")}} {
		if _, e := checkedImportAddresses(a, nil); e == nil {
			t.Fatal("unsafe DNS answer accepted")
		}
	}
	calls := 0
	controls := 0
	d := direct.New(direct.Options{Timeout: time.Second, Resolve: func(ctx context.Context, h string) ([]netip.Addr, error) {
		calls++
		return checkedImportAddresses([]netip.Addr{good}, nil)
	}, Guard: func(_ context.Context, ip netip.Addr) bool { return !publicImportIP(ip) }, Control: func(_ context.Context, network, address string, raw syscall.RawConn) error {
		controls++
		if address != "8.8.8.8:443" {
			t.Fatal("second resolution or unchecked address")
		}
		return errors.New("test stops before connect")
	}})
	if _, e := d.DialTCP(context.Background(), outbound.Addr{Host: "subscription.invalid", Port: 443}); e == nil || calls != 1 || controls != 1 {
		t.Fatal("checked literal not used")
	}
}
func TestImportLegacyProviderRuntimeProjectionRealSource(t *testing.T) {
	path := os.Getenv("KAT_AUTHORIZED_SUBSCRIPTION")
	if path == "" {
		t.Skip("private input not supplied")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("private input unavailable")
	}
	for _, format := range []DocumentFormat{FormatJSON, FormatYAML} {
		t.Run(string(format), func(t *testing.T) {
			h := newHost(t)
			if os.WriteFile(filepath.Join(h.workspace, "providers", "legacy.cache"), b, 0600) != nil {
				t.Fatal("private cache")
			}
			text := fixture(t, map[string]any{"dns": map[string]any{"server": "system"}, "providers": []any{map[string]any{"name": "legacy", "type": "http", "url": "http://127.0.0.1:1/no-fetch", "interval": "1h"}}, "groups": []any{map[string]any{"name": "pick", "type": "select", "use": []string{"legacy"}}}})
			if format == FormatYAML {
				var v any
				json.Unmarshal([]byte(text), &v)
				yb, _ := yaml.Marshal(v)
				text = "# legacy source: preserve this comment\n" + string(yb)
			}
			if strings.Contains(text, "dependency_probe_url") {
				t.Fatal("test unexpectedly contains new field")
			}
			if h.Validate(text, format) != nil {
				t.Fatal("legacy source validation")
			}
			if _, e := applyLegacyFixture(h, text, format); e != nil {
				t.Fatal("legacy apply")
			}
			if _, e := h.Start(); e != nil {
				t.Fatal("legacy cached dependency start")
			}
			c := h.server.CurrentConfig()
			obs, via, dep := 0, 0, 0
			for _, o := range c.Outbounds {
				if o.Obfs != nil {
					obs++
				}
				if o.Via != "" {
					via++
				}
			}
			for _, g := range c.Groups {
				if g.Type == "url-test" {
					dep++
					if len(g.Members) != 4 || g.Probe.URL != h.doc.client.ProbeURL {
						t.Fatal("legacy dependency URL/members")
					}
				}
			}
			if len(c.Outbounds) != 22 || obs != 18 || via != 3 || dep != 1 || c.Providers[0].DependencyProbeURL != h.doc.client.ProbeURL {
				t.Fatal("legacy graph")
			}
			disk, e := os.ReadFile(h.path)
			if e != nil || string(disk) != text || h.doc.text != text {
				t.Fatal("legacy source changed")
			}
		})
	}
	// An explicitly pinned provider URL wins over a later client probe choice.
	h := newHost(t)
	text := fixture(t, map[string]any{"providers": []any{map[string]any{"name": "p", "type": "http", "url": "http://127.0.0.1:1/", "dependency_probe_url": "https://example.org/pinned"}}})
	d, err := parseDocument(text, h.workspace)
	if err != nil || d.config.Providers[0].DependencyProbeURL != "https://example.org/pinned" {
		t.Fatal("explicit provider URL overwritten")
	}
}
