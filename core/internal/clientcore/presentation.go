package clientcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"github.com/shui1iao/Kat/internal/procattr"
	"github.com/shui1iao/Kat/internal/userio"
	"golang.org/x/net/proxy"
	"golang.org/x/net/publicsuffix"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sync"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

func (h *Host) filterPreview(raw json.RawMessage) (any, *Error) {
	var p struct {
		Filter       string `json:"filter"`
		Exclude      string `json:"exclude_filter"`
		IncludeGroup string `json:"include_group"`
		GroupName    string `json:"group_name"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	if len(p.Filter) > 4096 || len(p.Exclude) > 4096 {
		return nil, fail("invalid_params", "params.filter", "Regular expression too long")
	}
	// An empty filter keeps the legacy disabled preview unless a source is set.
	matches, e := group.MemberFilter(group.Options{Filter: p.Filter, ExcludeFilter: p.Exclude})
	if e != nil {
		return map[string]any{"names": []string{}, "error": "正则表达式无效（使用 RE2 语法）"}, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	names := []string{}
	if p.IncludeGroup != "" {
		cfg := h.doc.config
		if h.server != nil {
			cfg = h.server.CurrentConfig()
		}
		names, err := kernel.PreviewSourceGroup(cfg, p.IncludeGroup, p.GroupName, group.Options{Filter: p.Filter, ExcludeFilter: p.Exclude})
		if err != nil {
			return map[string]any{"names": []string{}, "error": "来源策略组无效（不存在、循环引用或含有 relay 链）"}, nil
		}
		return map[string]any{"names": names}, nil
	}
	if p.GroupName != "" {
		return nil, fail("invalid_params", "params.group_name", "group_name requires include_group")
	}
	if p.Filter != "" {
		cfg := h.doc.config
		if h.server != nil {
			cfg = h.server.CurrentConfig()
		}
		for _, o := range cfg.Outbounds {
			if o.Type != "direct" && o.Type != "reject" && matches(outbound.Options(o).FilterLabel(), o.Type) {
				names = append(names, o.Name)
			}
		}
	}
	return map[string]any{"names": names}, nil
}

const maxIconBytes = 512 << 10

func iconData(b []byte) (string, error) {
	if len(b) == 0 || len(b) > maxIconBytes {
		return "", errors.New("icon size")
	}
	typ := http.DetectContentType(b)
	switch typ {
	case "image/png", "image/jpeg", "image/webp", "image/gif", "image/x-icon", "image/vnd.microsoft.icon":
	default:
		// net/http's sniff table does not recognize all ICO/SVG variants.
		if len(b) >= 4 && bytes.Equal(b[:4], []byte{0, 0, 1, 0}) {
			typ = "image/x-icon"
		} else {
			dec := xml.NewDecoder(bytes.NewReader(b))
			found := false
			for {
				tok, e := dec.Token()
				if e != nil {
					break
				}
				if el, ok := tok.(xml.StartElement); ok {
					found = el.Name.Local == "svg"
					break
				}
			}
			if !found {
				return "", errors.New("icon type")
			}
			typ = "image/svg+xml"
		}
	}
	return "data:" + typ + ";base64," + base64.StdEncoding.EncodeToString(b), nil
}
func iconURL(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && len(raw) <= 2048 && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil && u.Fragment == ""
}
func (h *Host) iconDir() (string, error) {
	dir := filepath.Join(h.workspace, "icons")
	if st, e := userio.Lstat(dir); e == nil && (!st.IsDir() || st.Mode()&os.ModeSymlink != 0) {
		return "", errors.New("icon cache refused")
	}
	if e := userio.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	if e := rejectReparse(dir); e != nil {
		return "", e
	}
	if e := secureWorkspace(dir); e != nil {
		return "", e
	}
	return dir, nil
}
func readIcon(path string) (string, time.Time) {
	st, e := userio.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || rejectReparse(path) != nil || st.Size() > maxIconBytes {
		return "", time.Time{}
	}
	f, e := userio.Open(path)
	if e != nil {
		return "", time.Time{}
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(st, opened) {
		return "", time.Time{}
	}
	b, e := io.ReadAll(io.LimitReader(f, maxIconBytes+1))
	if e != nil {
		return "", time.Time{}
	}
	data, e := iconData(b)
	if e != nil {
		return "", time.Time{}
	}
	return data, st.ModTime()
}
func (h *Host) fetchIcon(ctx context.Context, raw string) ([]byte, error) {
	ctx, done := h.ipContext(ctx)
	defer done()
	h.mu.Lock()
	h.syncTUNEgressLocked()
	if !h.hostEgressReadyLocked() {
		h.mu.Unlock()
		return nil, dl("connect", "egress_unavailable")
	}
	ctx, stopBootstrap := h.bootstrapContextLocked(ctx)
	defer stopBootstrap()
	running := h.server != nil
	policy := h.egress
	expected, _ := ctx.Value(iconExpectedKey{}).(*bootstrapEgress)
	stale := bootstrapFrom(ctx) != nil && (expected == nil || expected.Generation != h.egressGeneration || expected.Enabled != (h.egress != nil))
	h.mu.Unlock()
	if stale || checkHostEgress(ctx) != nil {
		return nil, dl("connect", "egress_unavailable")
	}
	if h.iconFetch != nil {
		return h.iconFetch(ctx, raw)
	} // network-only test seam
	if !running {
		if bootstrapFrom(ctx) != nil {
			c, cancel := context.WithTimeout(ctx, 6*time.Second)
			b, e := fetchImportBounded(c, raw, policy, h.iconTransport, maxIconBytes)
			cancel()
			if e == nil {
				return b, nil
			}
			f := safeFailure(ctx, "connect", e).(*downloadFailure)
			h.iconFailureFor(ctx, f.stage, f.category)
		}
		return fetchImportBounded(context.WithValue(ctx, bootstrapKey{}, (*bootstrapProxy)(nil)), raw, policy, h.iconTransport, maxIconBytes)
	}
	return h.fetchKernelAsset(ctx, raw, maxIconBytes)
}

// Shared registered-origin SOCKS path for icons and subscription resources.
// No TUN, service lease or physical-egress prerequisite: plain local SOCKS
// supplies the real OS tuple even when network takeover is entirely disabled.
func (h *Host) fetchKernelAsset(ctx context.Context, raw string, limit int64) ([]byte, error) {
	h.mu.Lock()
	running := h.server != nil
	port := h.doc.client.SOCKSPort
	epoch := h.manualCtx
	h.mu.Unlock()
	if !running {
		return nil, dl("connect", "egress_unavailable")
	}
	ctx, cancelBudget := context.WithTimeout(ctx, 30*time.Second)
	defer cancelBudget()
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(epoch, cancel)
	defer stop()
	if epoch.Err() != nil {
		cancel()
	}
	ctx = child
	// Use the existing loopback SOCKS entry: the kernel makes the same routing,
	// DNS, nested-group and controlled egress decisions as ordinary connections.
	d, e := proxy.SOCKS5("tcp", portAddress(port), nil, &iconSOCKSForward{})
	if e != nil {
		return nil, e
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, dl("connect", "connect_failed")
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10, DialContext: cd.DialContext}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, CheckRedirect: subscriptionRedirectPolicy(ctx)}
	req, e := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if e != nil {
		return nil, e
	}
	var transportStage atomic.Int32
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{TLSHandshakeStart: func() { transportStage.Store(1) }, TLSHandshakeDone: func(_ tls.ConnectionState, e error) {
		if e == nil {
			transportStage.Store(2)
		}
	}}))
	req.Header.Set("User-Agent", "clash.meta")
	resp, e := cl.Do(req)
	if e != nil {
		stage := "connect"
		if transportStage.Load() == 1 {
			stage = "tls"
		}
		if transportStage.Load() == 2 {
			stage = "http_status"
		}
		return nil, safeFailure(ctx, stage, e)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		category := "http_status"
		if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
			category = "redirect_refused"
		}
		return nil, &downloadFailure{stage: "http_status", category: category, status: resp.StatusCode}
	}
	captureSubscriptionHeaders(ctx, resp.Header)
	b, e := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if e != nil {
		return nil, safeFailure(ctx, "body_read", e)
	}
	if int64(len(b)) > limit {
		return nil, dl("body_read", "size_limit")
	}
	return b, nil
}
func (h *Host) getIcon(ctx context.Context, raw json.RawMessage) (any, *Error) {
	var p struct {
		URL      string           `json:"url,omitempty"`
		Group    string           `json:"group,omitempty"`
		Domain   string           `json:"domain,omitempty"`
		Process  string           `json:"process_path,omitempty"`
		Proxy    *bootstrapProxy  `json:"_system_proxy,omitempty"`
		Expected *bootstrapEgress `json:"_egress,omitempty"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	// Resolve group label from accepted source only; never log asserted WebView text.
	var bootstrapLife context.Context
	h.mu.Lock()
	h.syncTUNEgressLocked()
	label := ""
	for _, g := range h.doc.config.Groups {
		if g.Name == p.Group {
			label = g.Name
			break
		}
	}
	if p.Proxy != nil && (p.Expected == nil || p.Expected.Generation != h.egressGeneration || p.Expected.Enabled != (h.egress != nil)) {
		h.mu.Unlock()
		return map[string]any{"data_uri": ""}, nil
	}
	if p.Proxy != nil {
		if h.bootstrapLife == nil {
			h.bootstrapLife, h.bootstrapCancel = context.WithCancel(context.Background())
		}
		bootstrapLife = h.bootstrapLife
	}
	h.mu.Unlock()
	ctx = context.WithValue(ctx, iconGroupKey{}, label)
	if p.Proxy != nil {
		ctx = context.WithValue(ctx, bootstrapKey{}, p.Proxy)
	}
	empty := map[string]any{"data_uri": ""}
	if p.URL == "" && p.Process != "" {
		if !h.isObservedProcessPath(p.Process) {
			return empty, nil
		}
		return map[string]any{"data_uri": extractProcessIconDataURI(p.Process)}, nil
	}
	if p.URL == "" && p.Domain != "" {
		return h.getDomainIcon(ctx, p.Domain, p.Proxy, p.Expected, bootstrapLife), nil
	}
	if strings.HasPrefix(strings.TrimSpace(p.URL), "<svg") {
		if !group.ValidIcon(p.URL) {
			h.iconFailureFor(ctx, "url_check", "invalid_format")
			return empty, nil
		}
		data, e := iconData([]byte(p.URL))
		if e != nil {
			h.iconFailureFor(ctx, "content_type", "invalid_format")
			return empty, nil
		}
		return map[string]any{"data_uri": data}, nil
	}
	if !iconURL(p.URL) {
		h.iconFailureFor(ctx, "url_check", "address_refused")
		return empty, nil
	}
	dir, e := h.iconDir()
	if e != nil {
		h.iconFailureFor(ctx, "cache_directory", localFailure(e))
		return empty, nil
	}
	path := filepath.Join(dir, fmt.Sprintf("%x", sha256.Sum256([]byte(p.URL)))+".img")
	data, at := readIcon(path)
	if data != "" && time.Since(at) < 7*24*time.Hour {
		return map[string]any{"data_uri": data}, nil
	}
	h.iconMu.Lock()
	if h.iconClosed {
		h.iconMu.Unlock()
		return empty, nil
	}
	done, exists := h.iconPending[path]
	if !exists {
		done = make(chan struct{})
		h.iconPending[path] = done
		h.iconWG.Add(1)
		go func() {
			defer h.iconWG.Done()
			c, cancel := context.WithTimeout(context.WithValue(context.WithValue(context.WithValue(h.iconCtx, iconExpectedKey{}, p.Expected), iconGroupKey{}, label), bootstrapKey{}, p.Proxy), 12*time.Second)
			defer cancel()
			if bootstrapLife != nil {
				stop := context.AfterFunc(bootstrapLife, cancel)
				defer stop()
				if bootstrapLife.Err() != nil {
					cancel()
				}
			}
			b, e := h.fetchIcon(c, p.URL)
			if e != nil {
				f := safeFailure(c, "connect", e).(*downloadFailure)
				h.iconFailureFor(c, f.stage, f.category)
			} else if _, e = iconData(b); e != nil {
				h.iconFailureFor(c, "content_type", "invalid_format")
			} else if e = atomicWriteContext(c, path, b); e != nil {
				h.iconFailureFor(c, "cache_write", localFailure(e))
			}
			h.iconMu.Lock()
			delete(h.iconPending, path)
			close(done)
			h.iconMu.Unlock()
		}()
	}
	h.iconMu.Unlock()
	if data != "" {
		return map[string]any{"data_uri": data}, nil
	} // stale while refresh; failure retains bytes
	select {
	case <-ctx.Done():
		return empty, nil
	case <-done:
	}
	data, _ = readIcon(path)
	return map[string]any{"data_uri": data}, nil
}

// A core-owned loopback connection is deliberately unknown to Windows process
// rules unless its private original tuple has been registered. Reuse the HTTP
// bridge's existing unforgeable in-process registry. The origin is this actual
// socket, so normal OS owner/epoch checks identify the real core executable;
// no WebView field, proxy header, claimed name or permission bypass is involved.
type iconSOCKSForward struct{}

func (f *iconSOCKSForward) Dial(network, address string) (net.Conn, error) {
	return f.DialContext(context.Background(), network, address)
}
func (f *iconSOCKSForward) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c, e := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, address)
	if e != nil {
		return nil, e
	}
	return procattr.RegisterHTTP(c, procattr.NewOrigin(c.LocalAddr(), c.RemoteAddr())), nil
}

// Stage and classification only. Never store URLs, hashes, paths, peers or raw
// errors; Rust repeats these finite allowlists before diagnostics export.
var iconLogStages = map[string]bool{"url_check": true, "resolve": true, "connect": true, "tls": true, "http_status": true, "body_read": true, "content_type": true, "cache_directory": true, "cache_write": true, "proxy_resolve": true, "proxy_connect": true, "proxy_http": true}
var iconLogCategories = map[string]bool{"invalid_format": true, "address_refused": true, "fake_ip": true, "dns_failed": true, "canceled": true, "timeout": true, "connect_failed": true, "tls_certificate": true, "tls_handshake": true, "http_status": true, "redirect_refused": true, "read_failed": true, "size_limit": true, "egress_unavailable": true, "permission_denied": true, "disk_full": true, "unsafe_file": true, "file_io": true, "unknown": true, "proxy_unsupported": true, "proxy_identity_unknown": true, "proxy_protocol": true, "header_limit": true, "self_loop": true, "proxy_connect_failed": true, "proxy_auth_required": true, "proxy_http": true, "proxy_redirect": true, "proxy_rejected": true}

func (h *Host) iconFailure(stage, category string) {
	if !iconLogStages[stage] || !iconLogCategories[category] {
		return
	}
	h.logs.record(kernel.ClientLogEvent{Time: time.Now(), Level: "warn", Event: "icon_" + stage + "_failed", Code: category})
}

// Disk-only startup hydration: configured icon URLs only, no caller-selected
// paths, no network and a total <=1MiB data budget below the 2MiB IPC ceiling.
func (h *Host) cachedIcons() map[string]string {
	h.mu.Lock()
	groups := append([]kernel.GroupConfig(nil), h.doc.config.Groups...)
	h.mu.Unlock()
	out := map[string]string{}
	dir, e := h.iconDir()
	if e != nil {
		return out
	}
	total := 0
	for _, g := range groups {
		if !iconURL(g.Icon) {
			continue
		}
		path := filepath.Join(dir, fmt.Sprintf("%x", sha256.Sum256([]byte(g.Icon)))+".img")
		data, _ := readIcon(path)
		if data != "" && total+len(data)+len(g.Icon) < 1<<20 {
			out[g.Icon] = data
			total += len(data) + len(g.Icon)
		}
	}
	return out
}

var (
	observedProcPaths sync.Map
	htmlLinkTagRe     = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	htmlAttrRe        = regexp.MustCompile(`(?is)\b(rel|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)
)

func rememberObservedProcessPath(p string) {
	p = strings.TrimSpace(p)
	if p != "" && len(p) <= 1024 && !strings.HasPrefix(p, `\`) && !strings.HasPrefix(p, "//") {
		observedProcPaths.Store(strings.ToLower(p), struct{}{})
	}
}

func validIconDomain(raw string) (string, bool) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if len(d) == 0 || len(d) > 253 || !strings.Contains(d, ".") || d == "localhost" || strings.HasSuffix(d, ".local") || strings.HasSuffix(d, ".internal") {
		return "", false
	}
	if _, err := netip.ParseAddr(d); err == nil {
		return "", false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.') {
			return "", false
		}
	}
	return d, true
}

func (h *Host) isObservedProcessPath(targetPath string) bool {
	want := strings.TrimSpace(targetPath)
	if want == "" || strings.HasPrefix(want, `\`) || strings.HasPrefix(want, "//") {
		return false
	}
	if _, ok := observedProcPaths.Load(strings.ToLower(want)); ok {
		return true
	}
	h.mu.Lock()
	s := h.server
	h.mu.Unlock()
	if s == nil {
		return false
	}
	active, closed := s.ClientConnections(500)
	found := false
	for i := range active {
		rememberObservedProcessPath(active[i].ProcessPath)
		if strings.EqualFold(active[i].ProcessPath, want) {
			found = true
		}
	}
	for i := range closed {
		rememberObservedProcessPath(closed[i].ProcessPath)
		if strings.EqualFold(closed[i].ProcessPath, want) {
			found = true
		}
	}
	return found
}

// fetchSiteBytes performs a bounded GET via the running kernel SOCKS5 port,
// permitting up to 4 HTTPS redirects to public hosts so real websites'
// root pages and <link rel="icon"> assets resolve cleanly.
func (h *Host) fetchSiteBytes(ctx context.Context, rawURL string, limit int64) ([]byte, *url.URL, error) {
	h.mu.Lock()
	running := h.server != nil
	port := h.doc.client.SOCKSPort
	epoch := h.manualCtx
	h.mu.Unlock()
	if !running {
		b, err := h.fetchIcon(ctx, rawURL)
		u, _ := url.Parse(rawURL)
		return b, u, err
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(epoch, cancel)
	defer stop()
	if epoch.Err() != nil {
		cancel()
	}
	d, err := proxy.SOCKS5("tcp", portAddress(port), nil, &iconSOCKSForward{})
	if err != nil {
		return nil, nil, err
	}
	cd, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, nil, errors.New("socks dialer")
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10, DialContext: cd.DialContext}
	defer tr.CloseIdleConnections()
	cl := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 4 || (req.URL.Scheme != "https" && req.URL.Scheme != "http") || req.URL.User != nil {
				return http.ErrUseLastResponse
			}
			if _, ok := validIconDomain(req.URL.Hostname()); !ok {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(child, "GET", rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, nil, errors.New("http status")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || int64(len(b)) > limit {
		return nil, nil, errors.New("body size")
	}
	return b, resp.Request.URL, nil
}

func extractHTMLIconURLs(htmlBytes []byte, base *url.URL) []string {
	if base == nil || len(htmlBytes) == 0 {
		return nil
	}
	// Inspect up to </head> or first 64 KiB
	s := string(htmlBytes)
	if idx := strings.Index(strings.ToLower(s), "</head>"); idx > 0 {
		s = s[:idx]
	}
	var appleIcons, stdIcons []string
	for _, tag := range htmlLinkTagRe.FindAllString(s, 32) {
		var rel, href string
		for _, m := range htmlAttrRe.FindAllStringSubmatch(tag, -1) {
			k := strings.ToLower(m[1])
			v := m[2]
			if v == "" {
				v = m[3]
			}
			if v == "" {
				v = m[4]
			}
			if k == "rel" {
				rel = strings.ToLower(v)
			} else if k == "href" {
				href = strings.TrimSpace(v)
			}
		}
		if href == "" || strings.HasPrefix(href, "data:") || strings.HasPrefix(href, "javascript:") {
			continue
		}
		hasIcon := false
		isApple := false
		for _, tok := range strings.Fields(rel) {
			if tok == "apple-touch-icon" || tok == "apple-touch-icon-precomposed" {
				hasIcon, isApple = true, true
			} else if tok == "icon" {
				hasIcon = true
			}
		}
		if !hasIcon {
			continue
		}
		u, err := base.Parse(href)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
			continue
		}
		if _, ok := validIconDomain(u.Hostname()); !ok {
			continue
		}
		if isApple {
			appleIcons = append(appleIcons, u.String())
		} else {
			stdIcons = append(stdIcons, u.String())
		}
	}
	return append(appleIcons, stdIcons...)
}

func (h *Host) resolveDomainIconBytes(baseCtx context.Context, domain string) []byte {
	hosts := []string{domain}
	if etld1, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil && etld1 != "" && etld1 != domain {
		hosts = append(hosts, etld1)
	}
	// 1. Try direct website: HTML <link rel="icon" / "apple-touch-icon"> & /favicon.ico
	for _, host := range hosts {
		c1, cancel1 := context.WithTimeout(baseCtx, 4*time.Second)
		favBytes, _, err := h.fetchSiteBytes(c1, "https://"+host+"/favicon.ico", maxIconBytes)
		cancel1()
		if err == nil {
			if _, ierr := iconData(favBytes); ierr == nil {
				return favBytes
			}
		}
		c2, cancel2 := context.WithTimeout(baseCtx, 4*time.Second)
		pageBytes, finalURL, err := h.fetchSiteBytes(c2, "https://"+host+"/", 64<<10)
		cancel2()
		if err == nil {
			for _, iconHref := range extractHTMLIconURLs(pageBytes, finalURL) {
				c3, cancel3 := context.WithTimeout(baseCtx, 4*time.Second)
				ib, _, err := h.fetchSiteBytes(c3, iconHref, maxIconBytes)
				cancel3()
				if err == nil {
					if _, ierr := iconData(ib); ierr == nil {
						return ib
					}
				}
			}
		}
	}
	// 2. Fallback to high-res favicon services (handles pure CDN/API subdomains)
	var fallbacks []string
	for _, host := range hosts {
		fallbacks = append(fallbacks,
			"https://t2.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://"+host+"&size=64",
			"https://icons.duckduckgo.com/ip3/"+host+".ico",
		)
	}
	for _, u := range fallbacks {
		c, cancel := context.WithTimeout(baseCtx, 5*time.Second)
		b, _, err := h.fetchSiteBytes(c, u, maxIconBytes)
		cancel()
		if err == nil {
			if _, ierr := iconData(b); ierr == nil {
				return b
			}
		}
	}
	return nil
}

func (h *Host) getDomainIcon(ctx context.Context, rawDomain string, proxyCfg *bootstrapProxy, expected *bootstrapEgress, _ context.Context) map[string]any {
	empty := map[string]any{"data_uri": ""}
	domain, ok := validIconDomain(rawDomain)
	if !ok {
		return empty
	}
	dir, e := h.iconDir()
	if e != nil {
		return empty
	}
	path := filepath.Join(dir, fmt.Sprintf("dom-%x.img", sha256.Sum256([]byte(domain))))
	data, at := readIcon(path)
	if data != "" && time.Since(at) < 7*24*time.Hour {
		return map[string]any{"data_uri": data}
	}
	h.iconMu.Lock()
	if h.iconClosed {
		h.iconMu.Unlock()
		return empty
	}
	done, exists := h.iconPending[path]
	if !exists {
		done = make(chan struct{})
		h.iconPending[path] = done
		h.iconWG.Add(1)
		go func() {
			defer h.iconWG.Done()
			baseCtx := context.WithValue(context.WithValue(h.iconCtx, iconExpectedKey{}, expected), bootstrapKey{}, proxyCfg)
			if b := h.resolveDomainIconBytes(baseCtx, domain); len(b) > 0 {
				_ = atomicWriteContext(h.iconCtx, path, b)
			}
			h.iconMu.Lock()
			delete(h.iconPending, path)
			close(done)
			h.iconMu.Unlock()
		}()
	}
	h.iconMu.Unlock()
	if data != "" {
		return map[string]any{"data_uri": data}
	}
	select {
	case <-ctx.Done():
		return empty
	case <-done:
	}
	data, _ = readIcon(path)
	return map[string]any{"data_uri": data}
}
