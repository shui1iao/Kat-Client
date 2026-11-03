package clientcore

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/clientdiag"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/procattr"
	"golang.org/x/net/proxy"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type diagnosticRow struct {
	Name  string `json:"name"`
	URL   string `json:"url,omitempty"`
	Group string `json:"group,omitempty"`
	clientdiag.Verdict
	Rule     string   `json:"rule,omitempty"`
	Chain    []string `json:"chain"`
	Node     string   `json:"node,omitempty"`
	HTTP     int      `json:"http_status,omitempty"`
	Duration int64    `json:"duration_ms"`
	IP       string   `json:"ip,omitempty"`
}
type diagnosticReply struct {
	At    time.Time       `json:"at"`
	Items []diagnosticRow `json:"items"`
}

var connectivityTargets = []struct{ Name, URL string }{{"Google", "https://www.google.com/generate_204"}, {"YouTube", "https://www.youtube.com/"}, {"Telegram", "https://telegram.org/"}, {"GitHub", "https://github.com/"}, {"Cloudflare", "https://www.cloudflare.com/cdn-cgi/trace"}}

// Each forwarder owns ONE real local SOCKS TCP socket. The registration is made
// before SOCKS sends the target and removed when the socket closes. This neither
// changes selections nor temporarily switches global mode. No WebView tuple,
// proxy header, cookie, token, login or arbitrary forced group is admitted.
type diagnosticForward struct {
	s        *kernel.Server
	group    string
	mu       sync.Mutex
	observed []*kernel.ClientDiagnostic
}
type diagnosticConn struct {
	net.Conn
	once    sync.Once
	cleanup func()
}

func (c *diagnosticConn) Close() error { e := c.Conn.Close(); c.once.Do(c.cleanup); return e }
func (d *diagnosticForward) Dial(n, a string) (net.Conn, error) {
	return d.DialContext(context.Background(), n, a)
}
func (d *diagnosticForward) DialContext(ctx context.Context, n, a string) (net.Conn, error) {
	c, e := (&net.Dialer{}).DialContext(ctx, n, a)
	if e != nil {
		return nil, e
	}
	ap, e := netip.ParseAddrPort(c.LocalAddr().String())
	if e != nil {
		c.Close()
		return nil, e
	}
	obs, cleanup, e := d.s.RegisterClientDiagnostic(ap, d.group)
	if e != nil {
		c.Close()
		return nil, e
	}
	d.mu.Lock()
	d.observed = append(d.observed, obs)
	d.mu.Unlock()
	return &diagnosticConn{Conn: procattr.RegisterHTTP(c, procattr.NewOrigin(c.LocalAddr(), c.RemoteAddr())), cleanup: cleanup}, nil
}
func (d *diagnosticForward) snapshot() (kernel.ConnInfo, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var last kernel.ConnInfo
	node := ""
	same := true
	for _, obs := range d.observed {
		ci := obs.Snapshot()
		if len(ci.Chain) == 0 {
			continue
		}
		next := ci.Chain[len(ci.Chain)-1]
		if node != "" && node != next {
			same = false
		}
		node = next
		last = ci
	}
	return last, same
}
func diagnosticHTTP(s *kernel.Server, port int, group string) (*http.Client, *http.Transport, *diagnosticForward, error) {
	forward := &diagnosticForward{s: s, group: group}
	dial, e := proxy.SOCKS5("tcp", portAddress(port), nil, forward)
	if e != nil {
		return nil, nil, nil, e
	}
	tr := &http.Transport{Proxy: nil, DialContext: dial.(proxy.ContextDialer).DialContext, DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10, ResponseHeaderTimeout: 8 * time.Second}
	return &http.Client{Transport: tr, CheckRedirect: clientdiag.Redirect}, tr, forward, nil
}
func fetchDiagnostic(client *http.Client) clientdiag.Fetch {
	return fetchDiagnosticLimit(client, clientdiag.BodyLimit)
}
func fetchDiagnosticLimit(client *http.Client, limit int) clientdiag.Fetch {
	return func(ctx context.Context, method, u string) (clientdiag.Page, error) {
		var body io.Reader
		if method == "POST" {
			body = strings.NewReader("{}")
		}
		req, e := http.NewRequestWithContext(ctx, method, u, body)
		if e != nil {
			return clientdiag.Page{}, e
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 Kat-Diagnostics/1.0")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		if method == "POST" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, e := client.Do(req)
		if e != nil {
			return clientdiag.Page{}, e
		}
		defer resp.Body.Close()
		// Preserve the status even when the decompressed body fails / exceeds
		// its service-specific hard cap. Partial bodies never reach a parser.
		page := clientdiag.Page{Status: resp.StatusCode, URL: resp.Request.URL.String(), Location: resp.Header.Get("Location")}
		b, e := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
		if e != nil {
			return page, e
		}
		if len(b) > limit {
			return page, clientdiag.ErrBodyLimit
		}
		page.Body = string(b)
		return page, nil
	}
}
func primaryDiagnosticGroups(c kernel.Config) []string {
	groups := map[string]bool{}
	for _, g := range c.Groups {
		groups[g.Name] = true
	}
	out := []string{}
	add := func(n string) {
		if groups[n] && len(out) < 5 {
			for _, v := range out {
				if v == n {
					return
				}
			}
			out = append(out, n)
		}
	}
	if c.Routing != nil {
		for _, r := range c.Routing.Rules {
			add(r.Outbound)
		}
		add(c.Routing.Final)
	}
	return out
}
func (h *Host) diagnosticsNetwork(ctx context.Context, raw json.RawMessage) (any, *Error) {
	var p struct {
		Kind string   `json:"kind"`
		Run  bool     `json:"run"`
		URLs []string `json:"urls,omitempty"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	if p.Kind != "unlock" && p.Kind != "connectivity" && p.Kind != "exit" {
		return nil, fail("invalid_params", "params.kind", "Expected unlock, connectivity or exit")
	}
	if len(p.URLs) > 16 || (p.Kind != "connectivity" && len(p.URLs) > 0) {
		return nil, fail("invalid_params", "params.urls", "At most 16 connectivity URLs")
	}
	for _, u := range p.URLs {
		if !clientdiag.ValidURL(u) {
			return nil, fail("invalid_params", "params.urls", "Expected HTTPS URL without credentials or fragment")
		}
	}
	// A read of the last result performs absolutely no network requests.
	if !p.Run {
		h.diagCacheMu.Lock()
		defer h.diagCacheMu.Unlock()
		if cached := h.diagCache[p.Kind]; cached != nil {
			return visibleDiagnosticCache(p.Kind, cached), nil
		}
		cached := h.readDiagnosticCache(p.Kind)
		if cached != nil {
			if h.diagCache == nil {
				h.diagCache = map[string]*diagnosticReply{}
			}
			h.diagCache[p.Kind] = cached
		}
		return cached, nil
	}
	if !h.diagRun.TryLock() {
		return nil, fail("diagnostic_busy", "", "A diagnostic is already running")
	}
	defer h.diagRun.Unlock()
	h.mu.Lock()
	s, epoch, port := h.server, h.manualCtx, h.doc.client.SOCKSPort
	if s == nil || !h.localReady {
		h.mu.Unlock()
		return nil, fail("not_running", "runtime", "Core is stopped")
	}
	groups := primaryDiagnosticGroups(h.doc.config)
	h.manualWG.Add(1)
	h.mu.Unlock()
	defer h.manualWG.Done()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(epoch, cancel)
	defer stop()
	if epoch.Err() != nil {
		cancel()
	}
	jobs := []diagnosticRow{}
	switch p.Kind {
	case "unlock":
		for _, n := range clientdiag.Services {
			jobs = append(jobs, diagnosticRow{Name: n})
		}
	case "connectivity":
		for _, t := range connectivityTargets {
			jobs = append(jobs, diagnosticRow{Name: t.Name, URL: t.URL})
		}
		for _, u := range p.URLs {
			jobs = append(jobs, diagnosticRow{Name: u, URL: u})
		}
	case "exit":
		for _, g := range groups {
			jobs = append(jobs, diagnosticRow{Name: g, Group: g, URL: "https://www.cloudflare.com/cdn-cgi/trace"})
		}
	}
	// One host-wide batch; four workers shared by all kinds. The eight-second
	// budget begins on dispatch, includes redirects/body and all service endpoints.
	indices := make(chan int)
	var wg sync.WaitGroup
	for range min(4, len(jobs)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range indices {
				r := jobs[i]
				start := time.Now()
				item, c := context.WithTimeout(ctx, 8*time.Second)
				client, tr, forward, e := diagnosticHTTP(s, port, r.Group)
				if e != nil {
					r.Verdict = clientdiag.Verdict{Result: "failed", Reason: "本地入口不可用"}
				} else {
					if h.diagTransport != nil {
						client.Transport = h.diagTransport(tr)
					}
					fetch := fetchDiagnostic(client)
					if p.Kind == "unlock" {
						fetch = fetchDiagnosticLimit(client, clientdiag.ResponseLimit(r.Name))
						r.Verdict = clientdiag.Detect(item, r.Name, fetch)
						r.HTTP = r.Verdict.HTTPStatus
					} else {
						page, err := fetch(item, "GET", r.URL)
						r.HTTP = page.Status
						if err != nil {
							r.Verdict = clientdiag.Verdict{Result: "failed", Reason: diagnosticFailure(err)}
						} else {
							r.HTTP = page.Status
							r.Result = "ok"
							if p.Kind == "exit" {
								ip, region, err := clientdiag.Trace(page.Body)
								if err != nil || page.Status != 200 {
									r.Verdict = clientdiag.Verdict{Result: "failed", Reason: "Cloudflare trace 响应无法识别"}
								} else if parsed, e := netip.ParseAddr(ip); e != nil || !parsed.IsGlobalUnicast() {
									r.Verdict = clientdiag.Verdict{Result: "failed", Reason: "出口 IP 无效"}
								} else {
									r.IP, r.Region = ip, region
								}
							}
						}
					}
					ci, same := forward.snapshot()
					r.Rule, r.Chain = ci.Rule, ci.Chain
					if len(ci.Chain) > 0 {
						r.Node = ci.Chain[len(ci.Chain)-1]
					}
					if !same && p.Kind == "unlock" {
						r.Verdict = clientdiag.Verdict{Result: "unknown", Reason: "[egress] 服务子请求出口不一致，不能合并地区 / 服务证据"}
					}
					if r.Node == "" && r.Result != "failed" {
						r.Verdict = clientdiag.Verdict{Result: "failed", Reason: "未取得真实连接策略链"}
					}
					tr.CloseIdleConnections()
				}
				if item.Err() != nil {
					// Retain the failing subrequest stage and HTTP status.
					r.Result, r.Region = "failed", ""
					if !strings.Contains(r.Reason, "[timeout]") && !strings.Contains(r.Reason, "[canceled]") {
						r.Reason += "；" + diagnosticFailure(item.Err())
					}
				}
				c()
				r.Duration = time.Since(start).Milliseconds()
				if r.Chain == nil {
					r.Chain = []string{}
				}
				jobs[i] = r
			}
		}()
	}
	for i := range jobs {
		indices <- i
	}
	close(indices)
	wg.Wait()
	if ctx.Err() != nil {
		return nil, requestCanceled()
	}
	reply := &diagnosticReply{At: time.Now(), Items: jobs}
	h.diagCacheMu.Lock()
	if h.diagCache == nil {
		h.diagCache = map[string]*diagnosticReply{}
	}
	if err := h.saveDiagnosticCache(p.Kind, reply); err != nil {
		h.diagCacheMu.Unlock()
		return nil, fail("diagnostic_cache_failed", "", "检测结果保存失败，已保留上次结果")
	}
	h.diagCache[p.Kind] = reply
	h.diagCacheMu.Unlock()
	return reply, nil
}
func diagnosticFailure(e error) string { return clientdiag.FailureReason(e) }

// Last explicit results survive application restart without starting any request.
// This private bounded cache contains only the same fields returned to the UI,
// not response pages, account credentials, cookies or arbitrary error text.
// User-added HTTPS URLs retain their exact value as authorized inputs.
func (h *Host) saveDiagnosticCache(kind string, r *diagnosticReply) error {
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	if len(b) > 1<<20 {
		return errors.New("diagnostic cache limit")
	}
	return atomicWrite(filepath.Join(h.workspace, "network-diagnostic-"+kind+".json"), b)
}
func (h *Host) readDiagnosticCache(kind string) *diagnosticReply {
	f, e := os.Open(filepath.Join(h.workspace, "network-diagnostic-"+kind+".json"))
	if e != nil {
		return nil
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil
	}
	var r diagnosticReply
	decoder := json.NewDecoder(io.LimitReader(f, (1<<20)+1))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&r) != nil || r.At.IsZero() || len(r.Items) > 21 {
		return nil
	}
	r = *visibleDiagnosticCache(kind, &r)
	for _, v := range r.Items {
		if kind == "unlock" && (v.Result == "unknown" || v.Result == "challenge") {
			continue
		}
		if v.Result != "unlocked" && v.Result != "blocked" && v.Result != "originals" && v.Result != "failed" && v.Result != "ok" {
			return nil
		}
	}
	return &r
}

// Read-only compatibility: omit removed services without rewriting a cache
// file, reclassifying other rows, changing timestamps or starting any request.
func visibleDiagnosticCache(kind string, r *diagnosticReply) *diagnosticReply {
	if kind != "unlock" || r == nil {
		return r
	}
	for _, row := range r.Items {
		if row.Name == "Claude" || row.Name == "TikTok" || row.Name == "YouTube Premium" {
			out := *r
			out.Items = make([]diagnosticRow, 0, len(r.Items))
			for _, item := range r.Items {
				if item.Name != "Claude" && item.Name != "TikTok" && item.Name != "YouTube Premium" {
					out.Items = append(out.Items, item)
				}
			}
			return &out
		}
	}
	return r
}
