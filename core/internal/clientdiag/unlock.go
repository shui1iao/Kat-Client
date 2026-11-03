// Package clientdiag independently implements bounded anonymous availability
// checks. Anonymous availability is not account, catalogue, DRM or playback access.
// See TESTS.md for observed schemas, unsupported positives and the Verge comparison.
package clientdiag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	xhtml "golang.org/x/net/html"
)

const BodyLimit = 2 << 20
const NetflixBodyLimit = 4 << 20

var ErrBodyLimit = errors.New("diagnostic response body limit")
var Services = []string{"ChatGPT", "Gemini", "Netflix", "Disney+"}

// ResponseLimit applies only to a named unlock job, not to arbitrary user URLs.
func ResponseLimit(service string) int {
	if service == "Netflix" {
		return NetflixBodyLimit
	}
	return BodyLimit
}

type Page struct {
	Status        int
	Body          string
	URL, Location string
}
type Fetch func(context.Context, string, string) (Page, error)
type Verdict struct {
	Result string `json:"result"`
	Region string `json:"region,omitempty"`
	Reason string `json:"reason,omitempty"`
	// The host copies this into the existing diagnosticRow.http_status field.
	// No response body, URL or raw error is part of the public/cache contract.
	HTTPStatus int `json:"-"`
}

func failed(why string) Verdict  { return Verdict{Result: "failed", Reason: why} }
func unknown(why string) Verdict { return Verdict{Result: "unknown", Reason: why} }
func verdict(ok bool, region, why string) Verdict {
	if !ok {
		return Verdict{Result: "blocked", Region: region, Reason: why}
	}
	return Verdict{Result: "unlocked", Region: region, Reason: why}
}

// FailureReason deliberately maps errors to fixed safe categories. In particular,
// a SOCKS failure does not tell us whether an upstream resolver failed.
func FailureReason(err error) string {
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var record tls.RecordHeaderError
	var timeout net.Error
	var op *net.OpError
	switch {
	case errors.Is(err, context.Canceled):
		return "[canceled] 检测已取消"
	case errors.Is(err, ErrBodyLimit):
		return "[body_limit] 响应超过该服务读取上限"
	case errors.Is(err, context.DeadlineExceeded):
		return "[timeout] 请求超时"
	case errors.As(err, &dns):
		return "[dns] 本次可确认的 DNS 解析失败"
	case errors.As(err, &cert), errors.As(err, &authority), errors.As(err, &hostname), errors.As(err, &invalid), errors.As(err, &record):
		return "[tls] TLS 验证或握手失败"
	case errors.As(err, &timeout) && timeout.Timeout():
		return "[timeout] 请求超时"
	case errors.As(err, &op):
		return "[connection] 本地入口 / SOCKS / 连接失败，远端原因未知"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		return "[io] 响应连接提前结束"
	default:
		return "[request] TLS / HTTP / SOCKS 请求失败，具体原因未知"
	}
}

func challenge(p Page) bool {
	b := strings.ToLower(p.Body)
	for _, m := range []string{"cf-chl-", "<title>just a moment", "<title>captcha", `<form id="challenge-form"`, "<h1>verify you are human", "<title>verify you are human", "<title>robot check", "<title>unusual traffic"} {
		if strings.Contains(b, m) {
			return true
		}
	}
	// Script configuration mentioning captchaEnabled/recaptchaKey is NOT a challenge.
	return regexp.MustCompile(`(?is)<(?:form|iframe)[^>]*(?:hcaptcha|recaptcha|captcha|challenge-form)`).MatchString(b)
}

// A completed HTTP response is not a transport failure. Neither generic HTTP
// denial nor a challenge proves a regional block or anonymous availability.
func pageFailure(p Page) Verdict {
	if challenge(p) {
		return Verdict{Result: "challenge", Reason: "[challenge] 访问验证 / 验证码，匿名可用性未知"}
	}
	if p.Status != http.StatusOK {
		return unknown(fmt.Sprintf("[http] HTTP %d，未取得匿名可用性证据", p.Status))
	}
	return Verdict{}
}
func regionRedirect(p Page, service string) bool {
	if p.Status < 200 || p.Status >= 400 {
		return false
	}
	for _, s := range []string{p.Location, p.URL} {
		u, e := url.Parse(s)
		if e != nil || u.User != nil || (u.Scheme != "" && u.Scheme != "https") {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if h != "" && h != service && !strings.HasSuffix(h, "."+service) {
			continue
		}
		switch strings.TrimSuffix(u.Path, "/") {
		case "/app-unavailable-in-region", "/welcome/unavailable", "/unavailable":
			return true
		}
	}
	return false
}

// Google publishes account-dependent availability, not an anonymous acceptance
// API contract. Do not infer availability from a country code, app-shell flags,
// HTTP 200, or a sign-in control. Only explicit visible visitor messages can
// establish a denial/challenge. Scripts/templates/hidden text are not messages.
func geminiPageEvidence(body string) (denied, verification bool) {
	doc, err := xhtml.Parse(strings.NewReader(body))
	if err != nil {
		return false, false
	}
	excluded := func(n *xhtml.Node) bool {
		if n.Type != xhtml.ElementNode {
			return false
		}
		switch n.Data {
		case "script", "style", "template", "noscript":
			return true
		}
		for _, a := range n.Attr {
			if a.Key == "hidden" || (a.Key == "aria-hidden" && a.Val == "true") {
				return true
			}
		}
		return false
	}
	var text func(*xhtml.Node) string
	text = func(n *xhtml.Node) string {
		if excluded(n) {
			return ""
		}
		if n.Type == xhtml.TextNode {
			return n.Data
		}
		var b strings.Builder
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			b.WriteString(text(c))
			b.WriteByte(' ')
		}
		return b.String()
	}
	var visit func(*xhtml.Node)
	visit = func(n *xhtml.Node) {
		if excluded(n) {
			return
		}
		if n.Type == xhtml.ElementNode {
			switch n.Data {
			case "h1", "h2", "h3", "p":
				label := strings.ToLower(strings.Join(strings.Fields(text(n)), " "))
				label = strings.ReplaceAll(label, "’", "'")
				label = strings.TrimSuffix(label, ".")
				switch label {
				case "gemini isn't available in your country", "gemini isn't available in your country yet",
					"gemini is not available in your country", "gemini is not available in your region",
					"gemini isn't currently supported in your country. stay tuned!":
					denied = true
				}
				if strings.HasPrefix(label, "our systems have detected unusual traffic from your computer network") {
					verification = true
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	visit(doc)
	return denied, verification
}

// Detect's entire sequence shares the host's eight-second context. Specific
// transport/challenge/HTTP failures precede semantic positives. Explicit regional
// denials are never inferred from generic 403, trace location or absent keywords.
func Detect(ctx context.Context, name string, get Fetch) (v Verdict) {
	stage := "服务请求"
	status := 0
	fetch := func(label, u string) (Page, error) {
		stage = label
		p, e := get(ctx, "GET", u)
		status = p.Status
		return p, e
	}
	defer func() {
		v.HTTPStatus = status
		if ctx.Err() != nil {
			v.Result = "failed"
			v.Region = ""
			v.Reason = FailureReason(ctx.Err())
		}
		if v.Reason != "" {
			v.Reason = stage + "：" + v.Reason
		}
	}()
	switch name {
	case "ChatGPT":
		// Observed official anonymous compliance error (2026-11-02). Unlike Verge,
		// arbitrary text/200/absence of unsupported_country is NOT a positive.
		p, e := fetch("ChatGPT 匿名地区合规", "https://api.openai.com/compliance/cookie_requirements")
		if e != nil {
			return failed(FailureReason(e))
		}
		if challenge(p) {
			return pageFailure(p)
		}
		var data struct {
			Error           json.RawMessage `json:"error"`
			ConsentRequired json.RawMessage `json:"cookie_consent_required"`
			RequiresConsent json.RawMessage `json:"requires_cookie_consent"`
		}
		if json.Unmarshal([]byte(p.Body), &data) != nil {
			if why := pageFailure(p); why.Result != "" {
				return why
			}
			return unknown("[schema] 合规响应不是可识别的官方 JSON")
		}
		var denial struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(data.Error, &denial)
		if (p.Status == 400 || p.Status == 403) && (denial.Code == "unsupported_country" || denial.Code == "unsupported_country_region_territory") {
			return verdict(false, "", "[region_denied] 官方合规接口明确拒绝当前地区；不代表账户状态")
		}
		if why := pageFailure(p); why.Result != "" {
			return why
		}
		if len(data.Error) > 0 && strings.TrimSpace(string(data.Error)) != "null" {
			return unknown("[policy_error] 官方合规响应包含未识别的错误结构")
		}
		// The captured official response uses cookie_consent_required, not
		// the reversed legacy field. Retain that legacy typed shape, but never
		// allow contradictory/invalid policy fields to hide an unknown error.
		var policy *bool
		for _, raw := range []json.RawMessage{data.ConsentRequired, data.RequiresConsent} {
			if len(raw) == 0 || strings.TrimSpace(string(raw)) == "null" {
				continue
			}
			var value bool
			if json.Unmarshal(raw, &value) != nil {
				return unknown("[policy] 匿名政策字段不是可识别的布尔值")
			}
			if policy != nil && *policy != value {
				return unknown("[policy] 匿名政策字段相互冲突")
			}
			policy = &value
		}
		if policy == nil {
			return unknown("[policy] 官方合规响应缺少匿名政策字段")
		}
		// This is anonymous regional/service acceptance, not a complete Web
		// session. A typed successful official compliance response plus the
		// service's own valid trace is sufficient for that bounded definition.
		// Consent required=true is a policy choice, not a regional denial.
		q, e := fetch("ChatGPT 辅助地区 trace", "https://chat.openai.com/cdn-cgi/trace")
		if e != nil {
			return failed(FailureReason(e))
		}
		if why := pageFailure(q); why.Result != "" {
			return why
		}
		_, loc, e := Trace(q.Body)
		if e != nil {
			return unknown("[schema] 官方 trace 地区无法识别")
		}
		return verdict(true, loc, "[anonymous] 官方匿名合规接口返回明确政策结构且服务 trace 可用；不保证账户 / 完整 Web 流程")
	case "Gemini":
		p, e := fetch("Gemini 匿名入口", "https://gemini.google.com/app?hl=en")
		if e != nil {
			return failed(FailureReason(e))
		}
		denied, verification := geminiPageEvidence(p.Body)
		if challenge(p) || verification {
			return Verdict{Result: "challenge", Reason: "[challenge] 访问验证 / 验证码，匿名可用性未知"}
		}
		if why := pageFailure(p); why.Result != "" {
			return why
		}
		if denied {
			return verdict(false, "", "[region_denied] 官方入口明确表示当前访客地区不可用；不代表账户状态")
		}
		// Observed 2026-11-03: the public app GET returns a JS shell with a
		// sign-in control, not a documented regional/service acceptance result.
		// The common ,2,1,200, country marker / blocklist complement is not a
		// capability signal. Anonymous features exist, but require more evidence
		// than this bounded, credential-free GET can establish.
		return unknown("[anonymous_evidence] 已取得入口响应，但未取得可确认的 Gemini 匿名功能 / 地区接受证据；登录页、应用壳或地区码不代表已解锁")
	case "Netflix":
		p, e := fetch("Netflix 匿名地区元数据", "https://www.netflix.com/title/80057281")
		if e != nil {
			return failed(FailureReason(e))
		}
		if why := pageFailure(p); why.Result != "" {
			return why
		}
		f, ok := netflixFacts(p, 80057281)
		if !ok {
			return unknown("[schema] 请求地区或对应标题身份元数据不完整")
		}
		if f.Status == "DENY" {
			return verdict(false, f.Region, "[region_denied] 官方 requestCountry 明确拒绝当前地区")
		}
		// The user chose anonymous regional/service availability, not licensed-title
		// catalogue or playback. A particular licensed title must not gate ALLOW.
		return verdict(true, f.Region, "[anonymous] 官方请求地区 ALLOW 且返回对应标题元数据；不保证片库 / 账户 / 播放")
	case "Disney+":
		p, e := fetch("Disney+ 匿名地区产品页", "https://www.disneyplus.com/")
		if e != nil {
			return failed(FailureReason(e))
		}
		if challenge(p) {
			return pageFailure(p)
		}
		if regionRedirect(p, "disneyplus.com") {
			return verdict(false, "", "[region_denied] 官方页面明确表示当前地区不可用")
		}
		if why := pageFailure(p); why.Result != "" {
			return why
		}
		var props struct {
			Location   string `json:"location"`
			HasContent bool   `json:"hasContent"`
			Countries  map[string]struct {
				Commerce struct {
					Products map[string]struct {
						SKUs []string `json:"skuList"`
					} `json:"defaultProduct"`
				} `json:"commerce"`
			} `json:"countriesConfig"`
		}
		if decodeAssignment(p.Body, "window.langRegionRedirectProps = ", &props) == nil && iso(props.Location) {
			if c, ok := props.Countries[props.Location]; ok && props.HasContent && len(c.Commerce.Products["NU"].SKUs) > 0 {
				return verdict(true, props.Location, "[anonymous] 当前访客地区存在公开产品 SKU；不保证账户 / 播放")
			}
		}
		return unknown("[schema] 当前访客地区没有可确认的公开产品证据")
	default:
		return failed("[unsupported] 不支持的服务")
	}
}

// Same-host HTTPS only; Location can be classified without visiting another host.
func Redirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.Host != via[0].URL.Host || req.URL.User != nil {
		return http.ErrUseLastResponse
	}
	req.Header.Del("Cookie")
	return nil
}
func ValidURL(s string) bool {
	u, e := url.Parse(s)
	return e == nil && len(s) <= 2048 && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && u.Opaque == "" && !strings.ContainsAny(s, "\r\n\x00")
}
func Trace(body string) (string, string, error) {
	values := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			if _, duplicate := values[k]; duplicate {
				return "", "", errors.New("duplicate trace field")
			}
			values[k] = v
		}
	}
	ip, region := values["ip"], values["loc"]
	parsed := net.ParseIP(ip)
	if parsed == nil || !parsed.IsGlobalUnicast() || !iso(region) {
		return "", "", errors.New("invalid trace")
	}
	return ip, region, nil
}
func iso(s string) bool {
	return len(s) == 2 && s[0] >= 'A' && s[0] <= 'Z' && s[1] >= 'A' && s[1] <= 'Z'
}

// Decode data only, never execute vendor JavaScript.
func decodeAssignment(body, marker string, v any) error {
	_, raw, ok := strings.Cut(body, marker)
	if !ok {
		return errors.New("missing page data")
	}
	raw = regexp.MustCompile(`\\x([0-9a-fA-F]{2})`).ReplaceAllString(raw, `\u00$1`)
	return json.NewDecoder(strings.NewReader(raw)).Decode(v)
}

type netflixFact struct {
	Region, Status      string
	Available, Original bool
}

func netflixFacts(p Page, title int) (netflixFact, bool) {
	var data struct {
		Models struct {
			Geo struct {
				Data struct {
					Country struct {
						ID     string `json:"id"`
						Status string `json:"status"`
					} `json:"requestCountry"`
				} `json:"data"`
			} `json:"geo"`
			Title struct {
				Data struct {
					Meta struct {
						Available *bool `json:"isAvailable"`
						Original  *bool `json:"isOriginal"`
						ID        int   `json:"videoId"`
					} `json:"metaData"`
				} `json:"data"`
			} `json:"nmTitleGQL"`
		} `json:"models"`
	}
	if decodeAssignment(p.Body, "netflix.reactContext = ", &data) != nil {
		return netflixFact{}, false
	}
	m, c := data.Models.Title.Data.Meta, data.Models.Geo.Data.Country
	if m.Available == nil || m.Original == nil || m.ID != title || !iso(c.ID) || (c.Status != "ALLOW" && c.Status != "DENY") {
		return netflixFact{}, false
	}
	return netflixFact{Region: c.ID, Status: c.Status, Available: *m.Available, Original: *m.Original}, true
}
