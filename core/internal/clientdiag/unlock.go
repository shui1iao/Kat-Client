// Package clientdiag independently implements bounded anonymous availability
// checks. Anonymous availability is not account, catalogue, DRM or playback access.
// See TESTS.md for observed schemas, service-unlock v0.5.8 criteria and boundaries.
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
	"time"

	xhtml "golang.org/x/net/html"
)

const BodyLimit = 2 << 20
const NetflixBodyLimit = 4 << 20

var ErrBodyLimit = errors.New("diagnostic response body limit")
var Services = []string{"ChatGPT", "Gemini", "Claude", "Google", "YouTube", "Netflix", "Disney+"}

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

var cfChallengeMarkers = []string{
	"cf_chl_opt",
	"_cf_chl",
	"just a moment",
	"cf-browser-verification",
	"enable javascript and cookies to continue",
}

var reChallengeElement = regexp.MustCompile(`(?is)<(?:form|iframe)[^>]*(?:hcaptcha|recaptcha|captcha|challenge-form)`)

func challenge(p Page) bool {
	b := strings.ToLower(p.Body)
	switch p.Status {
	case http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable:
		for _, m := range cfChallengeMarkers {
			if strings.Contains(b, m) {
				return true
			}
		}
	}
	for _, m := range []string{"cf-chl-", "<title>just a moment", "<title>captcha", `<form id="challenge-form"`, "<h1>verify you are human", "<title>verify you are human", "<title>robot check", "<title>unusual traffic"} {
		if strings.Contains(b, m) {
			return true
		}
	}
	// Script configuration mentioning captchaEnabled/recaptchaKey is NOT a challenge.
	return reChallengeElement.MatchString(b)
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

// reGeminiRegion pulls the served country out of the configuration block that
// Google's account bar embeds in its pages (ISO 3166-1 alpha-3).
var reGeminiRegion = regexp.MustCompile(`,\d+,\d+,200,"([A-Z]{3})"`)

// geminiUnsupported are the 7 countries where Google does not offer Gemini
// per service-unlock v0.5.8 internal/access/checks.go.
var geminiUnsupported = map[string]bool{
	"RUS": true,
	"BLR": true,
	"CHN": true,
	"PRK": true,
	"IRN": true,
	"CUB": true,
	"SYR": true,
}

var claudeUnavailableMarkers = []string{
	"app unavailable in region",
	"/app-unavailable-in-region",
	"unfortunately, claude isn't available here.",
	"unfortunately, claude isn’t available here.",
	"unfortunately, claude isn&apos;t available here.",
	"unfortunately, claude isn&#39;t available here.",
}

var (
	reGoogleBlocked    = regexp.MustCompile(`(?i)unusual traffic from|is blocked|unaddressed abuse`)
	reGoogleUnderscore = regexp.MustCompile(`"[a-z]{2}_([A-Z]{2})"`)
	reGoogleDash       = regexp.MustCompile(`"[a-z]{2}-([A-Z]{2})"`)

	reYouTubeCountryKey   = regexp.MustCompile(`"countryCode"\s*:`)
	reYouTubeCountryVal   = regexp.MustCompile(`"countryCode"\s*:\s*"([^"]*)"`)
	reYouTubeContextGLKey = regexp.MustCompile(`"INNERTUBE_CONTEXT_GL"\s*:`)
	reYouTubeContextGLVal = regexp.MustCompile(`"INNERTUBE_CONTEXT_GL"\s*:\s*"([^"]*)"`)

	reHTMLTag = regexp.MustCompile(`(?is)<\s*(?:!doctype\s+html|html|head|body|title|div|h1|h2|p|main|script)\b`)
)

func htmlDocument(body string) bool {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" || trimmed[0] == '{' || trimmed[0] == '[' {
		return false
	}
	return reHTMLTag.MatchString(trimmed)
}

func claudeUnavailable(body string) bool {
	lower := strings.ToLower(body)
	for _, marker := range claudeUnavailableMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func googleSorryRedirect(p Page) bool {
	for _, s := range []string{p.Location, p.URL} {
		u, e := url.Parse(s)
		if e != nil || u.User != nil || (u.Scheme != "" && u.Scheme != "https") {
			continue
		}
		h := strings.ToLower(u.Hostname())
		if h != "" && h != "google.com" && !strings.HasSuffix(h, ".google.com") {
			continue
		}
		path := strings.TrimSuffix(u.Path, "/")
		if path == "/sorry" || strings.HasPrefix(path, "/sorry/") {
			return true
		}
	}
	return false
}

func geminiRegion(body string) (alpha3, region, status string) {
	matches := reGeminiRegion.FindAllStringSubmatch(body, -1)
	if len(matches) == 0 {
		return "", "", "missing"
	}
	for _, m := range matches {
		code := m[1]
		iso2 := iso3Country(code)
		if iso2 == "" {
			return "", "", "conflict"
		}
		if alpha3 != "" && alpha3 != code {
			return "", "", "conflict"
		}
		alpha3 = code
		region = iso2
	}
	return alpha3, region, "ok"
}

func uniqueCountry(matches [][]string) string {
	value := ""
	for _, m := range matches {
		code := knownCountry(m[1])
		if code == "" || (value != "" && code != value) {
			return ""
		}
		value = code
	}
	return value
}

func googlePageRegion(body string) (string, bool) {
	underscore := reGoogleUnderscore.FindAllStringSubmatch(body, -1)
	dash := reGoogleDash.FindAllStringSubmatch(body, -1)
	_, gRegion, gStatus := geminiRegion(body)
	if gStatus == "conflict" {
		return "", false
	}
	if len(underscore) > 0 {
		code := uniqueCountry(underscore)
		if code == "" {
			return "", false
		}
		if len(dash) > 0 && knownCountry(dash[len(dash)-1][1]) != code {
			return "", false
		}
		if gStatus == "ok" && gRegion != code {
			return "", false
		}
		return code, true
	}
	if len(dash) > 0 {
		code := knownCountry(dash[len(dash)-1][1])
		if code == "" {
			return "", false
		}
		if gStatus == "ok" && gRegion != code {
			return "", false
		}
		return code, true
	}
	if gStatus == "ok" {
		return gRegion, true
	}
	return "", true
}

func youtubePageRegion(body string) (string, bool) {
	ccKeys := reYouTubeCountryKey.FindAllStringIndex(body, -1)
	ccVals := reYouTubeCountryVal.FindAllStringSubmatch(body, -1)
	if len(ccKeys) != len(ccVals) {
		return "", false
	}
	glKeys := reYouTubeContextGLKey.FindAllStringIndex(body, -1)
	glVals := reYouTubeContextGLVal.FindAllStringSubmatch(body, -1)
	if len(glKeys) != len(glVals) {
		return "", false
	}
	all := append(append([][]string{}, ccVals...), glVals...)
	if len(all) == 0 {
		return "", true
	}
	code := uniqueCountry(all)
	if code == "" {
		return "", false
	}
	return code, true
}

func traceCountry(body string) (string, error) {
	values := map[string]string{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if _, duplicate := values[k]; duplicate {
			return "", errors.New("duplicate trace field")
		}
		values[k] = v
	}
	if ip, hasIP := values["ip"]; hasIP {
		parsed := net.ParseIP(ip)
		if parsed == nil || !parsed.IsGlobalUnicast() {
			return "", errors.New("invalid trace ip")
		}
	}
	region := knownCountry(values["loc"])
	if region == "" {
		return "", errors.New("invalid trace loc")
	}
	return region, nil
}

// Explicit visible visitor messages on Gemini can also establish a denial or
// unusual-traffic verification. Scripts/templates/hidden text are excluded.
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
	// Best-effort auxiliary region lookup for services whose primary verdict is
	// already decided by the primary response (Claude, Google, YouTube). Never
	// overwrites primary stage/HTTPStatus or exhausts the outer 8-second budget.
	auxFetch := func(u string) (Page, bool) {
		if ctx.Err() != nil {
			return Page{}, false
		}
		budget := 1500 * time.Millisecond
		if deadline, ok := ctx.Deadline(); ok {
			rem := time.Until(deadline)
			if rem < 1500*time.Millisecond {
				return Page{}, false
			}
			if half := rem / 2; half < budget {
				budget = half
			}
		}
		subCtx, cancel := context.WithTimeout(ctx, budget)
		defer cancel()
		p, e := get(subCtx, "GET", u)
		if e != nil || p.Status != http.StatusOK || challenge(p) {
			return Page{}, false
		}
		return p, true
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
		p, e := fetch("Gemini 匿名入口", "https://gemini.google.com/app")
		if e != nil {
			return failed(FailureReason(e))
		}
		denied, verification := geminiPageEvidence(p.Body)
		if challenge(p) || verification {
			return Verdict{Result: "challenge", Reason: "[challenge] 访问验证 / 验证码，匿名可用性未知"}
		}
		if regionRedirect(p, "gemini.google.com") || (p.Status == http.StatusOK && denied) {
			return verdict(false, "", "[region_denied] 官方入口明确表示当前访客地区不可用；不代表账户状态")
		}
		if why := pageFailure(p); why.Result != "" {
			return why
		}
		alpha3, region, regStatus := geminiRegion(p.Body)
		if regStatus == "missing" {
			return unknown("[schema] 页面未包含可识别的官方服务地区配置")
		}
		if regStatus == "conflict" {
			return unknown("[schema] 页面服务地区配置冲突或代码无法识别")
		}
		if geminiUnsupported[alpha3] {
			return verdict(false, region, "[region_denied] 官方页面服务地区属于不支持国家/地区列表；不代表账户状态")
		}
		return verdict(true, region, "[anonymous] 官方入口返回可用服务地区配置；仅代表页面地区准入，未验证登录账户或真实对话能力")
	case "Claude":
		p, e := fetch("Claude 匿名入口", "https://claude.ai/")
		if e != nil {
			return failed(FailureReason(e))
		}
		if challenge(p) {
			return pageFailure(p)
		}
		if regionRedirect(p, "claude.ai") || ((p.Status == http.StatusOK || p.Status == http.StatusForbidden) && claudeUnavailable(p.Body)) {
			return verdict(false, "", "[region_denied] 官方页面明确表示当前地区不可用")
		}
		if p.Status == http.StatusForbidden {
			return unknown("[http] HTTP 403 未包含明确地区拒绝页面，原因未知")
		}
		if why := pageFailure(p); why.Result != "" {
			return why
		}
		if !htmlDocument(p.Body) {
			return unknown("[schema] 响应不是可识别的 Claude 页面结构")
		}
		loc := ""
		if q, ok := auxFetch("https://claude.ai/cdn-cgi/trace"); ok {
			if c, err := traceCountry(q.Body); err == nil {
				loc = c
			}
		}
		return verdict(true, loc, "[anonymous] 官方匿名入口可达且未返回地区拒绝页面；仅代表页面准入，不代表账户或对话状态")
	case "Google":
		p, e := fetch("Google Search 匿名验证码检测", "https://www.google.com/search?q=cats")
		if e != nil {
			return failed(FailureReason(e))
		}
		if challenge(p) {
			return pageFailure(p)
		}
		if (p.Status == http.StatusOK || p.Status == http.StatusForbidden || p.Status == http.StatusTooManyRequests) && (reGoogleBlocked.MatchString(p.Body) || googleSorryRedirect(p)) {
			return verdict(false, "", "[region_denied] Google Search 检测到异常流量验证或滥用拦截；仅代表搜索验证码状态，不代表账户登录能力")
		}
		if p.Status == http.StatusForbidden {
			return unknown("[http] HTTP 403 未包含明确验证码或滥用拦截标记，原因未知")
		}
		if why := pageFailure(p); why.Result != "" {
			return why
		}
		if !htmlDocument(p.Body) {
			return unknown("[schema] 响应不是可识别的 Google Search 页面结构")
		}
		region, ok := googlePageRegion(p.Body)
		if !ok {
			region = ""
		} else if region == "" {
			if q, auxOK := auxFetch("https://www.google.com/"); auxOK {
				if r, rOK := googlePageRegion(q.Body); rOK {
					region = r
				}
			}
		}
		return verdict(true, region, "[anonymous] Google Search 页面正常返回且未触发异常流量验证码；仅代表搜索未受验证码拦截，不代表账户登录能力")
	case "YouTube":
		p, e := fetch("YouTube Premium 匿名报价页", "https://www.youtube.com/premium")
		if e != nil {
			return failed(FailureReason(e))
		}
		if challenge(p) {
			return pageFailure(p)
		}
		region, ok := youtubePageRegion(p.Body)
		if !ok {
			region = ""
		}
		lower := strings.ToLower(p.Body)
		if (p.Status == http.StatusOK || p.Status == http.StatusForbidden) && strings.Contains(lower, "youtube premium is not available in your country") {
			return verdict(false, region, "[region_denied] 官方页面明确表示当前国家/地区未提供 YouTube Premium；仅代表 Premium 开通能力，不代表普通视频访问不可用")
		}
		if why := pageFailure(p); why.Result != "" {
			return why
		}
		hasOffer := strings.Contains(lower, "ad-free") || (strings.Contains(p.Body, "lpOfferCardViewModel") && strings.Contains(p.Body, "SPunlimited") && strings.Contains(p.Body, "/premium"))
		if !hasOffer {
			return unknown("[schema] 页面未包含 YouTube Premium 报价或明确地区拒绝标记")
		}
		if ok && region == "" {
			if q, auxOK := auxFetch("https://www.youtube.com/"); auxOK {
				if r, rOK := youtubePageRegion(q.Body); rOK {
					region = r
				}
			}
		}
		return verdict(true, region, "[anonymous] 官方 YouTube Premium 报价页可用；仅代表 Premium 区域开通能力，不混同 YouTube 普通访问或账户状态")
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

// ISO 3166-1 alpha-3 to canonical alpha-2 country codes (excluding pseudo-codes WW/EU/UK/ZZ).
var iso3To2 = map[string]string{
	"AFG": "AF", "ALA": "AX", "ALB": "AL", "DZA": "DZ", "ASM": "AS", "AND": "AD", "AGO": "AO", "AIA": "AI",
	"ATA": "AQ", "ATG": "AG", "ARG": "AR", "ARM": "AM", "ABW": "AW", "AUS": "AU", "AUT": "AT", "AZE": "AZ",
	"BHS": "BS", "BHR": "BH", "BGD": "BD", "BRB": "BB", "BLR": "BY", "BEL": "BE", "BLZ": "BZ", "BEN": "BJ",
	"BMU": "BM", "BTN": "BT", "BOL": "BO", "BES": "BQ", "BIH": "BA", "BWA": "BW", "BVT": "BV", "BRA": "BR",
	"IOT": "IO", "BRN": "BN", "BGR": "BG", "BFA": "BF", "BDI": "BI", "CPV": "CV", "KHM": "KH", "CMR": "CM",
	"CAN": "CA", "CYM": "KY", "CAF": "CF", "TCD": "TD", "CHL": "CL", "CHN": "CN", "CXR": "CX", "CCK": "CC",
	"COL": "CO", "COM": "KM", "COG": "CG", "COD": "CD", "COK": "CK", "CRI": "CR", "CIV": "CI", "HRV": "HR",
	"CUB": "CU", "CUW": "CW", "CYP": "CY", "CZE": "CZ", "DNK": "DK", "DJI": "DJ", "DMA": "DM", "DOM": "DO",
	"ECU": "EC", "EGY": "EG", "SLV": "SV", "GNQ": "GQ", "ERI": "ER", "EST": "EE", "SWZ": "SZ", "ETH": "ET",
	"FLK": "FK", "FRO": "FO", "FJI": "FJ", "FIN": "FI", "FRA": "FR", "GUF": "GF", "PYF": "PF", "ATF": "TF",
	"GAB": "GA", "GMB": "GM", "GEO": "GE", "DEU": "DE", "GHA": "GH", "GIB": "GI", "GRC": "GR", "GRL": "GL",
	"GRD": "GD", "GLP": "GP", "GUM": "GU", "GTM": "GT", "GGY": "GG", "GIN": "GN", "GNB": "GW", "GUY": "GY",
	"HTI": "HT", "HMD": "HM", "VAT": "VA", "HND": "HN", "HKG": "HK", "HUN": "HU", "ISL": "IS", "IND": "IN",
	"IDN": "ID", "IRN": "IR", "IRQ": "IQ", "IRL": "IE", "IMN": "IM", "ISR": "IL", "ITA": "IT", "JAM": "JM",
	"JPN": "JP", "JEY": "JE", "JOR": "JO", "KAZ": "KZ", "KEN": "KE", "KIR": "KI", "PRK": "KP", "KOR": "KR",
	"KWT": "KW", "KGZ": "KG", "LAO": "LA", "LVA": "LV", "LBN": "LB", "LSO": "LS", "LBR": "LR", "LBY": "LY",
	"LIE": "LI", "LTU": "LT", "LUX": "LU", "MAC": "MO", "MDG": "MG", "MWI": "MW", "MYS": "MY", "MDV": "MV",
	"MLI": "ML", "MLT": "MT", "MHL": "MH", "MTQ": "MQ", "MRT": "MR", "MUS": "MU", "MYT": "YT", "MEX": "MX",
	"FSM": "FM", "MDA": "MD", "MCO": "MC", "MNG": "MN", "MNE": "ME", "MSR": "MS", "MAR": "MA", "MOZ": "MZ",
	"MMR": "MM", "NAM": "NA", "NRU": "NR", "NPL": "NP", "NLD": "NL", "NCL": "NC", "NZL": "NZ", "NIC": "NI",
	"NER": "NE", "NGA": "NG", "NIU": "NU", "NFK": "NF", "MKD": "MK", "MNP": "MP", "NOR": "NO", "OMN": "OM",
	"PAK": "PK", "PLW": "PW", "PSE": "PS", "PAN": "PA", "PNG": "PG", "PRY": "PY", "PER": "PE", "PHL": "PH",
	"PCN": "PN", "POL": "PL", "PRT": "PT", "PRI": "PR", "QAT": "QA", "REU": "RE", "ROU": "RO", "RUS": "RU",
	"RWA": "RW", "BLM": "BL", "SHN": "SH", "KNA": "KN", "LCA": "LC", "MAF": "MF", "SPM": "PM", "VCT": "VC",
	"WSM": "WS", "SMR": "SM", "STP": "ST", "SAU": "SA", "SEN": "SN", "SRB": "RS", "SYC": "SC", "SLE": "SL",
	"SGP": "SG", "SXM": "SX", "SVK": "SK", "SVN": "SI", "SLB": "SB", "SOM": "SO", "ZAF": "ZA", "SGS": "GS",
	"SSD": "SS", "ESP": "ES", "LKA": "LK", "SDN": "SD", "SUR": "SR", "SJM": "SJ", "SWE": "SE", "CHE": "CH",
	"SYR": "SY", "TWN": "TW", "TJK": "TJ", "TZA": "TZ", "THA": "TH", "TLS": "TL", "TGO": "TG", "TKL": "TK",
	"TON": "TO", "TTO": "TT", "TUN": "TN", "TUR": "TR", "TKM": "TM", "TCA": "TC", "TUV": "TV", "UGA": "UG",
	"UKR": "UA", "ARE": "AE", "GBR": "GB", "USA": "US", "UMI": "UM", "URY": "UY", "UZB": "UZ", "VUT": "VU",
	"VEN": "VE", "VNM": "VN", "VGB": "VG", "VIR": "VI", "WLF": "WF", "ESH": "EH", "YEM": "YE", "ZMB": "ZM",
	"ZWE": "ZW", "XKX": "XK",
}

var validISO2 = func() map[string]bool {
	m := make(map[string]bool, len(iso3To2))
	for _, code := range iso3To2 {
		m[code] = true
	}
	return m
}()

func knownCountry(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 || !validISO2[code] {
		return ""
	}
	return code
}

func iso3Country(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 3 {
		return ""
	}
	return iso3To2[code]
}
