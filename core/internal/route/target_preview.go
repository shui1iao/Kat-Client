package route

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

// PreviewTargetInfo describes the normalized target of a target-only preview.
type PreviewTargetInfo struct {
	Input     string   `json:"input"`
	Host      string   `json:"host"`
	Kind      string   `json:"kind"`
	Addresses []string `json:"addresses"`
}

// PreviewMatched describes the winning rule or final fallback.
type PreviewMatched struct {
	Source  string `json:"source"`
	Index   *int   `json:"index"`
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Policy  string `json:"policy"`
}

// TargetPreview is the response payload of routing.previewTarget.
type TargetPreview struct {
	Target   PreviewTargetInfo `json:"target"`
	Matched  PreviewMatched    `json:"matched"`
	Chain    []string          `json:"chain"`
	Resolved bool              `json:"resolved"`
	Scope    string            `json:"scope"`
}

// TargetPreviewError classifies target validation, DNS, and resource errors.
type TargetPreviewError struct {
	Code    string
	Message string
}

func (e *TargetPreviewError) Error() string { return e.Message }

func previewErr(code, message string) error {
	return &TargetPreviewError{Code: code, Message: message}
}

// NewReadOnlyEngine creates an Engine that loads existing local rule-set and
// database snapshots without starting background downloads or dialing.
func NewReadOnlyEngine(o Options) (*Engine, error) {
	noDial := func(string) (DialFunc, error) {
		return func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("route: network dial disabled in target preview")
		}, nil
	}
	return NewEngine(o, noDial, nil)
}

// ParsePreviewTarget validates and normalizes a domain, IPv4/IPv6 literal, or
// HTTP(S) URL target for routing.previewTarget.
func ParsePreviewTarget(raw string) (PreviewTargetInfo, netip.Addr, error) {
	if len(raw) > maxURLLen {
		return PreviewTargetInfo{}, netip.Addr{}, previewErr("invalid_target", "目标地址长度不能超过 2048 字节")
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return PreviewTargetInfo{}, netip.Addr{}, previewErr("invalid_target", "请输入有效的域名、IP 或 HTTP(S) 网址")
	}
	for i := 0; i < len(trimmed); i++ {
		if trimmed[i] <= 0x20 || trimmed[i] == 0x7f {
			return PreviewTargetInfo{}, netip.Addr{}, previewErr("invalid_target", "目标地址包含无效空白或控制字符")
		}
	}
	if ip, err := netip.ParseAddr(trimmed); err == nil {
		if ip.Zone() != "" {
			return PreviewTargetInfo{}, netip.Addr{}, previewErr("invalid_target", "不支持带区域标识的 IP 地址")
		}
		ip = ip.Unmap()
		host := ip.String()
		return PreviewTargetInfo{
			Input:     trimmed,
			Host:      host,
			Kind:      "ip",
			Addresses: []string{host},
		}, ip, nil
	}
	hasScheme := strings.Contains(trimmed, "://")
	address := trimmed
	if !hasScheme {
		if strings.ContainsAny(trimmed, "/?#@\\") {
			return PreviewTargetInfo{}, netip.Addr{}, previewErr("invalid_target", "请输入有效的域名、IP 或完整的 HTTP(S) 网址")
		}
		address = "//" + trimmed
	}
	u, err := url.Parse(address)
	if err != nil || u.Opaque != "" || u.User != nil || u.Host == "" || u.Fragment != "" || strings.Contains(trimmed, "#") || strings.Contains(u.Host, "@") {
		return PreviewTargetInfo{}, netip.Addr{}, previewErr("invalid_target", "请输入不含账号信息或片段的有效地址")
	}
	if hasScheme {
		if u.Scheme != "http" && u.Scheme != "https" {
			return PreviewTargetInfo{}, netip.Addr{}, previewErr("invalid_target", "网址仅支持 HTTP 或 HTTPS 协议")
		}
		prefix := u.Scheme + "://"
		if len(trimmed) <= len(prefix) || strings.HasPrefix(trimmed[len(prefix):], "/") {
			return PreviewTargetInfo{}, netip.Addr{}, previewErr("invalid_target", "请输入包含有效主机名的网址")
		}
	} else if u.Scheme != "" || u.Path != "" || u.RawQuery != "" || u.ForceQuery {
		return PreviewTargetInfo{}, netip.Addr{}, previewErr("invalid_target", "请输入有效的域名、IP 或完整的 HTTP(S) 网址")
	}
	if p := u.Port(); p != "" {
		if _, ok := parsePort(p); !ok {
			return PreviewTargetInfo{}, netip.Addr{}, previewErr("invalid_target", "地址中的端口必须在 1–65535 之间")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return PreviewTargetInfo{}, netip.Addr{}, previewErr("invalid_target", "地址中的端口无效")
	}
	hostname := u.Hostname()
	if hostname == "" {
		return PreviewTargetInfo{}, netip.Addr{}, previewErr("invalid_target", "请输入有效的主机名或 IP 地址")
	}
	if ip, err := netip.ParseAddr(hostname); err == nil {
		if ip.Zone() != "" {
			return PreviewTargetInfo{}, netip.Addr{}, previewErr("invalid_target", "不支持带区域标识的 IP 地址")
		}
		if ip.Is6() && !strings.HasPrefix(u.Host, "[") {
			return PreviewTargetInfo{}, netip.Addr{}, previewErr("invalid_target", "URL 中的 IPv6 地址需使用方括号包裹")
		}
		ip = ip.Unmap()
		host := ip.String()
		return PreviewTargetInfo{
			Input:     trimmed,
			Host:      host,
			Kind:      "ip",
			Addresses: []string{host},
		}, ip, nil
	}
	if strings.ContainsAny(u.Host, "[]") {
		return PreviewTargetInfo{}, netip.Addr{}, previewErr("invalid_target", "无效的 IPv6 字面量或主机名")
	}
	domain, ok := previewDomainName(hostname)
	if !ok {
		return PreviewTargetInfo{}, netip.Addr{}, previewErr("invalid_target", "请输入有效的域名或 IP 地址")
	}
	return PreviewTargetInfo{
		Input:     trimmed,
		Host:      domain,
		Kind:      "domain",
		Addresses: []string{},
	}, netip.Addr{}, nil
}

func previewDomainName(s string) (string, bool) {
	d, ok := normDomain(s)
	if !ok || strings.Contains(d, "_") {
		return "", false
	}
	last := d
	if i := strings.LastIndexByte(d, '.'); i >= 0 {
		last = d[i+1:]
	}
	allDigits := true
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return "", false
	}
	return d, true
}

type targetCond struct {
	kind      condKind
	noResolve bool
	s         string
	re        *regexp.Regexp
	prefix    netip.Prefix
	num       uint32
	set       *ruleSet
	subs      []*targetCond
	inline    *targetSetData
}

type targetSetData struct {
	dom     domainSet
	ip      ipSet
	ipNR    ipSet
	geo     []string
	geoNR   []string
	extra   []*targetCond
	hasCond bool
}

func (s *source) hasLoadedSnapshot() bool {
	if s == nil {
		return false
	}
	s.metaMu.Lock()
	defer s.metaMu.Unlock()
	return s.value != nil
}

func (rs *ruleSet) loadedData() (*setData, bool) {
	if rs == nil {
		return nil, false
	}
	d := rs.data.Load()
	if rs.src != nil {
		if !rs.src.hasLoadedSnapshot() || d == nil {
			return nil, false
		}
		return d, true
	}
	return d, d != nil
}

func (rs *ruleSet) setName() string {
	if rs != nil && rs.src != nil {
		return rs.src.name
	}
	return ""
}

func (e *Engine) hasLoadedGeoIP() bool {
	return e != nil && e.geo != nil && e.geo.db.Load() != nil
}

func (e *Engine) hasLoadedASN() bool {
	return e != nil && e.asn != nil && e.asn.db.Load() != nil
}

func (e *Engine) hasLoadedGeosite() bool {
	return e != nil && e.site != nil && e.site.db.Load() != nil
}

func projectTargetSetData(d *setData) *targetSetData {
	if d == nil {
		return &targetSetData{}
	}
	var extra []*targetCond
	for _, c := range d.extra {
		if pc := projectTargetCond(c); pc != nil {
			extra = append(extra, pc)
		}
	}
	hasCond := !d.dom.empty() || !d.ip.empty() || !d.ipNR.empty() || len(d.geo) > 0 || len(d.geoNR) > 0 || len(extra) > 0
	return &targetSetData{
		dom:     d.dom,
		ip:      d.ip,
		ipNR:    d.ipNR,
		geo:     d.geo,
		geoNR:   d.geoNR,
		extra:   extra,
		hasCond: hasCond,
	}
}

func projectTargetCond(c *cond) *targetCond {
	if c == nil {
		return nil
	}
	switch c.kind {
	case kDomain, kSuffix, kKeyword, kRegex, kWildcard, kGeosite:
		return &targetCond{kind: c.kind, noResolve: c.noResolve, s: c.s, re: c.re}
	case kIPCIDR, kIPSuffix, kIPASN, kGeoIP:
		return &targetCond{kind: c.kind, noResolve: c.noResolve, s: c.s, prefix: c.prefix, num: c.num}
	case kRuleSet:
		if c.set == nil {
			return &targetCond{kind: kRuleSet, noResolve: c.noResolve}
		}
		d, loaded := c.set.loadedData()
		if !loaded {
			// Retain unloaded rule-set node so evaluation reports resource_unavailable
			// if and when this condition is actually reached.
			return &targetCond{kind: kRuleSet, noResolve: c.noResolve, set: c.set, s: c.set.setName()}
		}
		tsd := projectTargetSetData(d)
		if !tsd.hasCond {
			return nil
		}
		return &targetCond{kind: kRuleSet, noResolve: c.noResolve, set: c.set, s: c.set.setName(), inline: tsd}
	case kInline:
		tsd := projectTargetSetData(c.inline)
		if !tsd.hasCond {
			return nil
		}
		return &targetCond{kind: kInline, noResolve: c.noResolve, inline: tsd}
	case kNot:
		if len(c.subs) == 0 {
			return nil
		}
		sub := projectTargetCond(c.subs[0])
		if sub == nil {
			return nil
		}
		return &targetCond{kind: kNot, noResolve: c.noResolve, subs: []*targetCond{sub}}
	case kAnd, kOr:
		var subs []*targetCond
		for _, s := range c.subs {
			if ps := projectTargetCond(s); ps != nil {
				subs = append(subs, ps)
			}
		}
		if len(subs) == 0 {
			return nil
		}
		return &targetCond{kind: c.kind, noResolve: c.noResolve, subs: subs}
	default:
		// Non-target conditions (process_name, src_ip_*, dst_port, src_port,
		// in_port, network, in_name, in_type, protocol) do not participate.
		return nil
	}
}

func resourceUnavailableErr(kind, name string) error {
	switch kind {
	case "rule_set":
		if name != "" {
			return previewErr("resource_unavailable", fmt.Sprintf("规则集 %s 未就绪，无法完成判定", name))
		}
		return previewErr("resource_unavailable", "规则集资源未就绪，无法完成判定")
	case "geoip":
		return previewErr("resource_unavailable", "GeoIP 数据库未就绪，无法完成判定")
	case "geosite":
		return previewErr("resource_unavailable", "Geosite 数据库未就绪，无法完成判定")
	case "asn":
		return previewErr("resource_unavailable", "ASN 数据库未就绪，无法完成判定")
	default:
		return previewErr("resource_unavailable", "规则依赖的资源未就绪，无法完成判定")
	}
}

func (e *Engine) evalTargetPreDNS(tc *targetCond, host string, noResolve bool) (int8, error) {
	noResolve = noResolve || tc.noResolve
	switch tc.kind {
	case kDomain:
		if host != "" && host == tc.s {
			return triTrue, nil
		}
		return triFalse, nil
	case kSuffix:
		if host != "" && suffixMatch(host, tc.s) {
			return triTrue, nil
		}
		return triFalse, nil
	case kKeyword:
		if host != "" && strings.Contains(host, tc.s) {
			return triTrue, nil
		}
		return triFalse, nil
	case kRegex:
		if host != "" && tc.re != nil && tc.re.MatchString(host) {
			return triTrue, nil
		}
		return triFalse, nil
	case kWildcard:
		if host != "" && wildcardMatch(tc.s, host) {
			return triTrue, nil
		}
		return triFalse, nil
	case kGeosite:
		if !e.hasLoadedGeosite() {
			return 0, resourceUnavailableErr("geosite", tc.s)
		}
		if host != "" && e.siteMatch(tc.s, host) {
			return triTrue, nil
		}
		return triFalse, nil
	case kIPCIDR, kIPSuffix:
		if noResolve {
			return triFalse, nil
		}
		return triUnknown, nil
	case kIPASN:
		if noResolve {
			return triFalse, nil
		}
		if !e.hasLoadedASN() {
			return 0, resourceUnavailableErr("asn", "")
		}
		return triUnknown, nil
	case kGeoIP:
		if noResolve {
			return triFalse, nil
		}
		if tc.s != geoPrivate && !e.hasLoadedGeoIP() {
			return 0, resourceUnavailableErr("geoip", tc.s)
		}
		return triUnknown, nil
	case kRuleSet:
		if tc.set == nil || tc.inline == nil {
			return 0, resourceUnavailableErr("rule_set", tc.s)
		}
		return e.evalSetPreDNS(tc.inline, host, noResolve)
	case kInline:
		return e.evalSetPreDNS(tc.inline, host, noResolve)
	case kNot:
		v, err := e.evalTargetPreDNS(tc.subs[0], host, noResolve)
		if err != nil {
			return 0, err
		}
		if v == triUnknown {
			return triUnknown, nil
		}
		return 1 - v, nil
	case kAnd:
		var firstErr error
		unknown := false
		for _, sub := range tc.subs {
			v, err := e.evalTargetPreDNS(sub, host, noResolve)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if v == triFalse {
				return triFalse, nil
			}
			if v == triUnknown {
				unknown = true
			}
		}
		if firstErr != nil {
			return 0, firstErr
		}
		if unknown {
			return triUnknown, nil
		}
		return triTrue, nil
	case kOr:
		var firstErr error
		unknown := false
		for _, sub := range tc.subs {
			v, err := e.evalTargetPreDNS(sub, host, noResolve)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if v == triTrue {
				return triTrue, nil
			}
			if v == triUnknown {
				unknown = true
			}
		}
		if firstErr != nil {
			return 0, firstErr
		}
		if unknown {
			return triUnknown, nil
		}
		return triFalse, nil
	}
	return triFalse, nil
}

func (e *Engine) evalSetPreDNS(d *targetSetData, host string, noResolve bool) (int8, error) {
	if d == nil || !d.hasCond {
		return triFalse, nil
	}
	if d.dom.match(host) {
		return triTrue, nil
	}
	var firstErr error
	unknown := false
	for _, c := range d.extra {
		v, err := e.evalTargetPreDNS(c, host, noResolve)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if v == triTrue {
			return triTrue, nil
		}
		if v == triUnknown {
			unknown = true
		}
	}
	if firstErr != nil {
		return 0, firstErr
	}
	if !noResolve {
		if !d.ip.empty() {
			unknown = true
		}
		for _, code := range d.geo {
			if code != geoPrivate && !e.hasLoadedGeoIP() {
				return 0, resourceUnavailableErr("geoip", code)
			}
			unknown = true
		}
	}
	if unknown {
		return triUnknown, nil
	}
	return triFalse, nil
}

func (e *Engine) evalTargetWithIP(tc *targetCond, host string, x *ipInfo) (bool, error) {
	switch tc.kind {
	case kDomain:
		return host != "" && host == tc.s, nil
	case kSuffix:
		return host != "" && suffixMatch(host, tc.s), nil
	case kKeyword:
		return host != "" && strings.Contains(host, tc.s), nil
	case kRegex:
		return host != "" && tc.re != nil && tc.re.MatchString(host), nil
	case kWildcard:
		return host != "" && wildcardMatch(tc.s, host), nil
	case kGeosite:
		if !e.hasLoadedGeosite() {
			return false, resourceUnavailableErr("geosite", tc.s)
		}
		return host != "" && e.siteMatch(tc.s, host), nil
	case kIPCIDR:
		return x != nil && tc.prefix.Contains(x.ip), nil
	case kIPSuffix:
		return x != nil && ipSuffixMatch(tc.prefix, x.ip), nil
	case kIPASN:
		if x == nil {
			return false, nil
		}
		if !e.hasLoadedASN() {
			return false, resourceUnavailableErr("asn", "")
		}
		return e.asnOf(x) == tc.num, nil
	case kGeoIP:
		if x == nil {
			return false, nil
		}
		if tc.s != geoPrivate && !e.hasLoadedGeoIP() {
			return false, resourceUnavailableErr("geoip", tc.s)
		}
		return e.geoMatch(tc.s, x), nil
	case kRuleSet:
		if tc.set == nil || tc.inline == nil {
			return false, resourceUnavailableErr("rule_set", tc.s)
		}
		return e.evalSetWithIP(tc.inline, host, x)
	case kInline:
		return e.evalSetWithIP(tc.inline, host, x)
	case kNot:
		m, err := e.evalTargetWithIP(tc.subs[0], host, x)
		if err != nil {
			return false, err
		}
		return !m, nil
	case kAnd:
		var firstErr error
		for _, sub := range tc.subs {
			m, err := e.evalTargetWithIP(sub, host, x)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if !m {
				return false, nil
			}
		}
		if firstErr != nil {
			return false, firstErr
		}
		return true, nil
	case kOr:
		var firstErr error
		for _, sub := range tc.subs {
			m, err := e.evalTargetWithIP(sub, host, x)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if m {
				return true, nil
			}
		}
		if firstErr != nil {
			return false, firstErr
		}
		return false, nil
	}
	return false, nil
}

func (e *Engine) evalSetWithIP(d *targetSetData, host string, x *ipInfo) (bool, error) {
	if d == nil || !d.hasCond {
		return false, nil
	}
	if d.dom.match(host) {
		return true, nil
	}
	if x != nil {
		if d.ip.contains(x.ip) || d.ipNR.contains(x.ip) {
			return true, nil
		}
		for _, code := range d.geo {
			if code != geoPrivate && !e.hasLoadedGeoIP() {
				return false, resourceUnavailableErr("geoip", code)
			}
			if e.geoMatch(code, x) {
				return true, nil
			}
		}
		for _, code := range d.geoNR {
			if code != geoPrivate && !e.hasLoadedGeoIP() {
				return false, resourceUnavailableErr("geoip", code)
			}
			if e.geoMatch(code, x) {
				return true, nil
			}
		}
	}
	var firstErr error
	for _, c := range d.extra {
		m, err := e.evalTargetWithIP(c, host, x)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if m {
			return true, nil
		}
	}
	if firstErr != nil {
		return false, firstErr
	}
	return false, nil
}

func describeTargetRule(r *Rule) (string, string) {
	switch {
	case r.Domain != "":
		return "DOMAIN", r.Domain
	case r.DomainSuffix != "":
		return "DOMAIN-SUFFIX", r.DomainSuffix
	case r.DomainKeyword != "":
		return "DOMAIN-KEYWORD", r.DomainKeyword
	case r.DomainRegex != "":
		return "DOMAIN-REGEX", r.DomainRegex
	case r.DomainWildcard != "":
		return "DOMAIN-WILDCARD", r.DomainWildcard
	case r.Geosite != "":
		return "GEOSITE", r.Geosite
	case r.IPCIDR != "":
		return "IP-CIDR", r.IPCIDR
	case r.IPSuffix != "":
		return "IP-SUFFIX", r.IPSuffix
	case r.IPASN != "":
		return "IP-ASN", r.IPASN
	case r.GeoIP != "":
		return "GEOIP", r.GeoIP
	case r.RuleSet != "":
		return "RULE-SET", r.RuleSet
	case r.And != nil:
		return "AND", describeTargetSubList(r.And)
	case r.Or != nil:
		return "OR", describeTargetSubList(r.Or)
	case r.Not != nil:
		t, p := describeTargetRule(r.Not)
		if p != "" {
			return "NOT", t + "," + p
		}
		return "NOT", t
	}
	return "RULE", condString(r)
}

func isTargetSubRule(r *Rule) bool {
	if r == nil {
		return false
	}
	if r.Domain != "" || r.DomainSuffix != "" || r.DomainKeyword != "" || r.DomainRegex != "" || r.DomainWildcard != "" || r.Geosite != "" || r.IPCIDR != "" || r.IPSuffix != "" || r.IPASN != "" || r.GeoIP != "" || r.RuleSet != "" {
		return true
	}
	if r.Not != nil {
		return isTargetSubRule(r.Not)
	}
	for i := range r.And {
		if isTargetSubRule(&r.And[i]) {
			return true
		}
	}
	for i := range r.Or {
		if isTargetSubRule(&r.Or[i]) {
			return true
		}
	}
	return false
}

func describeTargetSubList(subs []Rule) string {
	var parts []string
	for i := range subs {
		if !isTargetSubRule(&subs[i]) {
			continue
		}
		t, p := describeTargetRule(&subs[i])
		if p != "" {
			parts = append(parts, "("+t+","+p+")")
		} else {
			parts = append(parts, "("+t+")")
		}
	}
	return strings.Join(parts, ", ")
}

func buildMatchedRulePreview(target PreviewTargetInfo, index int, r *Rule, resolved bool) TargetPreview {
	typ, payload := describeTargetRule(r)
	policy := ruleTarget(r.Action, r.Outbound)
	idx := index
	return TargetPreview{
		Target: target,
		Matched: PreviewMatched{
			Source:  "rule",
			Index:   &idx,
			Type:    typ,
			Payload: payload,
			Policy:  policy,
		},
		Chain:    []string{policy},
		Resolved: resolved,
		Scope:    "target-only",
	}
}

func buildFinalPreview(target PreviewTargetInfo, final string, resolved bool) TargetPreview {
	if final == "" {
		final = "direct"
	}
	return TargetPreview{
		Target: target,
		Matched: PreviewMatched{
			Source:  "final",
			Index:   nil,
			Type:    "FINAL",
			Payload: "",
			Policy:  final,
		},
		Chain:    []string{final},
		Resolved: resolved,
		Scope:    "target-only",
	}
}

// PreviewTarget evaluates opts against rawTarget using target-only projection
// (domain and destination IP conditions only). Non-target conditions do not
// participate; rules with no target conditions are skipped. DNS is queried at
// most once, only when a domain target reaches an IP condition without no_resolve.
func (e *Engine) PreviewTarget(ctx context.Context, opts Options, rawTarget string, resolve Resolver) (TargetPreview, error) {
	targetInfo, ip, err := ParsePreviewTarget(rawTarget)
	if err != nil {
		return TargetPreview{}, err
	}
	if e == nil {
		return TargetPreview{}, resourceUnavailableErr("engine", "")
	}
	opts.Rules = append([]Rule(nil), opts.Rules...)
	for i := range opts.Rules {
		opts.Rules[i] = cloneRule(opts.Rules[i])
	}
	opts.RuleSets = append([]RuleSetOptions(nil), opts.RuleSets...)
	for _, p := range []**GeoIPOptions{&opts.GeoIP, &opts.Geosite, &opts.ASN} {
		if *p != nil {
			cp := **p
			*p = &cp
		}
	}
	byName := map[string]*ruleSet{}
	e.mu.Lock()
	for _, rs := range e.sets {
		byName[rs.setName()] = rs
	}
	if len(opts.RuleSets) == 0 && len(e.sets) > 0 {
		for _, rs := range e.sets {
			if rs.src != nil {
				opts.RuleSets = append(opts.RuleSets, RuleSetOptions{
					Name:   rs.src.name,
					Format: FormatDomain,
					Path:   rs.src.path,
				})
			}
		}
	}
	if opts.GeoIP == nil && e.geo != nil && e.geo.src != nil {
		opts.GeoIP = &GeoIPOptions{Path: e.geo.src.path}
	}
	if opts.Geosite == nil && e.site != nil && e.site.src != nil {
		opts.Geosite = &GeoIPOptions{Path: e.site.src.path}
	}
	if opts.ASN == nil && e.asn != nil && e.asn.src != nil {
		opts.ASN = &GeoIPOptions{Path: e.asn.src.path}
	}
	e.mu.Unlock()
	if err := opts.Validate(); err != nil {
		return TargetPreview{}, previewErr("invalid_rules", "当前路由规则配置无效")
	}
	for _, rs := range opts.RuleSets {
		if byName[rs.Name] == nil {
			return TargetPreview{}, resourceUnavailableErr("rule_set", rs.Name)
		}
	}
	projected := make([]*targetCond, len(opts.Rules))
	for i := range opts.Rules {
		rawCond := compileRule(&opts.Rules[i], byName)
		projected[i] = projectTargetCond(rawCond)
	}
	if targetInfo.Kind == "ip" {
		info := ipInfo{ip: ip}
		for i := range opts.Rules {
			if projected[i] == nil {
				continue
			}
			matched, err := e.evalTargetWithIP(projected[i], "", &info)
			if err != nil {
				return TargetPreview{}, err
			}
			if matched {
				return buildMatchedRulePreview(targetInfo, i+1, &opts.Rules[i], false), nil
			}
		}
		return buildFinalPreview(targetInfo, opts.Final, false), nil
	}
	host := targetInfo.Host
	resolved := false
	var infos []ipInfo
	for i := range opts.Rules {
		tc := projected[i]
		if tc == nil {
			continue
		}
		if !resolved {
			tri, err := e.evalTargetPreDNS(tc, host, false)
			if err != nil {
				return TargetPreview{}, err
			}
			if tri == triTrue {
				return buildMatchedRulePreview(targetInfo, i+1, &opts.Rules[i], false), nil
			}
			if tri == triFalse {
				continue
			}
			ips, err := e.lookup(ctx, resolve, host)
			if err != nil {
				return TargetPreview{}, previewErr("dns_failed", "DNS 解析失败，无法评估后续 IP 规则")
			}
			ips = dedupe(ips)
			resolved = true
			addrs := make([]string, len(ips))
			infos = make([]ipInfo, len(ips))
			for k, addr := range ips {
				addrs[k] = addr.String()
				infos[k] = ipInfo{ip: addr}
			}
			targetInfo.Addresses = addrs
		}
		for k := range infos {
			matched, err := e.evalTargetWithIP(tc, host, &infos[k])
			if err != nil {
				return TargetPreview{}, err
			}
			if matched {
				return buildMatchedRulePreview(targetInfo, i+1, &opts.Rules[i], true), nil
			}
		}
	}
	return buildFinalPreview(targetInfo, opts.Final, resolved), nil
}
