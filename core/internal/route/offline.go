package route

// Offline matching borrows immutable resource snapshots. It never resolves,
// opens a resource, attributes a process, selects an outbound or counts traffic.
import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type OfflineInput struct {
	Target      string  `json:"target"`
	Network     string  `json:"network,omitempty"`
	TargetPort  *uint16 `json:"target_port,omitempty"`
	ProcessName string  `json:"process_name,omitempty"`
	SourceIP    string  `json:"source_ip,omitempty"`
	SourcePort  *uint16 `json:"source_port,omitempty"`
	InboundName string  `json:"inbound_name,omitempty"`
	InboundType string  `json:"inbound_type,omitempty"`
	InboundPort *uint16 `json:"inbound_port,omitempty"`
	Protocol    string  `json:"protocol,omitempty"`
}

type OfflineInputError struct{ Field, Message string }

func (e *OfflineInputError) Error() string       { return e.Message }
func offlineInvalid(field, message string) error { return &OfflineInputError{field, message} }

type OfflineKnown struct {
	Host        string `json:"host,omitempty"`
	IP          string `json:"ip,omitempty"`
	Port        uint16 `json:"port,omitempty"`
	PortSource  string `json:"port_source"`
	Network     string `json:"network,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	SourceIP    string `json:"source_ip,omitempty"`
	SourcePort  uint16 `json:"source_port,omitempty"`
	InboundName string `json:"inbound_name,omitempty"`
	InboundType string `json:"inbound_type,omitempty"`
	InboundPort uint16 `json:"inbound_port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
}

type OfflineResource struct {
	Kind          string `json:"kind"`
	Name          string `json:"name"`
	DataAvailable *bool  `json:"data_available"`
	State         string `json:"state,omitempty"`
	Code          string `json:"code,omitempty"`
	Entries       *int   `json:"entries,omitempty"`
	Warning       string `json:"warning,omitempty"`
}

type OfflineResult struct {
	Status               string                   `json:"status"`
	Target               string                   `json:"target"`
	Known                OfflineKnown             `json:"known"`
	Rule                 int                      `json:"rule"`
	DisplayRow           int                      `json:"display_row"`
	Condition            string                   `json:"condition"`
	Policy               string                   `json:"policy"`
	Reason               string                   `json:"reason,omitempty"`
	RuleSet              string                   `json:"rule_set,omitempty"`
	Missing              []string                 `json:"missing"`
	BlockedRule          int                      `json:"blocked_rule,omitempty"`
	CandidatePolicy      string                   `json:"candidate_policy,omitempty"`
	Resources            []OfflineResource        `json:"resources"`
	ResourcesMore        int                      `json:"resources_more,omitempty"`
	ResourceWarnings     []OfflineResource        `json:"resource_warnings"`
	ResourceWarningsMore int                      `json:"resource_warnings_more,omitempty"`
	AdmissionWarnings    []string                 `json:"admission_warnings,omitempty"`
	ConditionalAfter     *OfflineConditionalAfter `json:"conditional_after,omitempty"`
}

// A single explicit counterfactual, never a second asserted routing result.
// This type deliberately cannot contain another conditional_after.
type OfflineAssumption struct {
	Rule      int    `json:"rule"`
	RuleSet   string `json:"rule_set,omitempty"`
	Condition string `json:"condition"`
	Matches   bool   `json:"matches"`
}
type OfflineConditionalAfter struct {
	Assumption           OfflineAssumption `json:"assumption"`
	Status               string            `json:"status"`
	Rule                 int               `json:"rule"`
	DisplayRow           int               `json:"display_row"`
	Condition            string            `json:"condition"`
	Policy               string            `json:"policy"`
	RuleSet              string            `json:"rule_set,omitempty"`
	Missing              []string          `json:"missing"`
	BlockedRule          int               `json:"blocked_rule,omitempty"`
	CandidatePolicy      string            `json:"candidate_policy,omitempty"`
	Resources            []OfflineResource `json:"resources"`
	ResourcesMore        int               `json:"resources_more,omitempty"`
	ResourceWarnings     []OfflineResource `json:"resource_warnings"`
	ResourceWarningsMore int               `json:"resource_warnings_more,omitempty"`
}

// Rules may retain their existing domain syntax. A target must instead obey
// the current kernel dnsName admission (ASCII LDH labels, no underscore).
func offlineDomain(host string) (string, bool) {
	h, ok := normDomain(host)
	return h, ok && !strings.Contains(h, "_")
}
func parseOfflineTarget(input string) (Metadata, string, error) {
	var m Metadata
	if len(input) > 2048 {
		return m, "", offlineInvalid("target", "目标地址不能超过 2048 字节")
	}
	input = strings.TrimSpace(input)
	if input == "" || strings.ContainsAny(input, "\r\n\t") {
		return m, "", offlineInvalid("target", "请填写有效的 URL、域名或 IP")
	}
	if ip, e := netip.ParseAddr(input); e == nil {
		if ip.Zone() != "" {
			return m, "", offlineInvalid("target", "不支持带区域标识的 IP")
		}
		m.IP = ip.Unmap()
		return m, "unspecified", nil
	}
	address := input
	if !strings.Contains(input, "://") {
		address = "//" + input
	}
	u, e := url.Parse(address)
	if e != nil || u.User != nil || u.Host == "" || u.Fragment != "" {
		return m, "", offlineInvalid("target", "请填写不含账号或片段的有效地址")
	}
	if u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" {
		return m, "", offlineInvalid("target", "URL 仅支持 HTTP 或 HTTPS")
	}
	if u.Scheme == "" && (u.Path != "" || u.RawQuery != "") {
		return m, "", offlineInvalid("target", "含路径的地址请填写完整 URL")
	}
	source := "unspecified"
	if p := u.Port(); p != "" {
		v, e := strconv.ParseUint(p, 10, 16)
		if e != nil || v == 0 {
			return m, "", offlineInvalid("target", "地址中的端口应为 1–65535")
		}
		m.Port = uint16(v)
		source = "url_explicit"
	} else if strings.HasSuffix(u.Host, ":") {
		return m, "", offlineInvalid("target", "请填写有效端口")
	} else if u.Scheme == "http" {
		m.Port = 80
		source = "url_default"
	} else if u.Scheme == "https" {
		m.Port = 443
		source = "url_default"
	}
	host := u.Hostname()
	if ip, e := netip.ParseAddr(host); e == nil {
		if ip.Zone() != "" {
			return m, "", offlineInvalid("target", "不支持带区域标识的 IP")
		}
		m.IP = ip.Unmap()
	} else {
		h, ok := offlineDomain(host)
		if !ok || strings.HasPrefix(u.Host, "[") {
			return m, "", offlineInvalid("target", "目标域名需符合当前内核的字母、数字和连字符规则")
		}
		m.Host = h
	}
	return m, source, nil
}
func offlineTarget(input string) (Metadata, error) { m, _, e := parseOfflineTarget(input); return m, e }

func offlineMetadata(in OfflineInput) (Metadata, OfflineKnown, error) {
	m, source, err := parseOfflineTarget(in.Target)
	known := OfflineKnown{}
	if err != nil {
		return m, known, err
	}
	ports := []struct {
		name  string
		value *uint16
		dst   *uint16
	}{{"target_port", in.TargetPort, &m.Port}, {"source_port", in.SourcePort, &m.SrcPort}, {"inbound_port", in.InboundPort, &m.InPort}}
	for _, p := range ports {
		if p.value == nil {
			continue
		}
		if *p.value == 0 {
			return m, known, offlineInvalid(p.name, "端口应为 1–65535")
		}
		if p.name == "target_port" && m.Port != 0 && m.Port != *p.value {
			return m, known, offlineInvalid(p.name, "补充端口与目标地址中的显式或默认端口冲突")
		}
		if p.name == "target_port" && m.Port == 0 {
			source = "manual"
		}
		*p.dst = *p.value
	}
	if in.Network != "" {
		m.Network = strings.ToLower(in.Network)
		if m.Network != "tcp" && m.Network != "udp" {
			return m, known, offlineInvalid("network", "传输协议只能为 TCP 或 UDP")
		}
	}
	if in.ProcessName != "" {
		n, ok := normProcessName(in.ProcessName)
		if !ok {
			return m, known, offlineInvalid("process_name", "请填写有效进程文件名，不含路径")
		}
		m.ProcessName = n
		m.ProcessStatus = "known"
	}
	if in.SourceIP != "" {
		ip, e := netip.ParseAddr(in.SourceIP)
		if e != nil || ip.Zone() != "" {
			return m, known, offlineInvalid("source_ip", "来源 IP 必须是无区域标识的 IP 字面量")
		}
		m.Source = ip.Unmap()
	}
	if in.InboundName != "" {
		if !validName(in.InboundName) {
			return m, known, offlineInvalid("inbound_name", "入站名称应为 1–64 字节且不含空白")
		}
		m.InName = in.InboundName
	}
	if in.InboundType != "" {
		n, ok := normInType(in.InboundType)
		if !ok {
			return m, known, offlineInvalid("inbound_type", "入站类型不在当前内核支持范围内")
		}
		m.InType = n
	}
	if in.Protocol != "" {
		m.Protocol = strings.ToLower(in.Protocol)
		if m.Protocol != "http" && m.Protocol != "tls" && m.Protocol != "quic" {
			return m, known, offlineInvalid("protocol", "嗅探协议只能为 HTTP、TLS 或 QUIC")
		}
	}
	known = OfflineKnown{Host: m.Host, Port: m.Port, PortSource: source, Network: m.Network, ProcessName: m.ProcessName, SourcePort: m.SrcPort, InboundName: m.InName, InboundType: m.InType, InboundPort: m.InPort, Protocol: m.Protocol}
	if m.IP.IsValid() {
		known.IP = m.IP.String()
	}
	if m.Source.IsValid() {
		known.SourceIP = m.Source.String()
	}
	return m, known, nil
}

// Snapshot metadata under the same engine publication lock as its data pointer.
// source.value, not entry count or refresh status, identifies an active load.
func offlineResource(s *source, kind, name string, data any) OfflineResource {
	r := OfflineResource{Kind: kind, Name: name, Warning: "state_unavailable"}
	if s == nil {
		return r
	}
	s.metaMu.Lock()
	defer s.metaMu.Unlock()
	available := false
	if s.value != nil {
		// Every resource value is one of these immutable pointer types.
		switch v := s.value.(type) {
		case *setData:
			p, ok := data.(*setData)
			if !ok || p != v {
				return r
			}
		case *geoDB:
			p, ok := data.(*geoDB)
			if !ok || p != v {
				return r
			}
		case *asnDB:
			p, ok := data.(*asnDB)
			if !ok || p != v {
				return r
			}
		case *siteDB:
			p, ok := data.(*siteDB)
			if !ok || p != v {
				return r
			}
		default:
			return r
		}
		available = true
	}
	r.DataAvailable = &available
	r.State = s.metadata.State
	r.Code = s.metadata.Code
	if r.State == "" {
		r.State = "pending"
	}
	if s.metadata.Entries != nil {
		v := *s.metadata.Entries
		r.Entries = &v
	}
	r.Warning = ""
	if !available {
		r.Warning = "not_loaded"
	} else if r.State == "error" || r.State == "missing" {
		r.Warning = "refresh_failed_using_loaded"
	}
	return r
}

type offlineEvaluation struct {
	engine    *Engine
	resources map[string]OfflineResource
	used      map[string]bool
	order     []string
}

func (v *offlineEvaluation) use(kind, name string) {
	key := kind + ":" + name
	if !v.used[key] {
		v.used[key] = true
		v.order = append(v.order, key)
	}
}
func (v *offlineEvaluation) finish(out *OfflineResult) {
	for _, key := range v.order {
		r, ok := v.resources[key]
		if !ok {
			continue
		}
		if len(out.Resources) < 16 {
			out.Resources = append(out.Resources, r)
		} else {
			out.ResourcesMore++
		}
		if r.Warning != "" {
			if len(out.ResourceWarnings) < 8 {
				out.ResourceWarnings = append(out.ResourceWarnings, r)
			} else {
				out.ResourceWarningsMore++
			}
		}
	}
}

func (e *Engine) Offline(options Options, input string) (OfflineResult, error) {
	return e.OfflineWithContext(options, OfflineInput{Target: input})
}
func (e *Engine) OfflineWithContext(options Options, in OfflineInput) (out OfflineResult, err error) {
	out = OfflineResult{Target: in.Target, Missing: []string{}, Resources: []OfflineResource{}, ResourceWarnings: []OfflineResource{}}
	m, known, err := offlineMetadata(in)
	if err != nil {
		return out, err
	}
	out.Known = known
	options, v, conditions, err := e.offlineRules(options, false)
	if err != nil {
		return out, err
	}
	seed := out
	out = v.evaluateFrom(options, conditions, m, 0, seed)
	v.finish(&out)
	if out.Status == "unknown" {
		// Assumption is that the ENTIRE blocked top-level rule is false; it is
		// not a guess about any process atom, NOT, OR or ruleset child.
		branch := &offlineEvaluation{engine: v.engine, resources: v.resources, used: map[string]bool{}}
		after := branch.evaluateFrom(options, conditions, m, out.BlockedRule, seed)
		branch.finish(&after)
		out.ConditionalAfter = &OfflineConditionalAfter{
			Assumption: OfflineAssumption{Rule: out.BlockedRule, RuleSet: out.RuleSet, Condition: out.Condition, Matches: false},
			Status:     after.Status, Rule: after.Rule, DisplayRow: after.DisplayRow,
			Condition: after.Condition, Policy: after.Policy, RuleSet: after.RuleSet,
			Missing: after.Missing, BlockedRule: after.BlockedRule, CandidatePolicy: after.CandidatePolicy,
			Resources: after.Resources, ResourcesMore: after.ResourcesMore,
			ResourceWarnings: after.ResourceWarnings, ResourceWarningsMore: after.ResourceWarningsMore,
		}
	}
	return out, nil
}

// freezeOffline captures data and availability once under the original
// publication lock. Both evaluations borrow this exact immutable snapshot.
func (e *Engine) freezeOffline() (*offlineEvaluation, map[string]*ruleSet) {
	byName := map[string]*ruleSet{}
	v := &offlineEvaluation{engine: &Engine{}, resources: map[string]OfflineResource{}, used: map[string]bool{}}
	e.mu.Lock()
	for _, rs := range e.sets {
		copy := &ruleSet{src: rs.src}
		data := rs.data.Load()
		copy.data.Store(data)
		byName[rs.src.name] = copy
		v.resources["rule_set:"+rs.src.name] = offlineResource(rs.src, "rule_set", rs.src.name, data)
	}
	if e.geo != nil {
		data := e.geo.db.Load()
		v.engine.geo = &geoSource{}
		v.engine.geo.db.Store(data)
		v.resources["geoip:"] = offlineResource(e.geo.src, "geoip", "", data)
	}
	if e.asn != nil {
		data := e.asn.db.Load()
		v.engine.asn = &asnSource{}
		v.engine.asn.db.Store(data)
		v.resources["asn:"] = offlineResource(e.asn.src, "asn", "", data)
	}
	if e.site != nil {
		data := e.site.db.Load()
		v.engine.site = &siteSource{}
		v.engine.site.db.Store(data)
		v.resources["geosite:"] = offlineResource(e.site.src, "geosite", "", data)
	}
	e.mu.Unlock()
	return v, byName
}

// Evaluate once from an original zero-based index. No nested counterfactuals,
// no invented metadata, no mutation of either the original rules or resources.
func (v *offlineEvaluation) evaluateFrom(options Options, conditions []*cond, m Metadata, start int, out OfflineResult) OfflineResult {
	// Keep fresh non-nil bounded lists for each result, including empty branches.
	out.Missing = []string{}
	out.Resources = []OfflineResource{}
	out.ResourceWarnings = []OfflineResource{}
	q := query{host: m.Host, port: m.Port, network: m.Network, src: m.Source, srcPort: m.SrcPort, inPort: m.InPort, inName: m.InName, inType: m.InType, protocol: m.Protocol, processName: m.ProcessName, processStatus: m.ProcessStatus}
	var ip *ipInfo
	if m.IP.IsValid() {
		ip = &ipInfo{ip: m.IP}
	}
	for i := start; i < len(options.Rules); i++ {
		r := options.Rules[i]
		value, missing := v.condition(conditions[i], &q, ip, false)
		if value == triFalse {
			continue
		}
		out.Rule = i + 1
		out.DisplayRow = i + 1
		out.Condition = condString(&r)
		out.RuleSet = r.RuleSet
		if value == triUnknown {
			out.Status = "unknown"
			out.Missing = missing
			out.BlockedRule = i + 1
			out.CandidatePolicy = ruleTarget(r.Action, r.Outbound)
			labels := make([]string, 0, len(missing))
			for _, field := range missing {
				labels = append(labels, offlineMissingLabel(field))
			}
			out.Reason = "该规则还需要" + strings.Join(labels, "、")
			return out
		}
		out.Status = "matched"
		out.Policy = ruleTarget(r.Action, r.Outbound)
		return out
	}
	out.Status = "final"
	out.DisplayRow = len(options.Rules) + 1
	out.Condition = "MATCH"
	out.Policy = options.Final
	return out
}
func offlineMissingLabel(s string) string {
	switch s {
	case "target_port":
		return "目标端口"
	case "network":
		return "传输协议（TCP/UDP）"
	case "process_name":
		return "手动进程信息"
	case "source_ip":
		return "来源 IP"
	case "source_port":
		return "来源端口"
	case "inbound_name":
		return "入站名称"
	case "inbound_type":
		return "入站类型"
	case "inbound_port":
		return "入站端口"
	case "protocol":
		return "嗅探协议"
	case "destination_ip":
		return "目的 IP（离线不解析 DNS）"
	default:
		return "已加载的规则集资源"
	}
}
func mergeOfflineMissing(dst, src []string) []string {
	for _, s := range src {
		found := false
		for _, old := range dst {
			if old == s {
				found = true
				break
			}
		}
		if !found && len(dst) < 11 {
			dst = append(dst, s)
		}
	}
	return dst
}
func (v *offlineEvaluation) condition(c *cond, q *query, x *ipInfo, noDNS bool) (int8, []string) {
	e := v.engine
	unknown := func(field string) (int8, []string) { return triUnknown, []string{field} }
	switch c.kind {
	case kAnd, kOr:
		result, decisive := triTrue, triFalse
		if c.kind == kOr {
			result, decisive = triFalse, triTrue
		}
		var missing []string
		for _, sub := range c.subs {
			value, fields := v.condition(sub, q, x, noDNS)
			if value == decisive {
				return value, nil
			}
			if value == triUnknown {
				missing = mergeOfflineMissing(missing, fields)
			}
		}
		if len(missing) > 0 {
			return triUnknown, missing
		}
		return result, nil
	case kNot:
		value, fields := v.condition(c.subs[0], q, x, noDNS)
		if value == triUnknown {
			return value, fields
		}
		return 1 - value, nil
	case kRuleSet:
		v.use("rule_set", c.set.src.name)
		return v.data(c.set.data.Load(), q, x, noDNS || c.noResolve)
	case kInline:
		return v.data(c.inline, q, x, noDNS)
	case kGeosite:
		v.use("geosite", "")
	case kIPASN:
		v.use("asn", "")
	case kGeoIP:
		if c.s != geoPrivate {
			v.use("geoip", "")
		}
	case kSrcIPASN:
		v.use("asn", "")
		if !e.asnUsable() {
			return triFalse, nil
		}
		if !q.src.IsValid() {
			return unknown("source_ip")
		}
	case kSrcGeoIP:
		if c.s != geoPrivate {
			v.use("geoip", "")
		}
		if !e.geoUsable(c.s) {
			return triFalse, nil
		}
		if !q.src.IsValid() {
			return unknown("source_ip")
		}
	case kSrcIPCIDR, kSrcIPSet:
		if !q.src.IsValid() {
			return unknown("source_ip")
		}
	case kProcessName:
		if q.processStatus != "known" {
			return unknown("process_name")
		}
	case kDstPort:
		if q.port == 0 {
			return unknown("target_port")
		}
	case kSrcPort:
		if q.srcPort == 0 {
			return unknown("source_port")
		}
	case kInPort:
		if q.inPort == 0 {
			return unknown("inbound_port")
		}
	case kInName:
		if q.inName == "" {
			return unknown("inbound_name")
		}
	case kInType:
		if q.inType == "" {
			return unknown("inbound_type")
		}
	case kNetwork:
		if q.network == "" {
			return unknown("network")
		}
	case kProtocol:
		if q.protocol == "" {
			return unknown("protocol")
		}
	}
	if x == nil && !noDNS && e.needsIP(c) {
		return unknown("destination_ip")
	}
	if e.match(c, q, x) {
		return triTrue, nil
	}
	return triFalse, nil
}
func (v *offlineEvaluation) data(d *setData, q *query, x *ipInfo, noDNS bool) (int8, []string) {
	if d == nil {
		return triUnknown, []string{"rule_set_data"}
	}
	e := v.engine
	indexed := *d
	indexed.extra = nil
	indexed.extraIP = false
	// Port 0 is unknown, not a valid port, including ranges such as :443.
	if q.port == 0 {
		indexed.ports = nil
	}
	// Country resources are only involved after the domain/port/IP shortcuts.
	if !indexed.dom.match(q.host) && !portIn(indexed.ports, q.port) && !(x != nil && (indexed.ip.contains(x.ip) || indexed.ipNR.contains(x.ip))) {
		for _, codes := range [][]string{indexed.geo, indexed.geoNR} {
			for _, code := range codes {
				if code != geoPrivate {
					v.use("geoip", "")
				}
			}
		}
	}
	if indexed.match(e, q, x) {
		return triTrue, nil
	}
	var missing []string
	if q.port == 0 && len(d.ports) > 0 {
		missing = append(missing, "target_port")
	}
	if x == nil && !noDNS && indexed.needsIP(e) {
		missing = append(missing, "destination_ip")
	}
	for _, c := range d.extra {
		value, fields := v.condition(c, q, x, noDNS)
		if value == triTrue {
			return value, nil
		}
		if value == triUnknown {
			missing = mergeOfflineMissing(missing, fields)
		}
	}
	if len(missing) > 0 {
		return triUnknown, missing
	}
	return triFalse, nil
}

// offlineRules normalizes a detached accepted projection and borrows one
// immutable resource snapshot. Target tests use the runtime's empty-set
// behavior for an unloaded resource, while the strict legacy view can still
// describe that missing resource as unknown.
func (e *Engine) offlineRules(options Options, emptyUnloaded bool) (Options, *offlineEvaluation, []*cond, error) {
	options.Rules = append([]Rule(nil), options.Rules...)
	for i := range options.Rules {
		options.Rules[i] = cloneRule(options.Rules[i])
	}
	options.RuleSets = append([]RuleSetOptions(nil), options.RuleSets...)
	for _, p := range []**GeoIPOptions{&options.GeoIP, &options.ASN, &options.Geosite} {
		if *p != nil {
			copy := **p
			*p = &copy
		}
	}
	if err := options.Validate(); err != nil {
		return options, nil, nil, errors.New("当前规则无法安全模拟")
	}
	if e == nil {
		return options, nil, nil, errors.New("当前路由引擎不可用")
	}
	v, byName := e.freezeOffline()
	for _, set := range options.RuleSets {
		if byName[set.Name] == nil {
			return options, nil, nil, errors.New("当前引擎未加载所需规则集")
		}
	}
	if emptyUnloaded {
		// The ruleSet is a detached snapshot from freezeOffline, not a live set.
		for _, set := range byName {
			if set.data.Load() == nil {
				set.data.Store(&setData{})
			}
		}
	}
	conditions := make([]*cond, len(options.Rules))
	for i := range options.Rules {
		conditions[i] = compileRule(&options.Rules[i], byName)
	}
	return options, v, conditions, nil
}
