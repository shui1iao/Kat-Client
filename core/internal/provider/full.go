package provider

// Full Clash configuration conversion deliberately reuses Kat's outbound,
// group and ordered route schemas. Unsupported routing is an error, never a
// dropped condition or an implicit DIRECT fallback.
import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"github.com/shui1iao/Kat/internal/route"
	"gopkg.in/yaml.v3"
)

type Full struct {
	Outbounds  []outbound.Options     `json:"outbounds"`
	Groups     []group.Options        `json:"groups"`
	Rules      []route.Rule           `json:"rules"`
	Final      string                 `json:"final,omitempty"`
	RuleSets   []route.RuleSetOptions `json:"rule_sets"`
	NeedsASN   bool                   `json:"needs_asn"`
	NeedsGeoIP bool                   `json:"needs_geoip"`
	Ignored    []string               `json:"ignored"`
}

type FullError struct {
	Section string
	Index   int
	Code    string
}

func (e *FullError) Error() string {
	return fmt.Sprintf("full config: %s[%d]: %s", e.Section, e.Index, e.Code)
}
func fullErr(s string, i int, c string) error { return &FullError{s, i, c} }

func fullYAML(b []byte) (map[string]any, error) {
	if len(b) > MaxSize {
		return nil, errors.New("configuration size limit")
	}
	var n yaml.Node
	d := yaml.NewDecoder(bytes.NewReader(b))
	if d.Decode(&n) != nil || d.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid YAML")
	}
	var walk func(*yaml.Node, int) bool
	walk = func(n *yaml.Node, depth int) bool {
		if depth > 64 || n.Kind == yaml.AliasNode || n.Anchor != "" {
			return false
		}
		if n.Kind == yaml.MappingNode {
			seen := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				k := n.Content[i]
				if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || seen[k.Value] || k.Value == "<<" {
					return false
				}
				seen[k.Value] = true
			}
		}
		for _, c := range n.Content {
			if !walk(c, depth+1) {
				return false
			}
		}
		return true
	}
	if !walk(&n, 0) {
		return nil, errors.New("ambiguous YAML")
	}
	var m map[string]any
	if n.Decode(&m) != nil || m == nil {
		return nil, errors.New("mapping required")
	}
	return m, nil
}

func ParseFull(b []byte, probe string) (Full, error) {
	f := Full{Outbounds: []outbound.Options{}, Groups: []group.Options{}, Rules: []route.Rule{}, RuleSets: []route.RuleSetOptions{}}
	doc, e := fullYAML(b)
	if e != nil {
		return f, e
	}
	ps, ok := doc["proxies"].([]any)
	if _, written := doc["proxies"]; written && !ok {
		return f, fullErr("proxies", 0, "list_required")
	}
	if len(ps) > MaxNodes {
		return f, fullErr("proxies", 0, "limit")
	}
	names := map[string]bool{"DIRECT": true, "REJECT": true, "direct": true, "reject": true}
	for i, v := range ps {
		m, ok := v.(map[string]any)
		if !ok {
			return f, fullErr("proxies", i, "mapping_required")
		}
		for k := range m {
			if !oneOf(k, "name", "type", "server", "port", "udp", "dialer-proxy", "cipher", "password", "plugin", "plugin-opts", "username", "tls", "sni", "servername", "skip-cert-verify", "alpn", "fingerprint", "client-fingerprint", "network", "tfo", "fast-open", "mptcp", "ip-version", "interface-name", "routing-mark", "udp-over-tcp", "udp-over-tcp-version", "idle-session-check-interval", "idle-session-timeout", "min-idle-session") {
				return f, fullErr("proxies", i, "unsupported_node_field")
			}
		}
		for _, k := range append(append([]string{}, clashIgnored...), "fast-open") {
			if has(m, k) {
				f.Ignored = append(f.Ignored, "节点本机选项."+k)
			}
		}
		r := Result{}
		clashNode(&r, m)
		if len(r.Nodes) != 1 || len(r.Skipped) > 0 {
			return f, fullErr("proxies", i, "unsupported_node")
		}
		o := r.Nodes[0].OutboundOptions()
		if names[o.Name] {
			return f, fullErr("proxies", i, "duplicate_or_reserved_name")
		}
		names[o.Name] = true
		f.Outbounds = append(f.Outbounds, o)
	}
	gs, ok := doc["proxy-groups"].([]any)
	if doc["proxy-groups"] != nil && !ok {
		return f, fullErr("proxy-groups", 0, "list_required")
	}
	if len(gs) > 128 {
		return f, fullErr("proxy-groups", 0, "limit")
	}
	for i, v := range gs {
		m, ok := v.(map[string]any)
		if !ok {
			return f, fullErr("proxy-groups", i, "mapping_required")
		}
		g, e := fullGroup(m, probe, f.Outbounds)
		if e != nil {
			return f, fullErr("proxy-groups", i, "unsupported_group_field_or_value")
		}
		if names[g.Name] || g.Name == "" {
			return f, fullErr("proxy-groups", i, "duplicate_or_reserved_name")
		}
		names[g.Name] = true
		f.Groups = append(f.Groups, g)
	}
	rs, ok := doc["rule-providers"].(map[string]any)
	if doc["rule-providers"] != nil && !ok {
		return f, fullErr("rule-providers", 0, "mapping_required")
	}
	// YAML declaration order matters for predictable preview/cache naming.
	var node yaml.Node
	_ = yaml.Unmarshal(b, &node)
	var keys []string
	if len(node.Content) > 0 {
		root := node.Content[0]
		for i := 0; i+1 < len(root.Content); i += 2 {
			if root.Content[i].Value == "rule-providers" {
				for j := 0; j+1 < len(root.Content[i+1].Content); j += 2 {
					keys = append(keys, root.Content[i+1].Content[j].Value)
				}
			}
		}
	}
	for i, name := range keys {
		m, ok := rs[name].(map[string]any)
		if !ok {
			return f, fullErr("rule-providers", i, "mapping_required")
		}
		for k := range m {
			if !oneOf(k, "type", "behavior", "format", "url", "path", "interval") {
				return f, fullErr("rule-providers", i, "unsupported_field")
			}
		}
		format := str(m, "format")
		if format == "" {
			format = "yaml"
		}
		behavior := str(m, "behavior")
		if str(m, "type") != "http" || !oneOf(format, "yaml", "text") || !oneOf(behavior, "classical", "domain", "ipcidr") || str(m, "url") == "" {
			return f, fullErr("rule-providers", i, "unsupported_source")
		}
		iv := str(m, "interval")
		if iv == "" {
			iv = "86400"
		}
		n, e := strconv.Atoi(iv)
		if e != nil || n < 60 || n > 604800 {
			return f, fullErr("rule-providers", i, "invalid_interval")
		}
		if format == "text" {
			format = behavior
		}
		f.RuleSets = append(f.RuleSets, route.RuleSetOptions{Name: name, Format: format, Behavior: behavior, URL: str(m, "url"), Interval: outbound.Duration(time.Duration(n) * time.Second)})
	}
	rules, ok := doc["rules"].([]any)
	if doc["rules"] != nil && !ok {
		return f, fullErr("rules", 0, "list_required")
	}
	for i, v := range rules {
		s, ok := v.(string)
		if !ok {
			return f, fullErr("rules", i, "string_required")
		}
		r, final, e := ClashRule(s)
		if e != nil {
			return f, fullErr("rules", i, "unsupported_rule")
		}
		if final != "" {
			if i != len(rules)-1 || f.Final != "" {
				return f, fullErr("rules", i, "MATCH_must_be_last")
			}
			f.Final = final
			continue
		}
		if r.IPASN != "" || r.SrcIPASN != "" {
			f.NeedsASN = true
		}
		if (r.GeoIP != "" && r.GeoIP != "private") || (r.SrcGeoIP != "" && r.SrcGeoIP != "private") {
			f.NeedsGeoIP = true
		}
		f.Rules = append(f.Rules, r)
	}
	for k := range doc {
		if !oneOf(k, "proxies", "proxy-groups", "rules", "rule-providers") {
			if oneOf(k, "proxy-providers", "sub-rules", "rule-anchor") {
				return f, fullErr(k, 0, "unsupported_routing_section")
			}
			f.Ignored = append(f.Ignored, k)
		}
	}
	// A missing MATCH does not silently overwrite the user's existing final.
	return f, nil
}
func oneOf(v string, vs ...string) bool {
	for _, s := range vs {
		if s == v {
			return true
		}
	}
	return false
}
func builtin(s string) string {
	switch s {
	case "DIRECT":
		return "direct"
	case "REJECT":
		return "reject"
	}
	return s
}
func fullGroup(m map[string]any, probe string, nodes []outbound.Options) (group.Options, error) {
	bad := errors.New("unsupported group")
	for k := range m {
		if !oneOf(k, "name", "type", "proxies", "include-all", "include-all-proxies", "filter", "exclude-filter", "exclude-type", "url", "interval", "timeout", "tolerance", "lazy", "expected-status", "strategy", "disable-udp", "icon", "hidden") && !(str(m, "type") == "smart" && oneOf(k, "smart", "priority", "fixed", "damping")) {
			return group.Options{}, bad
		}
	}
	if b, ok := m["disable-udp"]; ok && b != false {
		return group.Options{}, bad
	}
	g := group.Options{Name: str(m, "name"), Type: str(m, "type")}
	// Decode Smart-specific native fields with the ordinary strict decoder.
	extra := map[string]json.RawMessage{}
	for _, key := range []string{"smart", "priority", "fixed", "damping"} {
		if v, ok := m[key]; ok {
			b, e := json.Marshal(v)
			if e != nil {
				return g, bad
			}
			extra[key] = b
		}
	}
	b, _ := json.Marshal(g)
	fields := map[string]json.RawMessage{}
	json.Unmarshal(b, &fields)
	for k, v := range extra {
		fields[k] = v
	}
	b, _ = json.Marshal(fields)
	if e := json.Unmarshal(b, &g); e != nil {
		return g, e
	}
	g.Fixed = builtin(g.Fixed)
	if g.Priority != nil {
		w := map[string]float64{}
		for k, v := range g.Priority {
			w[builtin(k)] = v
		}
		g.Priority = w
	}

	_, g.ToleranceSet = m["tolerance"]
	if !oneOf(g.Type, group.TypeSelect, group.TypeSmart, group.TypeURLTest, group.TypeFallback, group.TypeLoadBalance, group.TypeRelay) {
		return g, bad
	}
	if v, ok := m["proxies"]; ok {
		a, ok := v.([]any)
		if !ok {
			return g, bad
		}
		for _, x := range a {
			s, ok := x.(string)
			if !ok || s == "" {
				return g, bad
			}
			g.Members = append(g.Members, builtin(s))
		}
	}
	inc := false
	for _, k := range []string{"include-all", "include-all-proxies"} {
		if v, ok := m[k]; ok {
			b, ok := v.(bool)
			if !ok {
				return g, bad
			}
			inc = inc || b
		}
	}
	if v, ok := m["icon"]; ok {
		icon, valid := v.(string)
		if !valid {
			return g, bad
		}
		g.Icon = icon
	}
	if !group.ValidIcon(g.Icon) {
		return g, bad
	}
	filter, exclude := group.NormalizeFilters(str(m, "filter"), str(m, "exclude-filter"))
	if m["exclude-type"] != nil {
		return g, bad
	}
	if !inc && (filter != "" || exclude != "") {
		return g, bad
	}
	if inc {
		if filter == "" {
			filter = ".*"
		}
		g.IncludeAll = true
		g.Filter = filter
		g.ExcludeFilter = exclude
		if _, e := group.MemberFilter(g); e != nil {
			return g, bad
		}
	}
	if g.Type != group.TypeSelect && g.Type != group.TypeRelay {
		u := str(m, "url")
		if u == "" {
			u = "https://www.gstatic.com/generate_204"
		}
		g.Probe = &group.ProbeOptions{URL: u, ExpectedStatus: str(m, "expected-status")}
		for _, f := range []struct {
			k    string
			p    *outbound.Duration
			unit time.Duration
		}{{"interval", &g.Probe.Interval, time.Second}, {"timeout", &g.Probe.Timeout, time.Millisecond}, {"tolerance", &g.Tolerance, time.Millisecond}} {
			if v, ok := m[f.k]; ok {
				n, e := strconv.ParseInt(fmt.Sprint(v), 10, 64)
				if e != nil || n < 0 || n > 604800000 {
					return g, bad
				}
				*f.p = outbound.Duration(time.Duration(n) * f.unit)
			}
		}
		if v, ok := m["lazy"]; ok {
			b, ok := v.(bool)
			if !ok {
				return g, bad
			}
			g.Lazy = &b
		}
		g.Strategy = str(m, "strategy")
	} else {
		for _, k := range []string{"url", "interval", "timeout", "tolerance", "lazy", "expected-status", "strategy"} {
			if m[k] != nil {
				return g, bad
			}
		}
	}
	if g.Type == group.TypeSmart {
		return g, group.Validate(g)
	}
	return g, nil
}

// ClashRule converts one ordered classical rule. Unknown types/modifiers are
// rejected, including MATCH in a rule-set (the caller rejects nonempty final).
func ClashRule(s string) (route.Rule, string, error) {
	var r route.Rule
	bad := errors.New("unsupported rule")
	a := strings.Split(s, ",")
	for i := range a {
		a[i] = strings.TrimSpace(a[i])
		if a[i] == "" {
			return r, "", bad
		}
	}
	if len(a) == 2 && a[0] == "MATCH" {
		return r, builtin(a[1]), nil
	}
	if len(a) != 3 && len(a) != 4 {
		return r, "", bad
	}
	if len(a) == 4 {
		if a[3] != "no-resolve" || !oneOf(a[0], "IP-CIDR", "IP-CIDR6", "GEOIP", "RULE-SET", "IP-ASN", "IP-SUFFIX") {
			return r, "", bad
		}
		r.NoResolve = true
	}
	switch a[0] {
	case "PROCESS-NAME":
		r.ProcessName = a[1]
	case "DOMAIN":
		r.Domain = a[1]
	case "DOMAIN-SUFFIX":
		r.DomainSuffix = a[1]
	case "DOMAIN-KEYWORD":
		r.DomainKeyword = a[1]
	case "DOMAIN-REGEX":
		r.DomainRegex = a[1]
	case "IP-CIDR", "IP-CIDR6":
		r.IPCIDR = a[1]
	case "SRC-IP-CIDR":
		r.SrcIPCIDR = a[1]
	case "GEOIP":
		r.GeoIP = a[1]
		if strings.EqualFold(a[1], "LAN") {
			r.GeoIP = "private"
		}
	case "RULE-SET":
		r.RuleSet = a[1]
	case "DST-PORT":
		r.DstPort = a[1]
	case "SRC-PORT":
		r.SrcPort = a[1]
	case "IP-SUFFIX":
		r.IPSuffix = a[1]
	case "IP-ASN":
		r.IPASN = a[1]
	case "SRC-IP-ASN":
		r.SrcIPASN = a[1]
	case "SRC-GEOIP":
		r.SrcGeoIP = a[1]
	case "DOMAIN-WILDCARD":
		r.DomainWildcard = a[1]
	case "NETWORK":
		r.Network = strings.ToLower(a[1])
	default:
		return r, "", bad
	}
	target := builtin(a[2])
	if target == "direct" || target == "reject" {
		r.Action = target
	} else {
		r.Outbound = target
	}
	return r, "", nil
}
