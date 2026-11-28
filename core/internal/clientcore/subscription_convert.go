package clientcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/oschwald/maxminddb-golang"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/provider"
	"github.com/shui1iao/Kat/internal/route"
	"gopkg.in/yaml.v3"
	"net"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"unicode"
)

func rawArrayMust(b []byte, k string) []json.RawMessage {
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	return rawArray(m, k)
}
func removeOwned(all, owned []json.RawMessage, mutableGroup bool) ([]json.RawMessage, error) {
	wanted := map[string]json.RawMessage{}
	for _, v := range owned {
		wanted[rawName(v)] = v
	}
	out := []json.RawMessage{}
	for _, v := range all {
		n := rawName(v)
		if o, ok := wanted[n]; ok {
			a, b := v, o
			if mutableGroup {
				var x, y map[string]json.RawMessage
				_ = json.Unmarshal(a, &x)
				_ = json.Unmarshal(b, &y)
				delete(x, "selected")
				delete(y, "selected")
				delete(x, "priority")
				delete(y, "priority")
				delete(x, "fixed")
				delete(y, "fixed")
				a = rawJSON(x)
				b = rawJSON(y)
			}
			if !sameJSON(a, b) {
				return nil, errors.New("owned value changed")
			}
			delete(wanted, n)
		} else {
			out = append(out, v)
		}
	}
	if len(wanted) > 0 {
		return nil, errors.New("owned value missing")
	}
	return out, nil
}

// A snapshot identifies an owned block only if its position is unique.
// -1 means absent, -2 ambiguous; neither permits removing any matching block.
func findRuleBlock(all, block []json.RawMessage) int {
	if len(block) == 0 {
		return -1
	}
	found := -1
	for i := 0; i+len(block) <= len(all); i++ {
		ok := true
		for j := range block {
			if !sameJSON(all[i+j], block[j]) {
				ok = false
				break
			}
		}
		if ok {
			if found >= 0 {
				return -2
			}
			found = i
		}
	}
	return found
}
func validateFullGraph(f provider.Full, workspace string) error {
	sets := append([]route.RuleSetOptions{}, f.RuleSets...)
	for i := range sets {
		sets[i].Path = filepath.Join(workspace, fmt.Sprintf("static-full-%d", i))
	}
	var geo *route.GeoIPOptions
	var asn *route.GeoIPOptions
	if f.NeedsGeoIP {
		geo = &route.GeoIPOptions{Path: filepath.Join(workspace, "static-country.mmdb")}
	}
	if f.NeedsASN {
		asn = &route.GeoIPOptions{Path: filepath.Join(workspace, "static-asn.mmdb")}
	}
	final := f.Final
	if final == "" {
		final = "direct"
	}
	b := rawJSON(map[string]any{"inbounds": []kernel.Inbound{{Protocol: "socks5", Listen: "127.0.0.1:7891"}}, "outbounds": f.Outbounds, "groups": f.Groups, "routing": map[string]any{"rules": f.Rules, "final": final}, "rule_sets": sets, "geoip": geo, "asn": asn})
	// Omit nil geoip: kernel's strict decoder rejects explicit null for options.
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	if geo == nil {
		delete(m, "geoip")
	}
	if asn == nil {
		delete(m, "asn")
	}
	_, e := kernel.DecodeConfig(rawJSON(m))
	return e
}
func validateSubscriptionResources(c kernel.Config, owners ...fullSubscription) *Error {
	owned := map[string][2]int{}
	for oi, o := range owners {
		for ri, v := range o.Snapshot.RuleSets {
			owned[rawName(v)] = [2]int{oi + 1, ri + 1}
		}
	}
	deps := route.SubscriptionSetDependencies{GeoIP: c.GeoIP != nil, ASN: c.ASN != nil, Geosite: c.Geosite != nil}
	var tasks []func() *Error
	for _, s := range c.RuleSets {
		ord, ok := owned[s.Name]
		if !ok {
			continue
		}
		rs := s
		envStamp := fmt.Sprintf("%t%t%t", deps.GeoIP, deps.ASN, deps.Geosite)
		tasks = append(tasks, func() *Error {
			fi, e := statSubscriptionResource(rs.Path, 16<<20)
			if e != nil {
				de := resourceError(context.Background(), "rule_set", ord[1], "cache", "cache_verify", "unknown", e)
				de.Detail.SubscriptionOrdinal = ord[0]
				return de
			}
			if _, hit, _ := route.ValidateSubscriptionSetFile(route.RuleSetOptions(rs), fi, deps); hit {
				return nil
			}
			b, fi, e := readSubscriptionResourceStat(rs.Path, 16<<20)
			if e != nil {
				de := resourceError(context.Background(), "rule_set", ord[1], "cache", "cache_verify", "unknown", e)
				de.Detail.SubscriptionOrdinal = ord[0]
				return de
			}
			if _, e = route.ValidateSubscriptionSetWithDependencies(route.RuleSetOptions(rs), b, deps); e != nil {
				de := resourceError(context.Background(), "rule_set", ord[1], "cache", "format_check", "invalid_format", nil)
				de.Detail.SubscriptionOrdinal = ord[0]
				return de
			}
			route.CacheRecordStat(rs.Path, "rule_set", "rule_set|"+rs.Format+"|"+rs.Behavior+"|"+envStamp, fi)
			return nil
		})
	}
	if c.GeoIP != nil {
		geoPath := c.GeoIP.Path
		tasks = append(tasks, func() *Error {
			fi, e := statSubscriptionResource(geoPath, 64<<20)
			if e != nil {
				return resourceError(context.Background(), "geoip", 0, "cache", "cache_verify", "unknown", e)
			}
			if hit, _ := route.ValidateSubscriptionGeoIPFile(geoPath, fi); hit {
				return nil
			}
			b, fi, e := readSubscriptionResourceStat(geoPath, 64<<20)
			if e != nil {
				return resourceError(context.Background(), "geoip", 0, "cache", "cache_verify", "unknown", e)
			}
			if route.ValidateSubscriptionGeoIPAt(geoPath, b) != nil {
				return resourceError(context.Background(), "geoip", 0, "cache", "format_check", "db_incompatible", nil)
			}
			route.CacheRecordStat(geoPath, "geoip", "geoip", fi)
			return nil
		})
	}
	if c.ASN != nil {
		asnPath := c.ASN.Path
		tasks = append(tasks, func() *Error {
			fi, e := statSubscriptionResource(asnPath, 64<<20)
			if e != nil {
				return resourceError(context.Background(), "asn", 0, "cache", "cache_verify", "unknown", e)
			}
			if hit, _ := route.ValidateSubscriptionASNFile(asnPath, fi); hit {
				return nil
			}
			b, fi, e := readSubscriptionResourceStat(asnPath, 64<<20)
			if e != nil {
				return resourceError(context.Background(), "asn", 0, "cache", "cache_verify", "unknown", e)
			}
			if validateSubscriptionDBAt("asn", asnPath, b) != nil {
				return resourceError(context.Background(), "asn", 0, "cache", "format_check", "db_incompatible", nil)
			}
			route.CacheRecordStat(asnPath, "asn", "asn", fi)
			return nil
		})
	}
	if len(tasks) == 0 {
		return nil
	}
	if len(tasks) == 1 {
		return tasks[0]()
	}
	errs := make([]*Error, len(tasks))
	workers := min(len(tasks), max(1, min(runtime.GOMAXPROCS(0), 4)))
	jobs := make(chan int, len(tasks))
	for i := range tasks {
		jobs <- i
	}
	close(jobs)
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for idx := range jobs {
				errs[idx] = tasks[idx]()
			}
		}()
	}
	wg.Wait()
	for _, de := range errs {
		if de != nil {
			return de
		}
	}
	return nil
}

// Only subscription-owned fields are patched; YAML nodes for unrelated keys
// and unchanged manual declarations keep their comments/scalar spelling.
func renderSubscriptionSource(base document, root map[string]json.RawMessage) (string, error) {
	if base.format == FormatJSON {
		b, e := json.MarshalIndent(root, "", "  ")
		return string(b) + "\n", e
	}
	var doc yaml.Node
	if yaml.Unmarshal([]byte(base.text), &doc) != nil || len(doc.Content) != 1 {
		return "", errors.New("invalid YAML")
	}
	var patch yaml.Node
	if yaml.Unmarshal(rawJSON(root), &patch) != nil || len(patch.Content) != 1 {
		return "", errors.New("invalid YAML projection")
	}
	mergeSubscriptionYAML(doc.Content[0], patch.Content[0])
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if e := enc.Encode(&doc); e != nil {
		return "", e
	}
	return out.String(), nil
}
func mergeSubscriptionYAML(old, next *yaml.Node) {
	var a, b any
	_ = old.Decode(&a)
	_ = next.Decode(&b)
	if reflect.DeepEqual(a, b) {
		return
	}
	if old.Kind == yaml.MappingNode && next.Kind == yaml.MappingNode {
		index := map[string]*yaml.Node{}
		for i := 0; i < len(old.Content); i += 2 {
			index[old.Content[i].Value] = old.Content[i+1]
		}
		var result []*yaml.Node
		for i := 0; i < len(old.Content); i += 2 {
			for j := 0; j < len(next.Content); j += 2 {
				if old.Content[i].Value == next.Content[j].Value {
					mergeSubscriptionYAML(old.Content[i+1], next.Content[j+1])
					result = append(result, old.Content[i], old.Content[i+1])
					delete(index, old.Content[i].Value)
					break
				}
			}
		}
		for j := 0; j < len(next.Content); j += 2 {
			found := false
			for i := 0; i < len(old.Content); i += 2 {
				if old.Content[i].Value == next.Content[j].Value {
					found = true
					break
				}
			}
			if !found {
				result = append(result, next.Content[j], next.Content[j+1])
			}
		}
		old.Content = result
		return
	}
	if old.Kind == yaml.SequenceNode && next.Kind == yaml.SequenceNode {
		used := map[int]bool{}
		for i, n := range next.Content {
			var v any
			_ = n.Decode(&v)
			for j, o := range old.Content {
				if used[j] {
					continue
				}
				var w any
				_ = o.Decode(&w)
				if reflect.DeepEqual(v, w) {
					next.Content[i] = o
					used[j] = true
					break
				}
			}
		}
	}
	next.HeadComment = old.HeadComment
	next.LineComment = old.LineComment
	next.FootComment = old.FootComment
	*old = *next
}

func safeSubscriptionName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), "_")
	s = strings.ReplaceAll(s, "=", "_")
	if len(s) > 44 || s == "" {
		h := sha256.Sum256([]byte(s))
		return "item-" + hex.EncodeToString(h[:8])
	}
	return s
}

func validateSubscriptionDB(kind string, b []byte) error {
	return validateSubscriptionDBAt(kind, "", b)
}

func validateSubscriptionDBAt(kind, path string, b []byte) error {
	if len(b) > 64<<20 {
		return errors.New("resource limit")
	}
	if kind == "geoip" {
		return route.ValidateSubscriptionGeoIPAt(path, b)
	}
	if e := route.ValidateSubscriptionASNAt(path, b); e != nil {
		return e
	}
	r, e := maxminddb.FromBytes(b)
	if e != nil {
		return e
	}
	defer r.Close()
	if r.Metadata.IPVersion != 4 && r.Metadata.IPVersion != 6 {
		return errors.New("MMDB IP version")
	}
	found := false
	for _, ip := range []string{"1.1.1.1", "8.8.8.8", "223.5.5.5"} {
		var v struct {
			ASN uint32 `maxminddb:"autonomous_system_number"`
		}
		if r.Lookup(net.ParseIP(ip), &v) != nil {
			return errors.New("MMDB ASN field")
		}
		found = found || v.ASN > 0
	}
	if !found {
		return errors.New("MMDB lacks autonomous_system_number")
	}
	return nil
}

// Detect resources only from classical type tokens, not arbitrary URL/domain
// substrings. Runtime strict parser remains authoritative for full semantics.
func subscriptionSetNeeds(s route.RuleSetOptions, b []byte) (bool, bool, error) {
	if s.Behavior != "classical" {
		return false, false, nil
	}
	var lines []string
	if s.Format == "yaml" {
		j, e := yamlJSON(b)
		if e != nil {
			return false, false, e
		}
		var p struct {
			Payload []string `json:"payload"`
		}
		if json.Unmarshal(j, &p) != nil || p.Payload == nil {
			return false, false, errors.New("payload required")
		}
		lines = p.Payload
	}
	country, asn := false, false
	scanLine := func(line []byte) {
		typ, _, ok := bytes.Cut(bytes.TrimSpace(line), []byte(","))
		if !ok {
			return
		}
		typ = bytes.TrimSpace(typ)
		// Avoid running a regex over ordinary domain lines. The runtime also
		// accepts mixed-case classical/logical operators in mihomo text.
		switch string(bytes.ToUpper(typ)) {
		case "GEOIP", "SRC-GEOIP", "IP-ASN", "SRC-IP-ASN", "AND", "OR", "NOT":
		default:
			return
		}
		for _, m := range subscriptionSetNeedsRx.FindAllSubmatch(line, -1) {
			if bytes.EqualFold(m[1], []byte("IP-ASN")) || bytes.EqualFold(m[1], []byte("SRC-IP-ASN")) {
				asn = true
			} else if val := bytes.TrimSpace(m[2]); !bytes.EqualFold(val, []byte("LAN")) && !bytes.EqualFold(val, []byte("private")) {
				country = true
			}
		}
	}
	if lines != nil {
		for _, l := range lines {
			scanLine([]byte(l))
			if country && asn {
				break
			}
		}
	} else {
		for l := range bytes.Lines(b) {
			scanLine(l)
			if country && asn {
				break
			}
		}
	}
	return country, asn, nil
}
func subscriptionItems(f provider.Full) map[string]any {
	nodes := []map[string]string{}
	for _, n := range f.Outbounds {
		nodes = append(nodes, map[string]string{"name": n.Name, "type": n.Type})
	}
	groups := []map[string]any{}
	for _, g := range f.Groups {
		if g.Members == nil {
			g.Members = []string{}
		}
		groups = append(groups, map[string]any{"name": g.Name, "type": g.Type, "members": g.Members})
	}
	sets := []string{}
	for _, s := range f.RuleSets {
		sets = append(sets, s.Name)
	}
	if f.Rules == nil {
		f.Rules = []route.Rule{}
	}
	return map[string]any{"nodes": nodes, "groups": groups, "rules": f.Rules, "rule_sets": sets, "final": f.Final}
}

func subscriptionSetIssues(index int, err error) []string {
	var detail *route.SubscriptionSetValidationError
	if !errors.As(err, &detail) {
		return []string{fmt.Sprintf("规则集第%d项格式校验未通过；没有接纳任何内容", index)}
	}
	labels := map[string]string{"invalid_format": "格式无效或不受支持", "unsupported_type": "类型不受支持", "unsupported_option": "选项不受支持", "missing_dependency": "缺少必要数据库"}
	out := []string{}
	for i, issue := range detail.Issues {
		if i >= 256 {
			out = append(out, fmt.Sprintf("另有%d项问题", len(detail.Issues)-i))
			break
		}
		label := labels[issue.Code]
		if label == "" {
			label = "未通过校验"
		}
		typ := issue.RuleType
		if !subscriptionRuleTypeRx.MatchString(typ) {
			typ = "未识别"
		}
		dep := ""
		if issue.Dependency == "asn" || issue.Dependency == "geoip" || issue.Dependency == "geosite" {
			dep = "（" + issue.Dependency + "）"
		}
		out = append(out, fmt.Sprintf("规则集第%d项：payload第%d条，文件第%d行，%s：%s%s；保留原配置", index, issue.Entry, issue.Line, typ, label, dep))
	}
	return out
}
