package route

import (
	"context"
	"errors"
	"net/netip"
)

// TargetSkippedRule explains a rule omitted only because the caller supplied
// no connection-specific metadata. It is never presented as a false match.
type TargetSkippedRule struct {
	Rule      int      `json:"rule"`
	Condition string   `json:"condition"`
	Policy    string   `json:"policy"`
	Missing   []string `json:"missing"`
}

type TargetDNS struct {
	Status         string   `json:"status"` // not_needed | resolved | failed
	Addresses      []string `json:"addresses"`
	SelectedIP     string   `json:"selected_ip,omitempty"`
	Message        string   `json:"message,omitempty"`
	DifferentRules bool     `json:"different_rules,omitempty"`
}

type TargetIPResult struct {
	IP     string `json:"ip"`
	Status string `json:"status"`
	Rule   int    `json:"rule"`
	Policy string `json:"policy"`
}

// TargetResult is a target-only rule lookup, not an attempt to establish a
// connection. Missing caller metadata is explicit; DNS is the sole I/O seam.
type TargetResult struct {
	OfflineResult
	Skipped     []TargetSkippedRule `json:"skipped"`
	SkippedMore int                 `json:"skipped_more,omitempty"`
	DNS         TargetDNS           `json:"dns"`
	IPResults   []TargetIPResult    `json:"ip_results,omitempty"`
}

func targetSeed(input string, known OfflineKnown) TargetResult {
	return TargetResult{
		OfflineResult: OfflineResult{Target: input, Known: known, Missing: []string{}, Resources: []OfflineResource{}, ResourceWarnings: []OfflineResource{}},
		Skipped:       []TargetSkippedRule{}, DNS: TargetDNS{Status: "not_needed", Addresses: []string{}},
	}
}

func cloneTarget(out TargetResult) TargetResult {
	out.Skipped = append([]TargetSkippedRule{}, out.Skipped...)
	out.Missing = []string{}
	out.Resources = []OfflineResource{}
	out.ResourceWarnings = []OfflineResource{}
	out.ConditionalAfter = nil
	return out
}

func hasTargetMissing(fields []string, field string) bool {
	for _, v := range fields {
		if v == field {
			return true
		}
	}
	return false
}

// targetFrom retains first-match ordering. Only connection-context unknowns
// are skipped. An unresolved IP is a hard boundary until DNS has answered.
func (v *offlineEvaluation) targetFrom(options Options, conditions []*cond, m Metadata, x *ipInfo, start int, out TargetResult) TargetResult {
	q := query{host: m.Host, port: m.Port, network: m.Network, src: m.Source, srcPort: m.SrcPort, inPort: m.InPort, inName: m.InName, inType: m.InType, protocol: m.Protocol, processName: m.ProcessName, processStatus: m.ProcessStatus}
	for i := start; i < len(options.Rules); i++ {
		r := options.Rules[i]
		value, missing := v.condition(conditions[i], &q, x, false)
		if value == triFalse {
			continue
		}
		if value == triUnknown && !hasTargetMissing(missing, "destination_ip") && !hasTargetMissing(missing, "rule_set_data") {
			skipped := TargetSkippedRule{Rule: i + 1, Condition: condString(&r), Policy: ruleTarget(r.Action, r.Outbound), Missing: append([]string(nil), missing...)}
			if len(out.Skipped) < 32 {
				out.Skipped = append(out.Skipped, skipped)
			} else {
				out.SkippedMore++
			}
			continue
		}
		out.Rule = i + 1
		out.DisplayRow = i + 1
		out.Condition = condString(&r)
		out.RuleSet = r.RuleSet
		if value == triUnknown {
			out.Status = "unknown"
			out.Policy = ""
			out.Missing = missing
			out.BlockedRule = i + 1
			out.CandidatePolicy = ruleTarget(r.Action, r.Outbound)
			out.Reason = "需要目的 IP；仅做 DNS 查询，不访问目标"
			return out
		}
		out.Status = "matched"
		out.Policy = ruleTarget(r.Action, r.Outbound)
		out.Rule = i + 1
		out.Missing = []string{}
		out.BlockedRule = 0
		out.CandidatePolicy = ""
		out.Reason = ""
		return out
	}
	out.Status = "final"
	out.Rule = 0
	out.DisplayRow = len(options.Rules) + 1
	out.Condition = "MATCH"
	out.Policy = options.Final
	out.RuleSet = ""
	out.Missing = []string{}
	out.BlockedRule = 0
	out.CandidatePolicy = ""
	out.Reason = ""
	return out
}

func forkTargetEvaluation(v *offlineEvaluation) *offlineEvaluation {
	next := &offlineEvaluation{engine: v.engine, resources: v.resources, used: map[string]bool{}, order: append([]string(nil), v.order...)}
	for k, b := range v.used {
		next.used[k] = b
	}
	return next
}

// TestTarget evaluates the accepted rule projection against one frozen set of
// resources. It never calls Decide, any outbound, attribution, selection or
// traffic accounting. resolve is called at most once and only for an IP rule.
func (e *Engine) TestTarget(ctx context.Context, options Options, in OfflineInput, resolve Resolver) (TargetResult, error) {
	m, known, err := offlineMetadata(in)
	if err != nil {
		return TargetResult{}, err
	}
	options, v, conditions, err := e.offlineRules(options, true)
	if err != nil {
		return TargetResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return TargetResult{}, err
	}
	seed := targetSeed(in.Target, known)
	var x *ipInfo
	if m.IP.IsValid() {
		x = &ipInfo{ip: m.IP}
	}
	out := v.targetFrom(options, conditions, m, x, 0, seed)
	if out.Status != "unknown" || !hasTargetMissing(out.Missing, "destination_ip") {
		v.finish(&out.OfflineResult)
		return out, nil
	}
	// Keep the pre-DNS stop index. In particular, earlier no-resolve IP rules
	// that already missed must not be reconsidered after a later rule asks DNS.
	stop := out.BlockedRule - 1
	if resolve == nil {
		err = errors.New("no rule DNS resolver")
	} else {
		var ips []netip.Addr
		ips, err = e.lookup(ctx, resolve, m.Host)
		if err == nil {
			ips = dedupe(ips)
			if len(ips) == 0 {
				err = errors.New("empty DNS answer")
			} else {
				dns := TargetDNS{Status: "resolved", Addresses: make([]string, 0, len(ips))}
				for _, ip := range ips {
					dns.Addresses = append(dns.Addresses, ip.String())
				}
				var selected *TargetResult
				results := make([]TargetIPResult, 0, len(ips))
				// out includes only context skips encountered before the DNS boundary.
				prefix := cloneTarget(out)
				for _, ip := range ips {
					branch := forkTargetEvaluation(v)
					current := branch.targetFrom(options, conditions, m, &ipInfo{ip: ip}, stop, cloneTarget(prefix))
					branch.finish(&current.OfflineResult)
					current.DNS = dns
					current.DNS.SelectedIP = ip.String()
					results = append(results, TargetIPResult{IP: ip.String(), Status: current.Status, Rule: current.Rule, Policy: current.Policy})
					// Match the router: the first non-reject answer decides; retain the
					// first rejection only when every candidate is rejected.
					if selected == nil || selected.Policy == "reject" && current.Policy != "reject" {
						keep := current
						selected = &keep
					}
				}
				out = *selected
				out.IPResults = results
				for _, r := range results {
					if r.Rule != out.Rule || r.Policy != out.Policy || r.Status != out.Status {
						out.DNS.DifferentRules = true
					}
				}
				return out, nil
			}
		}
	}
	if ctx.Err() != nil {
		return TargetResult{}, ctx.Err()
	}
	out.DNS = TargetDNS{Status: "failed", Addresses: []string{}, Message: "DNS 未返回可用地址，不能确定目的 IP 规则；未访问目标"}
	out.Reason = out.DNS.Message
	v.finish(&out.OfflineResult)
	return out, nil
}
