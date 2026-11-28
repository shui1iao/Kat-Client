package group

import (
	"errors"
	"slices"
)

// MaxGroupDepth bounds nested policy-group chains consistently across document
// validation, static/running target preview, and kernel startup.
const MaxGroupDepth = 8

// ErrGroupDepthExceeded reports a policy-group nesting chain exceeding MaxGroupDepth.
var ErrGroupDepthExceeded = errors.New("group: policy group nesting exceeds MaxGroupDepth")

// PreviewMember returns the reliable read-only member choice of g without
// mutating state, triggering probes, or dialing. If g is an automatic group
// that cannot reliably determine a single node (e.g. cold/unprobed without a
// fixed preference, or load-balance without a fixed preference), it returns "".
func PreviewMember(g Group) string {
	switch x := g.(type) {
	case *selectGroup:
		x.mu.Lock()
		defer x.mu.Unlock()
		if x.sel >= 0 && x.sel < len(x.cfg.members) {
			return x.cfg.members[x.sel]
		}
		return ""
	case *emptyGroup:
		return ""
	case *autoGroup:
		return x.previewMember()
	default:
		if g != nil && g.Type() == TypeSelect {
			return g.Current()
		}
		return ""
	}
}

// PreviewStaticMember returns the reliable static member choice of an unstarted
// group configuration without dialing or probing.
func PreviewStaticMember(o Options) string {
	switch o.Type {
	case TypeSelect:
		if o.Selected != "" && slices.Contains(o.Members, o.Selected) {
			return o.Selected
		}
		if len(o.Members) > 0 {
			return o.Members[0]
		}
	case TypeURLTest, TypeFallback, TypeSmart, TypeLoadBalance:
		if o.Fixed != "" && slices.Contains(o.Members, o.Fixed) {
			return o.Fixed
		}
	}
	return ""
}

// ExpandPolicyChain expands a policy-group chain starting from policy using a
// single authoritative loop and MaxGroupDepth enforcement for both stopped and
// running previews. step returns (chosenMember, true) when name is a group, or
// ("", false) when name is a terminal outbound/built-in leaf.
func ExpandPolicyChain(policy string, step func(name string) (next string, isGroup bool)) ([]string, error) {
	if policy == "" {
		return []string{}, nil
	}
	if policy == "direct" || policy == "reject" {
		return []string{policy}, nil
	}
	chain := []string{policy}
	seen := map[string]bool{policy: true}
	curr := policy
	hops := 0
	for {
		next, isGroup := step(curr)
		if !isGroup {
			return chain, nil
		}
		hops++
		if hops > MaxGroupDepth {
			return nil, ErrGroupDepthExceeded
		}
		if next == "" {
			return chain, nil
		}
		if seen[next] {
			return nil, errors.New("group: policy group cycle")
		}
		seen[next] = true
		chain = append(chain, next)
		curr = next
	}
}

func (g *autoGroup) previewMember() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.cfg.fixed != "" && g.cfg.fixedIndex >= 0 && g.cfg.fixedIndex < len(g.cfg.members) {
		if !g.hasRound || g.previewUpLocked(g.cfg.fixedIndex) {
			return g.cfg.members[g.cfg.fixedIndex]
		}
	}
	if !g.hasRound || g.cold {
		return ""
	}
	switch g.cfg.kind {
	case TypeURLTest, TypeSmart:
		if g.cur >= 0 && g.cur < len(g.cfg.members) && g.previewUpLocked(g.cur) {
			return g.cfg.members[g.cur]
		}
	case TypeFallback:
		for i := range g.st {
			if g.previewUpLocked(i) {
				return g.cfg.members[i]
			}
		}
	case TypeLoadBalance:
		return ""
	}
	return ""
}

func (g *autoGroup) previewUpLocked(i int) bool {
	if i < 0 || i >= len(g.st) {
		return false
	}
	s := &g.st[i]
	limit := g.cfg.maxFailed
	if limit == 0 {
		limit = 1
	}
	return (!s.probed || s.probeOK) && s.consec < limit && s.recovery.ready(g.clk.Now())
}
