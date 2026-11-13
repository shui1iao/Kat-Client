package group

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
