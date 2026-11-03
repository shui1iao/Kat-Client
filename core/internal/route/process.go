package route

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

func normProcessName(s string) (string, bool) {
	if s == "" || len(s) > 255 || !utf8.ValidString(s) || s == "." || s == ".." || strings.TrimSpace(s) != s {
		return "", false
	}
	for _, c := range s {
		if unicode.IsControl(c) || strings.ContainsRune(`\/:*?"<>|`, c) {
			return "", false
		}
	}
	return strings.ToLower(s), true
}

// ProcessUnavailableError means attribution could change the first matching
// rule. It is never a direct fallback and never includes process paths or PIDs.
type ProcessUnavailableError struct {
	Rule   int
	Status string
}

func (e *ProcessUnavailableError) Error() string {
	return fmt.Sprintf("route: process attribution %s at rule %d", e.Status, e.Rule)
}
func safeProcessStatus(s string) string {
	switch s {
	case "ambiguous", "unsupported", "denied", "changed", "closed":
		return s
	}
	return "unknown"
}

// NeedsProcess also examines atomically replaced rule sets. No positive
// attribution or routing outcome is cached here across connections/reloads.
func (e *Engine) NeedsProcess() bool {
	for _, r := range e.rules {
		if condNeedsProcess(r.c) {
			return true
		}
	}
	return false
}
func condNeedsProcess(c *cond) bool {
	if c == nil {
		return false
	}
	switch c.kind {
	case kProcessName:
		return true
	case kRuleSet:
		return dataNeedsProcess(c.set.data.Load())
	case kInline:
		return dataNeedsProcess(c.inline)
	}
	for _, s := range c.subs {
		if condNeedsProcess(s) {
			return true
		}
	}
	return false
}
func dataNeedsProcess(d *setData) bool {
	if d == nil {
		return false
	}
	for _, c := range d.extra {
		if condNeedsProcess(c) {
			return true
		}
	}
	return false
}

// processTri preserves unknown attribution through NOT and uses the same
// three-valued short circuit before and after DNS. Ordinary IP semantics stay
// unchanged (including NOT-IP without an address).
func (e *Engine) processTri(c *cond, q *query, x *ipInfo, beforeDNS bool) int8 {
	switch c.kind {
	case kProcessName:
		if q.processStatus != "known" {
			return triUnknown
		}
		n, ok := normProcessName(q.processName)
		if !ok {
			return triUnknown
		}
		if strings.EqualFold(n, c.s) {
			return triTrue
		}
		return triFalse
	case kAnd, kOr:
		result := triTrue
		decisive := triFalse
		if c.kind == kOr {
			result, decisive = triFalse, triTrue
		}
		unknown := false
		for _, sub := range c.subs {
			v := e.processTri(sub, q, x, beforeDNS)
			if v == decisive {
				return decisive
			}
			unknown = unknown || v == triUnknown
		}
		if unknown {
			return triUnknown
		}
		return result
	case kNot:
		v := e.processTri(c.subs[0], q, x, beforeDNS)
		if v == triUnknown {
			return v
		}
		return 1 - v
	case kRuleSet:
		return e.dataProcessTri(c.set.data.Load(), q, x, beforeDNS, c.noResolve)
	case kInline:
		return e.dataProcessTri(c.inline, q, x, beforeDNS, false)
	}
	if beforeDNS && e.needsIP(c) {
		return triUnknown
	}
	if e.match(c, q, x) {
		return triTrue
	}
	return triFalse
}

func (e *Engine) dataProcessTri(d *setData, q *query, x *ipInfo, beforeDNS, noResolve bool) int8 {
	if d == nil {
		return triFalse
	}
	// Indexed entries contain no process conditions. Evaluate extra entries
	// without losing unknown attribution in the legacy boolean matcher.
	indexed := *d
	indexed.extra = nil
	if indexed.match(e, q, x) {
		return triTrue
	}
	unknown := beforeDNS && !noResolve && indexed.needsIP(e)
	for _, c := range d.extra {
		v := e.processTri(c, q, x, beforeDNS && !noResolve)
		if v == triTrue {
			return triTrue
		}
		unknown = unknown || v == triUnknown
	}
	if unknown {
		return triUnknown
	}
	return triFalse
}

func (q *query) loadProcess() bool {
	if q.processLoaded || q.processLookup == nil {
		return false
	}
	q.processLoaded = true
	q.processName, q.processStatus = q.processLookup()
	return true
}
