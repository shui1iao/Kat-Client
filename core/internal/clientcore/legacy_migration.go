package clientcore

import (
	"context"
	"encoding/json"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"github.com/shui1iao/Kat/internal/provider"
	"gopkg.in/yaml.v3"
	"time"
)

type legacyKey struct{}
type legacyConversion struct {
	Config kernel.ProviderConfig
	Roots  []string
}

// Existing accepted declarations may survive or be removed, never added or
// edited. This is deliberately separate from parseDocument (legacy load).
func legacyDelta(old, next document) *Error {
	a, e := sourceJSON(old)
	if e != nil {
		return nil
	}
	b, e := sourceJSON(next)
	if e != nil {
		return nil
	}
	ak, bk := map[string]json.RawMessage{}, map[string]json.RawMessage{}
	_ = json.Unmarshal(a["kernel"], &ak)
	_ = json.Unmarshal(b["kernel"], &bk)
	if bk["providers"] != nil && ak["providers"] == nil {
		return legacyUnsupported()
	}
	accepted := map[string]json.RawMessage{}
	for _, p := range rawArray(ak, "providers") {
		accepted[rawName(p)] = p
	}
	for _, p := range rawArray(bk, "providers") {
		if !sameJSON(p, accepted[rawName(p)]) {
			return legacyUnsupported()
		}
	}
	groups := map[string]map[string]json.RawMessage{}
	for _, g := range rawArray(ak, "groups") {
		var v map[string]json.RawMessage
		_ = json.Unmarshal(g, &v)
		groups[rawName(g)] = v
	}
	for _, g := range rawArray(bk, "groups") {
		var v map[string]json.RawMessage
		_ = json.Unmarshal(g, &v)
		prior := groups[rawName(g)]
		for _, key := range []string{"use", "include_all_providers"} {
			raw := v[key]
			if raw == nil {
				continue
			}
			if prior[key] == nil {
				return legacyUnsupported()
			}
			if key == "use" {
				var before, after []string
				if json.Unmarshal(prior[key], &before) != nil || json.Unmarshal(raw, &after) != nil {
					return legacyUnsupported()
				}
				cursor := 0
				for _, u := range after {
					for cursor < len(before) && before[cursor] != u {
						cursor++
					}
					if cursor == len(before) {
						return legacyUnsupported()
					}
					cursor++
				}
			} else if string(raw) != "false" && !sameJSON(raw, prior[key]) {
				return legacyUnsupported()
			}
		}
	}
	return nil
}
func legacyUnsupported() *Error {
	return fail("legacy_provider_unsupported", "kernel.providers", "节点订阅已不再支持，请使用完整订阅")
}

// Preview only: native document.apply validates both versions and durably
// snapshots the accepted bytes before any document/network mutation.
func (h *Host) previewLegacy(ctx context.Context, raw json.RawMessage) (any, *Error) {
	var p struct {
		Name string `json:"name"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	h.mu.Lock()
	base := h.doc
	h.mu.Unlock()
	root, _ := sourceJSON(base)
	var k map[string]json.RawMessage
	_ = json.Unmarshal(root["kernel"], &k)
	var pc *kernel.ProviderConfig
	for _, b := range rawArray(k, "providers") {
		var q kernel.ProviderConfig
		if json.Unmarshal(b, &q) == nil && q.Name == p.Name {
			pc = &q
			break
		}
	}
	if pc == nil {
		return nil, fail("invalid_params", "name", "Unknown legacy provider")
	}
	// A non-direct request route cannot be silently replaced by direct. Keep it
	// as a retryable legacy declaration instead of weakening the egress policy.
	if pc.Via != "" && pc.Via != "direct" {
		return nil, fail("legacy_migration_options", "", "现有请求设置无法安全转换，原配置已保留")
	}
	conv := &legacyConversion{Config: *pc}
	ctx = context.WithValue(ctx, legacyKey{}, conv)
	params := map[string]any{"name": pc.Name, "full_only": true}
	if pc.Type == "http" {
		params["url"] = pc.URL
		interval := int(time.Duration(pc.Interval) / time.Second)
		if interval == 0 {
			interval = 3600
		}
		params["interval"] = max(60, min(604800, interval))
	} else {
		b, e := readLegacyFile(pc.Path)
		if e != nil {
			return nil, fail("legacy_migration_fetch", "", "无法读取旧订阅文件，原配置已保留")
		}
		params["text"] = string(b)
	}
	return h.previewSubscription(ctx, rawJSON(params))
}
func readLegacyFile(path string) ([]byte, error) {
	return readSubscriptionResource(path, provider.MaxSize)
}
func legacyFull(b []byte, probe string, c *legacyConversion) (provider.Full, error) {
	if c.Config.DependencyProbeURL != "" {
		probe = c.Config.DependencyProbeURL
	}
	res, e := provider.Parse(b, c.Config.Format)
	if e != nil {
		return provider.Full{}, e
	}
	keep, e := group.MemberFilter(group.Options{Filter: c.Config.Filter, ExcludeFilter: c.Config.ExcludeFilter, ExcludeType: c.Config.ExcludeType})
	if e != nil {
		return provider.Full{}, e
	}
	outs, groups, roots, e := res.Materialize("", probe, nil, keep)
	if e != nil {
		return provider.Full{}, e
	}
	c.Roots = roots
	// A full source retains routes/groups/resources via the established importer.
	// Filtering a graph that still references a dropped declaration fails normal
	// validation rather than silently erasing routes or widening the filter.
	f, e := provider.ParseFull(b, probe)
	if e == nil {
		if c.Config.Filter != "" || c.Config.ExcludeFilter != "" || c.Config.ExcludeType != "" {
			f.Outbounds = outs
		}
		return f, nil
	}
	var header map[string]any
	if yaml.Unmarshal(b, &header) == nil {
		for _, k := range []string{"proxy-groups", "rules", "rule-providers", "proxy-providers"} {
			if _, ok := header[k]; ok {
				return provider.Full{}, e
			}
		}
	}
	// Node-only legacy content becomes a local full snapshot, never falls back to
	// a new provider. Dependency materialization keeps supporting nodes/groups.
	return provider.Full{Outbounds: outs, Groups: groups}, nil
}
func rewriteLegacy(root map[string]json.RawMessage, k map[string]json.RawMessage, sub fullSubscription, c *legacyConversion) error {
	ps := []json.RawMessage{}
	for _, b := range rawArray(k, "providers") {
		if rawName(b) != c.Config.Name {
			ps = append(ps, b)
		}
	}
	if len(ps) == 0 {
		delete(k, "providers")
	} else {
		k["providers"] = rawJSON(ps)
	}
	types := map[string]string{}
	for _, b := range rawArray(k, "outbounds") {
		var o struct{ Name, Type string }
		_ = json.Unmarshal(b, &o)
		types[o.Name] = o.Type
	}
	gs := rawArray(k, "groups")
	for i, b := range gs {
		var g map[string]json.RawMessage
		_ = json.Unmarshal(b, &g)
		var uses, members []string
		var all, allProviders bool
		_ = json.Unmarshal(g["use"], &uses)
		_ = json.Unmarshal(g["members"], &members)
		_ = json.Unmarshal(g["include_all"], &all)
		_ = json.Unmarshal(g["include_all_providers"], &allProviders)
		referenced := all || allProviders
		kept := []string{}
		for _, u := range uses {
			if u == c.Config.Name {
				referenced = true
			} else {
				kept = append(kept, u)
			}
		}
		if !referenced {
			continue
		}
		var opt group.Options
		_ = json.Unmarshal(b, &opt)
		keep, e := group.MemberFilter(opt)
		if e != nil {
			return e
		}
		seen := map[string]bool{}
		for _, n := range members {
			seen[n] = true
		}
		for _, n := range c.Roots {
			mapped := sub.Names[n]
			if mapped != "" && !seen[mapped] && (keep == nil || keep(mapped, types[mapped])) {
				members = append(members, mapped)
				seen[mapped] = true
			}
		}
		g["members"] = rawJSON(members)
		if len(kept) > 0 {
			g["use"] = rawJSON(kept)
		} else {
			delete(g, "use")
		}
		if len(ps) == 0 {
			delete(g, "include_all_providers")
		}
		// Preserve explicit choices where the original dynamic name is unchanged;
		// map the common collision alias to the corresponding accepted full name.
		for _, key := range []string{"selected", "fixed"} {
			var n string
			_ = json.Unmarshal(g[key], &n)
			for original, mapped := range sub.Names {
				if n == original || n == provider.SuffixedName(original, "@"+c.Config.Name) || n == original+"@"+c.Config.Name+".n" {
					g[key] = rawJSON(mapped)
				}
			}
		}
		gs[i] = rawJSON(g)
	}
	k["groups"] = rawJSON(gs)
	root["kernel"] = rawJSON(k)
	return nil
}
