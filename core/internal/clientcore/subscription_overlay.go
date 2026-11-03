package clientcore

import (
	"encoding/json"
	"fmt"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"sort"
	"time"
)

// Remote ownership is immutable. Only overlay and selection state describe local edits.
var subscriptionGroupPatchFields = map[string]bool{"type": true, "members": true, "members_add": true, "members_remove": true, "members_order": true, "filter": true, "exclude_filter": true, "include_all": true, "include_group": true, "include_all_proxies": true, "icon": true, "probe": true, "tolerance": true, "damping": true, "smart": true, "strategy": true, "sticky_ttl": true, "lazy": true, "max_failed_times": true, "use": true, "exclude_type": true, "include_all_providers": true}

type subscriptionOverlay struct {
	Groups  map[string]map[string]json.RawMessage `json:"groups,omitempty"`
	Rules   []subscriptionRulePatch               `json:"rules,omitempty"`
	Final   *string                               `json:"final,omitempty"`
	Invalid []string                              `json:"invalid,omitempty"`
}
type subscriptionRulePatch struct {
	Original json.RawMessage `json:"original,omitempty"`
	Value    json.RawMessage `json:"value,omitempty"`
	Deleted  bool            `json:"deleted,omitempty"`
	Disabled bool            `json:"disabled,omitempty"`
	Position int             `json:"position"`
}

func subActive(s fullSubscription) bool { return s.Active == nil || *s.Active }
func boolRef(b bool) *bool              { return &b }
func rawObject(b json.RawMessage) map[string]json.RawMessage {
	m := map[string]json.RawMessage{}
	_ = json.Unmarshal(b, &m)
	return m
}
func sameRawArray(a, b []json.RawMessage) bool { return sameJSON(rawJSON(a), rawJSON(b)) }
func groupState(b json.RawMessage) map[string]json.RawMessage {
	m := rawObject(b)
	out := map[string]json.RawMessage{}
	for _, k := range []string{"selected", "fixed", "priority"} {
		if v := m[k]; v != nil {
			out[k] = v
		}
	}
	return out
}
func groupDiff(remote, current json.RawMessage) map[string]json.RawMessage {
	a, b := rawObject(remote), rawObject(current)
	diff := map[string]json.RawMessage{}
	for _, key := range []string{"selected", "fixed", "priority", "name"} {
		delete(a, key)
		delete(b, key)
	}
	for k, v := range a {
		if k == "probe" && b[k] != nil && string(b[k]) != "null" {
			nested := map[string]json.RawMessage{}
			x, y := rawObject(v), rawObject(b[k])
			for field, old := range x {
				if !sameJSON(old, y[field]) {
					if y[field] == nil {
						nested[field] = rawJSON(nil)
					} else {
						nested[field] = y[field]
					}
				}
			}
			for field, value := range y {
				if x[field] == nil {
					nested[field] = value
				}
			}
			if len(nested) > 0 {
				diff[k] = rawJSON(nested)
			}
			continue
		}
		if k == "members" && b[k] != nil {
			var old, next []string
			_ = json.Unmarshal(v, &old)
			_ = json.Unmarshal(b[k], &next)
			has := func(a []string, n string) bool {
				for _, v := range a {
					if v == n {
						return true
					}
				}
				return false
			}
			added, removed := []string{}, []string{}
			for _, n := range next {
				if !has(old, n) {
					added = append(added, n)
				}
			}
			for _, n := range old {
				if !has(next, n) {
					removed = append(removed, n)
				}
			}
			if len(added) > 0 {
				diff["members_add"] = rawJSON(added)
			}
			if len(removed) > 0 {
				diff["members_remove"] = rawJSON(removed)
			}
			if !sameJSON(v, b[k]) {
				diff["members_order"] = b[k]
			}
			continue
		}
		if !sameJSON(v, b[k]) {
			if b[k] == nil {
				diff[k] = rawJSON(nil)
			} else {
				diff[k] = b[k]
			}
		}
	}
	for k, v := range b {
		if a[k] == nil {
			if k == "members" {
				diff["members_add"] = v
				continue
			}
			diff[k] = v
		}
	}
	return diff
}
func captureSubscriptionLocal(s *fullSubscription, kernel map[string]json.RawMessage, manualRules []json.RawMessage) {
	if s.Overlay.Groups == nil {
		s.Overlay.Groups = map[string]map[string]json.RawMessage{}
	}
	if s.State == nil {
		s.State = map[string]map[string]json.RawMessage{}
	}
	groups := map[string]json.RawMessage{}
	for _, g := range rawArray(kernel, "groups") {
		groups[rawName(g)] = g
	}
	for _, r := range s.Snapshot.Groups {
		name := rawName(r)
		if current := groups[name]; current != nil {
			s.State[name] = groupState(current)
			patch := groupDiff(r, current)
			priorInvalid := false
			for _, entry := range s.Overlay.Invalid {
				priorInvalid = priorInvalid || entry == "group:"+name
			}
			if priorInvalid {
				continue
			}
			if len(patch) == 0 {
				delete(s.Overlay.Groups, name)
			} else {
				s.Overlay.Groups[name] = patch
			}
		} else if s.Model < 2 {
			s.Migration = append(s.Migration, "group_missing_restored")
		}
	}
	routing := rawObject(kernel["routing"])
	current := rawArray(routing, "rules")
	s.RulePositions = nil
	manualUsed := map[int]bool{}
	for _, manual := range manualRules {
		for i, r := range current {
			if !manualUsed[i] && sameJSON(r, manual) {
				manualUsed[i] = true
				break
			}
		}
	}
	for i := range current {
		if !manualUsed[i] {
			s.RulePositions = append(s.RulePositions, i)
		}
	}
	// Remove unchanged manual rules from the comparison. New rules in the active
	// subscription's editor belong to that subscription, including their position.
	for _, manual := range manualRules {
		for i, r := range current {
			if sameJSON(r, manual) {
				current = append(append([]json.RawMessage{}, current[:i]...), current[i+1:]...)
				break
			}
		}
	}
	used := map[int]bool{}
	patches := []subscriptionRulePatch{}
	for i, r := range s.Snapshot.Rules {
		found := -1
		for j, c := range current {
			if !used[j] && sameJSON(r, c) {
				found = j
				break
			}
		}
		if found < 0 {
			patches = append(patches, subscriptionRulePatch{Original: r, Deleted: true, Position: i})
		} else {
			used[found] = true
			if found != i {
				patches = append(patches, subscriptionRulePatch{Original: r, Value: r, Position: found})
			}
		}
	}
	for i, r := range current {
		if !used[i] {
			patches = append(patches, subscriptionRulePatch{Value: r, Position: i})
		}
	}
	// A field edit of one remote rule remains one object patch, not a
	// deletion plus an unrelated insertion, so object-level restore/disable is exact.
	for i := range patches {
		if !patches[i].Deleted {
			continue
		}
		for j := range patches {
			if i != j && len(patches[j].Original) == 0 && len(patches[j].Value) > 0 && patches[j].Position == patches[i].Position {
				patches[i].Value = patches[j].Value
				patches[i].Deleted = false
				patches[j].Value = nil
				break
			}
		}
	}
	compact := []subscriptionRulePatch{}
	for _, p := range patches {
		if len(p.Original) > 0 || len(p.Value) > 0 {
			compact = append(compact, p)
		}
	}
	patches = compact
	// Keep explicitly disabled operations and skipped invalid operations until
	// the user restores/deletes them; a switch must not silently forget them.
	for i, old := range s.Overlay.Rules {
		invalid := false
		for _, entry := range s.Overlay.Invalid {
			invalid = invalid || entry == fmt.Sprintf("rule:%d", i)
		}
		if old.Disabled {
			for j := range patches {
				if sameJSON(patches[j].Original, old.Original) && patches[j].Deleted {
					patches[j] = old
				}
			}
		}
		if invalid {
			patches = append(patches, old)
		}
	}
	s.Overlay.Rules = patches
	var final string
	_ = json.Unmarshal(routing["final"], &final)
	if final != s.Snapshot.Final && s.Snapshot.Final != "" {
		s.Overlay.Final = &final
	} else {
		s.Overlay.Final = nil
	}
}
func validOverlayRefs(raw json.RawMessage, names, sets map[string]bool) bool {
	m := rawObject(raw)
	for _, k := range []string{"members", "members_add"} {
		var a []string
		_ = json.Unmarshal(m[k], &a)
		for _, n := range a {
			if !names[n] {
				return false
			}
		}
	}
	for _, k := range []string{"action", "outbound", "via", "selected", "fixed"} {
		var n string
		_ = json.Unmarshal(m[k], &n)
		if n != "" && !names[n] {
			return false
		}
	}
	var use []string
	_ = json.Unmarshal(m["use"], &use)
	for _, name := range use {
		if !sets["provider:"+name] {
			return false
		}
	}
	for _, key := range []string{"and", "or"} {
		for _, child := range rawArray(m, key) {
			if !validOverlayRefs(child, names, sets) {
				return false
			}
		}
	}
	if child := m["not"]; len(child) > 0 && string(child) != "null" {
		if !validOverlayRefs(child, names, sets) {
			return false
		}
	}
	var set string
	_ = json.Unmarshal(m["rule_set"], &set)
	return set == "" || sets[set]
}
func effectiveSubscription(s *fullSubscription, kernel map[string]json.RawMessage) fullSnapshot {
	snap := s.Snapshot
	snap.Positions = s.RulePositions
	snap.Groups = append([]json.RawMessage{}, snap.Groups...)
	snap.Rules = append([]json.RawMessage{}, snap.Rules...)
	names, sets := map[string]bool{"direct": true, "reject": true}, map[string]bool{}
	for _, a := range [][]json.RawMessage{rawArray(kernel, "outbounds"), rawArray(kernel, "groups"), snap.Outbounds, snap.Groups} {
		for _, v := range a {
			names[rawName(v)] = true
		}
	}
	for _, a := range [][]json.RawMessage{rawArray(kernel, "rule_sets"), snap.RuleSets} {
		for _, v := range a {
			sets[rawName(v)] = true
		}
	}
	for _, provider := range rawArray(kernel, "providers") {
		sets["provider:"+rawName(provider)] = true
	}
	s.Overlay.Invalid = nil
	applied := map[string]bool{}
	for i, g := range snap.Groups {
		name := rawName(g)
		m := rawObject(g)
		if patch := s.Overlay.Groups[name]; len(patch) > 0 {
			for k, v := range patch {
				if k == "members_add" || k == "members_remove" || k == "members_order" {
					continue
				}
				if string(v) == "null" {
					delete(m, k)
				} else if k == "probe" && m[k] != nil {
					merged := rawObject(m[k])
					for field, value := range rawObject(v) {
						if string(value) == "null" {
							delete(merged, field)
						} else {
							merged[field] = value
						}
					}
					m[k] = rawJSON(merged)
				} else {
					m[k] = v
				}
			}
			var members, add, remove, order []string
			_ = json.Unmarshal(m["members"], &members)
			_ = json.Unmarshal(patch["members_add"], &add)
			_ = json.Unmarshal(patch["members_remove"], &remove)
			_ = json.Unmarshal(patch["members_order"], &order)
			has := func(a []string, n string) bool {
				for _, v := range a {
					if v == n {
						return true
					}
				}
				return false
			}
			kept := []string{}
			for _, n := range members {
				if !has(remove, n) {
					kept = append(kept, n)
				}
			}
			for _, n := range add {
				if !has(kept, n) {
					kept = append(kept, n)
				}
			}
			ordered := []string{}
			for _, n := range order {
				if has(kept, n) && !has(ordered, n) {
					ordered = append(ordered, n)
				}
			}
			for _, n := range kept {
				if !has(ordered, n) {
					ordered = append(ordered, n)
				}
			}
			if len(add) > 0 || len(remove) > 0 || len(order) > 0 {
				m["members"] = rawJSON(ordered)
			}

			var candidate group.Options
			err := json.Unmarshal(rawJSON(m), &candidate)
			valid := err == nil
			if valid {
				_, err = group.MemberFilter(candidate)
				valid = err == nil
			}
			if valid && validOverlayRefs(rawJSON(m), names, sets) {
				g = rawJSON(m)
			} else {
				s.Overlay.Invalid = append(s.Overlay.Invalid, "group:"+name)
			}
		}
		applied[name] = true
		m = rawObject(g)
		for k, v := range s.State[name] {
			m[k] = v
		}
		if !validOverlayRefs(rawJSON(m), names, sets) {
			delete(m, "selected")
			delete(m, "fixed")
		}
		var options group.Options
		_ = json.Unmarshal(rawJSON(m), &options)
		// Static weights follow the effective member set. Dynamic names may be
		// temporarily absent and must retain their local per-name preference.
		if !options.Dynamic() {
			var weights map[string]float64
			_ = json.Unmarshal(m["priority"], &weights)
			for n := range weights {
				ok := false
				for _, member := range options.Members {
					ok = ok || n == member
				}
				if !ok {
					delete(weights, n)
				}
			}
			if len(weights) > 0 {
				m["priority"] = rawJSON(weights)
			} else {
				delete(m, "priority")
			}
		}
		memberValid := func(n string) bool {
			if n == "" {
				return true
			}
			for _, v := range options.Members {
				if v == n {
					return true
				}
			}
			if options.Dynamic() {
				matches, e := group.MemberFilter(options)
				if e == nil && matches != nil {
					for _, a := range [][]json.RawMessage{snap.Outbounds, rawArray(kernel, "outbounds")} {
						for _, v := range a {
							node := rawObject(v)
							var name, typ, label string
							_ = json.Unmarshal(node["name"], &name)
							_ = json.Unmarshal(node["type"], &typ)
							_ = json.Unmarshal(node["filter_name"], &label)
							if label == "" {
								label = name
							}
							if n == name && matches(label, typ) {
								return true
							}
						}
					}
				}
			}
			return false
		}
		for _, key := range []string{"selected", "fixed"} {
			var n string
			_ = json.Unmarshal(m[key], &n)
			if !memberValid(n) {
				delete(m, key)
			}
		}
		if options.Type != group.TypeSmart && options.Type != group.TypeURLTest {
			delete(m, "priority")
		}
		snap.Groups[i] = rawJSON(m)
	}
	for name := range s.Overlay.Groups {
		if !applied[name] {
			s.Overlay.Invalid = append(s.Overlay.Invalid, "group:"+name)
		}
	}
	type placed struct {
		rule            json.RawMessage
		position, order int
	}
	placedRules := []placed{}
	for i, r := range snap.Rules {
		placedRules = append(placedRules, placed{r, i, i})
	}
	for i, p := range s.Overlay.Rules {
		idx := -1
		if len(p.Original) > 0 {
			for j, r := range placedRules {
				if sameJSON(r.rule, p.Original) {
					idx = j
					break
				}
			}
			if idx < 0 {
				s.Overlay.Invalid = append(s.Overlay.Invalid, fmt.Sprintf("rule:%d", i))
				continue
			}
		}
		if !p.Deleted && !p.Disabled && !validOverlayRefs(p.Value, names, sets) {
			s.Overlay.Invalid = append(s.Overlay.Invalid, fmt.Sprintf("rule:%d", i))
			continue
		}
		if idx >= 0 {
			placedRules = append(placedRules[:idx], placedRules[idx+1:]...)
		}
		if !p.Deleted && !p.Disabled {
			placedRules = append(placedRules, placed{p.Value, p.Position, i - len(s.Overlay.Rules)})
		}
	}
	sort.SliceStable(placedRules, func(i, j int) bool {
		if placedRules[i].position == placedRules[j].position {
			return placedRules[i].order < placedRules[j].order
		}
		return placedRules[i].position < placedRules[j].position
	})
	snap.Rules = nil
	for _, p := range placedRules {
		snap.Rules = append(snap.Rules, p.rule)
	}
	if s.Overlay.Final != nil {
		if names[*s.Overlay.Final] {
			snap.Final = *s.Overlay.Final
		} else {
			s.Overlay.Invalid = append(s.Overlay.Invalid, "final")
		}
	}
	return snap
}
func detachSubscription(kernel map[string]json.RawMessage, snap fullSnapshot, prior string) (int, error) {
	for _, p := range []struct {
		k string
		v []json.RawMessage
	}{{"outbounds", snap.Outbounds}, {"groups", snap.Groups}, {"rule_sets", snap.RuleSets}} {
		a, e := removeOwned(rawArray(kernel, p.k), p.v, p.k == "groups")
		if e != nil {
			return 0, &subscriptionOwnershipError{Section: p.k, Ordinal: 1}
		}
		kernel[p.k] = rawJSON(a)
	}
	routing := rawObject(kernel["routing"])
	rules := rawArray(routing, "rules")
	pos := len(rules)
	if len(snap.Rules) > 0 {
		positions, err := ownedRulePositions(rules, snap.Rules)
		if err != nil {
			return 0, &subscriptionOwnershipError{Section: "rules", Ordinal: 1}
		}
		pos = positions[0]
		remove := map[int]bool{}
		for _, i := range positions {
			remove[i] = true
		}
		kept := []json.RawMessage{}
		for i, r := range rules {
			if !remove[i] {
				kept = append(kept, r)
			}
		}
		rules = kept
	}
	routing["rules"] = rawJSON(rules)
	if snap.Final != "" {
		if prior == "" {
			prior = "direct"
		}
		routing["final"] = rawJSON(prior)
	}
	kernel["routing"] = rawJSON(routing)
	for k, b := range map[string]json.RawMessage{"geoip": snap.GeoIP, "asn": snap.ASN} {
		if len(b) > 0 {
			delete(kernel, k)
		}
	}
	return pos, nil
}
func attachSubscription(kernel map[string]json.RawMessage, snap fullSnapshot, position int) {
	for _, p := range []struct {
		k string
		v []json.RawMessage
	}{{"outbounds", snap.Outbounds}, {"groups", snap.Groups}, {"rule_sets", snap.RuleSets}} {
		kernel[p.k] = rawJSON(append(rawArray(kernel, p.k), p.v...))
	}
	routing := rawObject(kernel["routing"])
	rules := rawArray(routing, "rules")
	position = max(0, min(position, len(rules)))
	if len(snap.Positions) > 0 {
		for i, r := range snap.Rules {
			at := position + i
			if i < len(snap.Positions) {
				at = snap.Positions[i]
			} else {
				at = snap.Positions[len(snap.Positions)-1] + i - len(snap.Positions) + 1
			}
			at = max(0, min(at, len(rules)))
			rules = append(rules, nil)
			copy(rules[at+1:], rules[at:])
			rules[at] = r
		}
	} else {
		rules = append(append(append([]json.RawMessage{}, rules[:position]...), snap.Rules...), rules[position:]...)
	}
	routing["rules"] = rawJSON(rules)
	if snap.Final != "" {
		routing["final"] = rawJSON(snap.Final)
	}
	kernel["routing"] = rawJSON(routing)
	for k, b := range map[string]json.RawMessage{"geoip": snap.GeoIP, "asn": snap.ASN} {
		if len(b) > 0 {
			kernel[k] = b
		}
	}
}

func manualSubscriptionRules(kernel map[string]json.RawMessage, snap fullSnapshot) []json.RawMessage {
	rules := rawArray(rawObject(kernel["routing"]), "rules")
	if len(snap.Rules) == 0 {
		return rules
	}
	if positions, e := ownedRulePositions(rules, snap.Rules); e == nil {
		owned := map[int]bool{}
		for _, i := range positions {
			owned[i] = true
		}
		manual := []json.RawMessage{}
		for i, r := range rules {
			if !owned[i] {
				manual = append(manual, r)
			}
		}
		return manual
	}
	// Legacy edited blocks have no stable ids. Equal match conditions prove a
	// field edit; otherwise preserve an unmatched rule as manual and report that
	// its old origin cannot be established, rather than guessing from its target.
	out := []json.RawMessage{}
	for _, r := range rules {
		owned := false
		for _, remote := range snap.Rules {
			if sameRuleCondition(r, remote) {
				owned = true
				break
			}
		}
		if !owned {
			out = append(out, r)
		}
	}
	return out
}
func prepareSubscriptionModel(root map[string]json.RawMessage, subs []fullSubscription) ([]fullSubscription, error) {
	kernel := rawObject(root["kernel"])
	legacy := false
	for i := range subs {
		s := &subs[i]
		if s.Model >= 2 {
			continue
		}
		legacy = true
		manual := manualSubscriptionRules(kernel, s.Snapshot)
		if len(s.Snapshot.Rules) > 0 && findRuleBlock(rawArray(rawObject(kernel["routing"]), "rules"), s.Snapshot.Rules) < 0 && len(manual) > 0 {
			s.Migration = append(s.Migration, "rule_origin_unknown_preserved_manual")
		}
		for key, remote := range map[string]json.RawMessage{"geoip": s.Snapshot.GeoIP, "asn": s.Snapshot.ASN} {
			if len(remote) > 0 && !sameJSON(kernel[key], remote) {
				kernel[key] = remote
				s.Migration = append(s.Migration, key+"_difference_discarded")
			}
		}

		captureSubscriptionLocal(s, kernel, manual)
		// Node/provider/database mutations have no supported local overlay.
		// Restore the authoritative declaration and record closed migration codes.
		for _, part := range []struct {
			k      string
			remote []json.RawMessage
		}{{"outbounds", s.Snapshot.Outbounds}, {"rule_sets", s.Snapshot.RuleSets}} {
			values := rawArray(kernel, part.k)
			for _, remote := range part.remote {
				found := false
				for j, value := range values {
					if rawName(value) == rawName(remote) {
						found = true
						if !sameJSON(value, remote) {
							values[j] = remote
							s.Migration = append(s.Migration, part.k+"_difference_discarded")
						}
						break
					}
				}
				if !found {
					values = append(values, remote)
					s.Migration = append(s.Migration, part.k+"_missing_restored")
				}
			}
			kernel[part.k] = rawJSON(values)
		}
		s.Active = boolRef(i == 0)
		s.DownloadMode = "auto"
		s.Model = 2
	}
	if legacy {
		// All former profiles were mixed into one graph. Detach their effective
		// declarations once, then restore only the first profile.
		for i := range subs {
			s := &subs[i]
			snap := effectiveSubscription(s, kernel)
			// Missing legacy groups are restored from remote rather than blocking migration.
			for _, g := range snap.Groups {
				found := false
				for _, v := range rawArray(kernel, "groups") {
					found = found || rawName(g) == rawName(v)
				}
				if !found {
					kernel["groups"] = rawJSON(append(rawArray(kernel, "groups"), g))
				}
			}
			if _, e := detachSubscription(kernel, snap, s.PriorFinal); e != nil {
				return nil, e
			}
		}
		for i := range subs {
			if subActive(subs[i]) {
				attachSubscription(kernel, effectiveSubscription(&subs[i], kernel), len(rawArray(rawObject(kernel["routing"]), "rules")))
			}
		}
		root["kernel"] = rawJSON(kernel)
		root["subscriptions"] = rawJSON(subs)
	}
	return subs, nil
}
func recordSubscriptionEdits(before, after document) (string, error) {
	a, e := sourceJSON(before)
	if e != nil {
		return "", e
	}
	b, e := sourceJSON(after)
	if e != nil {
		return "", e
	}
	old, e := subscriptionsOf(a)
	if e != nil {
		return "", e
	}
	subs, e := subscriptionsOf(b)
	if e != nil {
		return "", e
	}
	kernel := rawObject(b["kernel"])
	previous := rawObject(a["kernel"])
	for i := range subs {
		s := &subs[i]
		if !subActive(*s) {
			continue
		}
		for _, o := range old {
			if o.ID != s.ID {
				continue
			}
			if !sameJSON(rawJSON(o.Overlay), rawJSON(s.Overlay)) {
				continue
			}
			for _, g := range o.Snapshot.Groups {
				present := false
				for _, current := range rawArray(kernel, "groups") {
					present = present || rawName(g) == rawName(current)
				}
				if !present {
					return "", fmt.Errorf("subscription group identity cannot be removed")
				}
			}
			snap := effectiveSubscription(&o, previous)
			manual := manualRulesForEdit(previous, kernel, snap)
			captureSubscriptionLocal(s, kernel, manual)
		}
	}
	b["subscriptions"] = rawJSON(subs)
	subs, e = prepareSubscriptionModel(b, subs)
	if e != nil {
		return "", e
	}
	b["subscriptions"] = rawJSON(subs)
	if len(subs) == 0 && len(old) == 0 {
		return after.text, nil
	}
	return renderSubscriptionSource(after, b)
}
func (h *Host) selectSubscription(raw json.RawMessage) (any, *Error) {
	var p struct {
		ID                string          `json:"id"`
		RestoreGroup      string          `json:"restore_group,omitempty"`
		RestoreRules      bool            `json:"restore_rules,omitempty"`
		RemoveInvalid     string          `json:"remove_invalid,omitempty"`
		EditOnly          bool            `json:"edit_only,omitempty"`
		DeleteID          string          `json:"delete_id,omitempty"`
		RestoreRule       *int            `json:"restore_rule,omitempty"`
		ToggleRule        *int            `json:"toggle_rule,omitempty"`
		DisableRemoteRule *int            `json:"disable_remote_rule,omitempty"`
		EditRule          *int            `json:"edit_rule,omitempty"`
		EditLocalRule     *int            `json:"edit_local_rule,omitempty"`
		AddRule           json.RawMessage `json:"add_rule,omitempty"`
		RulePosition      string          `json:"rule_position,omitempty"`
		RuleValue         json.RawMessage `json:"rule_value,omitempty"`
		DisableEdited     bool            `json:"disable_edited,omitempty"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	base := h.doc
	root, e := sourceJSON(base)
	if e != nil {
		return nil, fail("subscription_conflict", "source", "Cannot read source")
	}
	subs, e := subscriptionsOf(root)
	if e != nil {
		return nil, fail("subscription_conflict", "subscriptions", "Invalid ownership")
	}
	subs, e = prepareSubscriptionModel(root, subs)
	if e != nil {
		return nil, fail("subscription_conflict", "subscriptions", "Cannot migrate ownership")
	}
	kernel := rawObject(root["kernel"])
	position := len(rawArray(rawObject(kernel["routing"]), "rules"))
	target := p.ID
	if p.EditOnly || p.DeleteID != "" {
		for _, s := range subs {
			if subActive(s) {
				target = s.ID
			}
		}
		if target == p.DeleteID {
			target = ""
		}
	}
	if len(p.AddRule) > 0 {
		var rule map[string]json.RawMessage
		if !p.EditOnly || p.ID != target || json.Unmarshal(p.AddRule, &rule) != nil || len(rule) == 0 || (p.RulePosition != "top" && p.RulePosition != "end") {
			return nil, fail("invalid_params", "add_rule", "Expected active subscription rule, edit_only and top/end position")
		}
	} else if p.RulePosition != "" {
		return nil, fail("invalid_params", "rule_position", "Position requires add_rule")
	}
	found := target == ""
	for i := range subs {
		s := &subs[i]
		if subActive(*s) {
			snap := effectiveSubscription(s, kernel)
			manual := manualSubscriptionRules(kernel, snap)
			if s.ID == p.ID && len(p.AddRule) > 0 {
				// Generated connection rules explicitly belong to the active local overlay.
				// Normal "new rule" remains manual. Capture with the PRE-insertion manual
				// set so global top/before-MATCH positions survive subscription refresh.
				routing := rawObject(kernel["routing"])
				rules := rawArray(routing, "rules")
				at := 0
				if p.RulePosition == "end" {
					at = len(rules)
				}
				rules = append(rules, nil)
				copy(rules[at+1:], rules[at:])
				rules[at] = p.AddRule
				routing["rules"] = rawJSON(rules)
				kernel["routing"] = rawJSON(routing)
				captureSubscriptionLocal(s, kernel, manual)
				snap = effectiveSubscription(s, kernel)
			} else {
				captureSubscriptionLocal(s, kernel, manual)
			}
			var err error
			position, err = detachSubscription(kernel, snap, s.PriorFinal)
			if err != nil {
				return nil, subscriptionOwnershipFailure(err)
			}
		}
		s.Active = boolRef(false)
	}
	for i := range subs {
		s := &subs[i]
		if s.ID == target {
			found = true
			s.Active = boolRef(true)
		}
		if s.ID == p.ID {
			if p.RestoreGroup != "" {
				delete(s.Overlay.Groups, p.RestoreGroup)
			}
			if p.RestoreRules {
				s.Overlay.Rules = nil
				s.Overlay.Final = nil
			}
			if p.EditRule != nil || p.EditLocalRule != nil {
				if len(p.RuleValue) == 0 || rawObject(p.RuleValue) == nil {
					return nil, fail("invalid_params", "rule_value", "Expected rule object")
				}
				if p.EditLocalRule != nil {
					n := *p.EditLocalRule
					if n < 0 || n >= len(s.Overlay.Rules) {
						return nil, fail("invalid_params", "edit_local_rule", "Unknown local rule")
					}
					s.Overlay.Rules[n].Value = p.RuleValue
					s.Overlay.Rules[n].Deleted = false
					s.Overlay.Rules[n].Disabled = p.DisableEdited
				} else {
					n := *p.EditRule
					if n < 0 || n >= len(s.Snapshot.Rules) {
						return nil, fail("invalid_params", "edit_rule", "Unknown remote rule")
					}
					original := s.Snapshot.Rules[n]
					found := false
					for i := range s.Overlay.Rules {
						if sameJSON(s.Overlay.Rules[i].Original, original) {
							s.Overlay.Rules[i].Value = p.RuleValue
							s.Overlay.Rules[i].Deleted = false
							s.Overlay.Rules[i].Disabled = p.DisableEdited
							found = true
							break
						}
					}
					if !found {
						s.Overlay.Rules = append(s.Overlay.Rules, subscriptionRulePatch{Original: original, Value: p.RuleValue, Disabled: p.DisableEdited, Position: n})
					}
				}
			}
			if p.RestoreRule != nil {
				n := *p.RestoreRule
				if n < 0 || n >= len(s.Overlay.Rules) {
					return nil, fail("invalid_params", "restore_rule", "Unknown local rule")
				}
				s.Overlay.Rules = append(s.Overlay.Rules[:n], s.Overlay.Rules[n+1:]...)
			}
			if p.ToggleRule != nil {
				n := *p.ToggleRule
				if n < 0 || n >= len(s.Overlay.Rules) {
					return nil, fail("invalid_params", "toggle_rule", "Unknown local rule")
				}
				s.Overlay.Rules[n].Disabled = !s.Overlay.Rules[n].Disabled
			}
			if p.DisableRemoteRule != nil {
				n := *p.DisableRemoteRule
				if n < 0 || n >= len(s.Snapshot.Rules) {
					return nil, fail("invalid_params", "disable_remote_rule", "Unknown remote rule")
				}
				original := s.Snapshot.Rules[n]
				found := false
				for i := range s.Overlay.Rules {
					if sameJSON(s.Overlay.Rules[i].Original, original) {
						s.Overlay.Rules[i].Disabled = true
						found = true
						break
					}
				}
				if !found {
					s.Overlay.Rules = append(s.Overlay.Rules, subscriptionRulePatch{Original: original, Value: original, Disabled: true, Position: n})
				}
			}
			if p.RemoveInvalid != "" {
				if len(p.RemoveInvalid) > 6 && p.RemoveInvalid[:6] == "group:" {
					delete(s.Overlay.Groups, p.RemoveInvalid[6:])
				} else if p.RemoveInvalid == "final" {
					s.Overlay.Final = nil
				} else {
					var n int
					if _, err := fmt.Sscanf(p.RemoveInvalid, "rule:%d", &n); err == nil && n >= 0 && n < len(s.Overlay.Rules) {
						s.Overlay.Rules = append(s.Overlay.Rules[:n], s.Overlay.Rules[n+1:]...)
					}
				}
			}
		}
		if subActive(*s) {
			attachSubscription(kernel, effectiveSubscription(s, kernel), position)
		} else {
			_ = effectiveSubscription(s, kernel)
		}
	}
	if p.DeleteID != "" {
		kept := []fullSubscription{}
		for _, s := range subs {
			if s.ID != p.DeleteID {
				kept = append(kept, s)
			}
		}
		subs = kept
	}
	if !found {
		return nil, fail("invalid_params", "id", "Unknown subscription")
	}
	root["kernel"] = rawJSON(kernel)
	root["subscriptions"] = rawJSON(subs)
	text, e := renderSubscriptionSource(base, root)
	if e != nil {
		return nil, fail("subscription_failed", "source", "Cannot preserve format")
	}
	if _, err := parseDocument(text, h.workspace, base.format); err != nil {
		return nil, fail("apply_failed", "kernel", "切换校验失败，原订阅保持不变")
	}
	token := subscriptionID()
	if h.fullCandidates == nil {
		h.fullCandidates = map[string]*subscriptionPending{}
	}
	pending := &subscriptionPending{Token: token, Base: base.text, Text: text, ID: p.ID, Format: base.format, Created: time.Now()}
	h.fullCandidates["select"] = pending
	h.fullPending = pending
	return subscriptionPreview{Kind: "full", Token: token, Text: text, Format: base.format, ID: p.ID, Counts: map[string]int{}, Changes: []string{}, Issues: []string{}}, nil
}

// The normal "new rule" editor creates a manual rule. Only edits of remote
// rules (or explicit overlay additions) are subscription-local. UI operations
// save one change at a time, so added/deleted/replaced manual rules are exact.
func manualRulesForEdit(previous, next map[string]json.RawMessage, snap fullSnapshot) []json.RawMessage {
	manual := manualSubscriptionRules(previous, snap)
	before := rawArray(rawObject(previous["routing"]), "rules")
	after := rawArray(rawObject(next["routing"]), "rules")
	contains := func(a []json.RawMessage, r json.RawMessage) bool {
		for _, v := range a {
			if sameJSON(v, r) {
				return true
			}
		}
		return false
	}
	if len(after) == len(before) {
		for i, r := range before {
			if contains(manual, r) && !contains(after, r) {
				for j, m := range manual {
					if sameJSON(m, r) {
						manual[j] = after[i]
						break
					}
				}
			}
		}
	}
	if len(after) > len(before) {
		added := []json.RawMessage{}
		for _, r := range after {
			if !contains(before, r) {
				added = append(added, r)
			}
		}
		if len(added) == len(after)-len(before) {
			manual = append(manual, added...)
		}
	}
	return manual
}

func ownedRulePositions(all, owned []json.RawMessage) ([]int, error) {
	positions := []int{}
	used := map[int]bool{}
	for _, r := range owned {
		allCount, ownedCount := 0, 0
		for _, v := range all {
			if sameJSON(r, v) {
				allCount++
			}
		}
		for _, v := range owned {
			if sameJSON(r, v) {
				ownedCount++
			}
		}
		if allCount != ownedCount {
			return nil, fmt.Errorf("ambiguous or missing rule ownership")
		}
		found := -1
		for i, v := range all {
			if !used[i] && sameJSON(r, v) {
				found = i
				break
			}
		}
		if found < 0 {
			return nil, fmt.Errorf("missing rule ownership")
		}
		used[found] = true
		positions = append(positions, found)
	}
	return positions, nil
}

type subscriptionOwnershipError struct {
	Section string
	Ordinal int
}

func (e *subscriptionOwnershipError) Error() string { return "subscription ownership conflict" }
func subscriptionOwnershipFailure(e error) *Error {
	section, ordinal := "graph", 0
	if s, ok := e.(*subscriptionOwnershipError); ok {
		section, ordinal = s.Section, s.Ordinal
	}
	err := fail("subscription_conflict", section, "订阅对象归属冲突，原配置已保留")
	err.Detail = &ResourceDetail{Resource: "subscription", Ordinal: ordinal, Source: "local", Stage: "validate", Category: "invalid_format", Route: "direct"}
	return err
}

func sameRuleCondition(a, b json.RawMessage) bool {
	x, y := rawObject(a), rawObject(b)
	for _, k := range []string{"action", "outbound", "no_resolve"} {
		delete(x, k)
		delete(y, k)
	}
	return sameJSON(rawJSON(x), rawJSON(y))
}
