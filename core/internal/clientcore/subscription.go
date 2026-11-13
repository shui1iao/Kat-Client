package clientcore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/oschwald/maxminddb-golang"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"github.com/shui1iao/Kat/internal/userio"
	"net"
	"os"
	"runtime"

	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shui1iao/Kat/internal/clientegress"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/provider"
	"github.com/shui1iao/Kat/internal/route"
	"gopkg.in/yaml.v3"
)

// A subscription owns only its last accepted declarations and ordered rule
// block. Exact snapshots prevent a refresh from erasing later manual edits.
// URL and node credentials stay in the normal private user source, never logs.
type fullSubscription struct {
	Model          int                                   `json:"model,omitempty"`
	Active         *bool                                 `json:"active,omitempty"`
	Overlay        subscriptionOverlay                   `json:"overlay,omitempty"`
	RulePositions  []int                                 `json:"rule_positions,omitempty"`
	State          map[string]map[string]json.RawMessage `json:"state,omitempty"`
	Migration      []string                              `json:"migration,omitempty"`
	UserInfo       *subscriptionUserInfo                 `json:"userinfo,omitempty"`
	ServerInterval int                                   `json:"server_interval,omitempty"`
	FollowInterval bool                                  `json:"follow_interval,omitempty"`
	DownloadMode   string                                `json:"download_mode,omitempty"`
	LastRoute      string                                `json:"last_route,omitempty"`
	Resources      map[string]subscriptionLocal          `json:"resources,omitempty"`
	ID             string                                `json:"id"`
	Name           string                                `json:"name"`
	URL            string                                `json:"url,omitempty"`
	UseSystemProxy bool                                  `json:"use_system_proxy,omitempty"`
	AutoUpdate     *bool                                 `json:"auto_update,omitempty"`
	Interval       int                                   `json:"interval"`
	Updated        int64                                 `json:"updated"`
	Names          map[string]string                     `json:"names"`
	SetNames       map[string]string                     `json:"set_names"`
	Snapshot       fullSnapshot                          `json:"snapshot"`
	SourceOptions  *kernel.ProviderConfig                `json:"source_options,omitempty"`
	PriorFinal     string                                `json:"prior_final,omitempty"`
}
type fullSnapshot struct {
	Outbounds []json.RawMessage `json:"outbounds"`
	Groups    []json.RawMessage `json:"groups"`
	Rules     []json.RawMessage `json:"rules"`
	RuleSets  []json.RawMessage `json:"rule_sets"`
	Final     string            `json:"final,omitempty"`
	Positions []int             `json:"-"`
	GeoIP     json.RawMessage   `json:"geoip,omitempty"`
	ASN       json.RawMessage   `json:"asn,omitempty"`
}
type subscriptionPending struct {
	Token, Base, Text, Dir string
	ID                     string
	Format                 DocumentFormat
	Refresh                bool
	Created                time.Time
}
type subscriptionPreview struct {
	Token             string         `json:"token,omitempty"`
	Text              string         `json:"text,omitempty"`
	Format            DocumentFormat `json:"format,omitempty"`
	ID                string         `json:"id,omitempty"`
	Counts            map[string]int `json:"counts"`
	Changes           []string       `json:"changes"`
	Issues            []string       `json:"issues"`
	NeedsConfirmation bool           `json:"needs_confirmation"`
	Items             map[string]any `json:"items"`
	Kind              string         `json:"kind"`
	NodeImport        any            `json:"node_import,omitempty"`
}

const subscriptionGeoURL = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb"
const subscriptionASNURL = "https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb"

func rawJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
func sameJSON(a, b []byte) bool {
	var x, y any
	return json.Unmarshal(a, &x) == nil && json.Unmarshal(b, &y) == nil && reflect.DeepEqual(x, y)
}
func rawName(b []byte) string {
	var n struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(b, &n)
	return n.Name
}
func rawArray(m map[string]json.RawMessage, k string) []json.RawMessage {
	a := []json.RawMessage{}
	_ = json.Unmarshal(m[k], &a)
	return a
}
func sourceJSON(d document) (map[string]json.RawMessage, error) {
	b := []byte(d.text)
	if d.format != FormatJSON {
		var e error
		b, e = yamlJSON(b)
		if e != nil {
			return nil, e
		}
	}
	var m map[string]json.RawMessage
	e := json.Unmarshal(b, &m)
	return m, e
}
func subscriptionsOf(root map[string]json.RawMessage) ([]fullSubscription, error) {
	var s []fullSubscription
	if b := root["subscriptions"]; b != nil {
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if d.Decode(&s) != nil || len(s) > 16 {
			return nil, errors.New("invalid subscription ownership")
		}
	}
	seen := map[string]bool{}
	active := 0
	for _, v := range s {
		if v.Model != 0 && v.Model != 2 {
			return nil, errors.New("invalid subscription model")
		}
		if v.Model == 2 && subActive(v) {
			active++
		}
		if active > 1 {
			return nil, errors.New("multiple active subscriptions")
		}
		if v.DownloadMode != "" && v.DownloadMode != "auto" && v.DownloadMode != "direct" && v.DownloadMode != "proxy" {
			return nil, errors.New("invalid download mode")
		}
		for _, patch := range v.Overlay.Groups {
			for key := range patch {
				if !subscriptionGroupPatchFields[key] {
					return nil, errors.New("invalid overlay group field")
				}
			}
		}
		if v.ServerInterval < 0 || v.ServerInterval > 2592000 || len(v.Overlay.Rules) > 10000 || len(v.Overlay.Groups) > 1000 {
			return nil, errors.New("invalid subscription metadata")
		}
		if v.UserInfo != nil {
			u := v.UserInfo
			if u.Upload+u.Download > 1<<53-1 || u.Upload > 1<<53-1 || u.Download > 1<<53-1 || u.Total != nil && *u.Total > 1<<53-1 || u.Expire != nil && (*u.Expire < 1 || *u.Expire > 1<<53-1) {
				return nil, errors.New("invalid subscription userinfo")
			}
		}

		if len(v.ID) != 32 || seen[v.ID] || v.Interval < 60 || v.Interval > 2592000 {
			return nil, errors.New("invalid subscription ownership")
		}
		if _, e := hex.DecodeString(v.ID); e != nil {
			return nil, e
		}
		seen[v.ID] = true
	}
	return s, nil
}
func subscriptionID() string { var b [16]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }
func (h *Host) cancelSubscription(raw json.RawMessage) (any, *Error) {
	var p struct {
		Token string `json:"token"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, pending := range h.fullCandidates {
		if pending.Token == p.Token {
			h.expireFullPendingLocked(pending)
			if pending.Dir != "" {
				userio.RemoveAll(pending.Dir)
			}
			delete(h.fullCandidates, id)
			if h.fullPending == pending {
				h.fullPending = nil
			}
		}
	}
	return map[string]any{"canceled": true}, nil
}
func (h *Host) clearFullPendingLocked() {
	for id, p := range h.fullCandidates {
		if p.Dir != "" {
			userio.RemoveAll(p.Dir)
		}
		delete(h.fullCandidates, id)
	}
	if h.fullPending != nil {
		if h.fullPending.Dir != "" {
			userio.RemoveAll(h.fullPending.Dir)
		}
		h.fullPending = nil
	}
}

func (h *Host) previewSubscription(ctx context.Context, raw json.RawMessage) (any, *Error) {
	var p struct {
		Text           *string          `json:"text"`
		URL            string           `json:"url"`
		ID             string           `json:"id"`
		Name           string           `json:"name"`
		Interval       int              `json:"interval"`
		UseSystemProxy *bool            `json:"use_system_proxy,omitempty"`
		AutoUpdate     *bool            `json:"auto_update,omitempty"`
		FollowInterval *bool            `json:"follow_interval,omitempty"`
		DownloadMode   string           `json:"download_mode,omitempty"`
		FullOnly       bool             `json:"full_only"`
		Proxy          *bootstrapProxy  `json:"_system_proxy,omitempty"`
		ResourceProxy  *bootstrapProxy  `json:"_resource_proxy,omitempty"`
		Expected       *bootstrapEgress `json:"_egress,omitempty"`
	}
	if e := decodeParams(raw, &p); e != nil {
		return nil, e
	}
	h.mu.Lock()
	h.syncTUNEgressLocked()
	if !h.hostEgressReadyLocked() {
		h.mu.Unlock()
		return nil, resourceError(ctx, "subscription", 0, "download", "connect", "egress_unavailable", nil)
	}
	base := h.doc
	policy := h.egress
	generation := h.egressGeneration
	var bootstrapLife context.Context
	availableProxy := p.Proxy
	if availableProxy == nil {
		availableProxy = p.ResourceProxy
	}
	if availableProxy != nil {
		if p.Expected != nil && (p.Expected.Generation != h.egressGeneration || p.Expected.Enabled != (h.egress != nil)) || h.egress != nil && !h.egress.Ready() {
			h.mu.Unlock()
			return nil, resourceError(context.WithValue(ctx, bootstrapKey{}, availableProxy), "subscription", 0, "download", "connect", "egress_unavailable", nil)
		}
	}
	// All routes (including ordinary nil-policy direct and kernel fallback)
	// share this lifecycle, not only requests carrying a Windows proxy hint.
	var stop func()
	ctx, stop = h.bootstrapContextLocked(ctx)
	bootstrapLife = h.bootstrapLife
	defer stop()
	root, e := sourceJSON(base)
	dynamicNames := []string{}
	written := map[string]bool{}
	for _, o := range base.config.Outbounds {
		written[o.Name] = true
	}
	for _, g := range base.config.Groups {
		written[g.Name] = true
	}
	if h.server != nil {
		current := h.server.CurrentConfig()
		for _, o := range current.Outbounds {
			if !written[o.Name] {
				dynamicNames = append(dynamicNames, o.Name)
			}
		}
		for _, g := range current.Groups {
			if !written[g.Name] {
				dynamicNames = append(dynamicNames, g.Name)
			}
		}
	}
	h.mu.Unlock()
	if e != nil {
		return nil, fail("subscription_failed", "source", "Cannot read accepted source")
	}
	subs, e := subscriptionsOf(root)
	if e != nil {
		return nil, fail("subscription_conflict", "subscriptions", "Invalid subscription ownership")
	}
	subs, e = prepareSubscriptionModel(root, subs)
	if e != nil {
		return nil, fail("subscription_conflict", "subscriptions", "Cannot migrate subscription ownership")
	}
	var old *fullSubscription
	for i := range subs {
		if subs[i].ID == p.ID || (p.ID == "" && p.URL != "" && subs[i].URL == p.URL) {
			v := subs[i]
			old = &v
			p.ID = v.ID
		}
	}
	if p.ID != "" && old == nil {
		return nil, fail("subscription_conflict", "subscriptions", "Unknown subscription")
	}
	conversion, _ := ctx.Value(legacyKey{}).(*legacyConversion)
	migrating := conversion != nil
	if conversion == nil && old != nil && old.SourceOptions != nil {
		conversion = &legacyConversion{Config: *old.SourceOptions}
		ctx = context.WithValue(ctx, legacyKey{}, conversion)
	}
	if old != nil && p.Text == nil && p.URL == "" {
		p.URL = old.URL
	}
	if (p.Text == nil) == (p.URL == "") {
		return nil, fail("invalid_params", "subscription", "Exactly one text or HTTPS URL required")
	}
	if p.URL != "" && !validImportURL(p.URL) {
		return nil, fail("invalid_params", "subscription", "Expected public HTTPS URL")
	}
	if p.Proxy != nil {
		if !validBootstrap(p.Proxy) {
			return nil, resourceError(ctx, "subscription", 0, "download", "proxy_connect", "proxy_unsupported", nil)
		}
		ctx = context.WithValue(ctx, bootstrapKey{}, p.Proxy)
	}
	ctx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	var b []byte
	if p.Text != nil {
		b = []byte(*p.Text)
	} else {
		meta := &subscriptionHeaders{}
		ctx = context.WithValue(ctx, subscriptionHeadersKey{}, meta)
		mode, last := "auto", ""
		if old != nil {
			mode = old.DownloadMode
			last = old.LastRoute
		}
		if p.DownloadMode != "" {
			mode = p.DownloadMode
		}
		var route string
		b, route, e = h.fetchMainSubscription(ctx, p.URL, policy, provider.MaxSize, mode, last, availableProxy)
		if e == nil {
			ctx = context.WithValue(ctx, mainRouteKey{}, route)
		}
		if e != nil {
			return nil, resourceError(ctx, "subscription", 0, "download", "connect", "unknown", e)
		}
	}
	// Classify once after a URL fetch. Native source and node URI imports retain
	// their old staging/append behavior; full Clash never falls back on an error.
	// Inspect root key nodes before decoding values. If strict YAML projection
	// rejects aliases/duplicates, a full policy MUST NOT fall back to nodes-only.
	keys := map[string]bool{}
	var header yaml.Node
	if yaml.Unmarshal(b, &header) == nil && len(header.Content) == 1 && header.Content[0].Kind == yaml.MappingNode {
		n := header.Content[0]
		for i := 0; i+1 < len(n.Content); i += 2 {
			keys[n.Content[i].Value] = true
		}
	}
	if keys["schema_version"] && keys["client"] && keys["kernel"] {
		if p.FullOnly {
			return nil, fail("subscription_native_config", "subscription", "Native configuration belongs to the configuration draft workflow")
		}
		format := FormatYAML
		if strings.HasPrefix(strings.TrimSpace(string(b)), "{") {
			format = FormatJSON
		}
		// Native drafts otherwise keep their existing deferred-validation workflow.
		// Only this unsafe legacy combination is refused before returning a draft.
		if _, err := parseDocument(string(b), h.workspace, format); err != nil && err.Code == "legacy_smart_subscription_unsupported" {
			return nil, err
		}
		return subscriptionPreview{Kind: "native", Text: string(b), Format: format, Counts: map[string]int{}, Changes: []string{"Kat原生配置仅载入草稿，保存后才生效"}, Issues: []string{}}, nil
	}
	full := false
	for _, k := range []string{"proxies", "proxy-groups", "rules", "rule-providers", "proxy-providers"} {
		full = full || keys[k]
	}
	if !full && old == nil && conversion == nil {
		if p.FullOnly {
			return nil, fail("subscription_format_unsupported", "subscription", "A complete Clash configuration is required")
		}
		v, e := h.importParse(ctx, rawJSON(map[string]string{"text": string(b)}))
		if e != nil {
			return nil, e
		}
		return subscriptionPreview{Kind: "nodes", NodeImport: v, Counts: map[string]int{}, Changes: []string{"仅节点格式：沿用原节点合入流程"}, Issues: []string{}}, nil
	}
	f, e := provider.ParseFull(b, base.client.ProbeURL)
	if conversion != nil {
		f, e = legacyFull(b, base.client.ProbeURL, conversion)
	}
	preview := subscriptionPreview{Kind: "full", Counts: map[string]int{}, Changes: []string{}, Issues: []string{}}
	if e != nil {
		msg := "配置不是受支持的完整 Clash YAML"
		if se, ok := e.(*provider.FullError); ok {
			msg = fmt.Sprintf("不支持的配置：%s 第 %d 项（%s）", se.Section, se.Index+1, se.Code)
		}
		if p.FullOnly {
			section := "subscription"
			ordinal := 0
			if se, ok := e.(*provider.FullError); ok {
				section = se.Section
				ordinal = se.Index + 1
			}
			err := fail("subscription_format_unsupported", section, "配置格式不受支持")
			err.Detail = &ResourceDetail{Resource: "subscription", Ordinal: ordinal, Source: "download", Stage: "format_check", Category: "invalid_format", Route: "direct"}
			return nil, err
		}
		preview.Issues = append(preview.Issues, msg)
		return preview, nil
	}
	// Validate the isolated graph before any network resource request. Paths are
	// temporary placeholders solely for static validation, never read or trusted.

	interval := 86400
	id := subscriptionID()
	name := "完整配置 " + id[:6]
	if old != nil {
		id = old.ID
		name = old.Name
		interval = old.Interval
	}
	if p.Name == "" && (old == nil || defaultFullSubscriptionNameRx.MatchString(old.Name)) {
		if n := subscriptionName(ctx, p.URL); n != "" {
			name = n
		}
	}
	if p.Name != "" {
		if len([]byte(p.Name)) > 128 || strings.ContainsAny(p.Name, "\r\n\x00") {
			return nil, fail("invalid_params", "name", "订阅名称无效")
		}
		name = p.Name
	}
	if p.Interval != 0 {
		if p.Interval < 60 || p.Interval > 2592000 {
			return nil, fail("invalid_params", "interval", "刷新间隔须为60至2592000秒")
		}
		interval = p.Interval
	}
	subURL := p.URL
	if old != nil && p.Text != nil {
		subURL = old.URL
	}
	sub := fullSubscription{ID: id, Name: name, URL: subURL, Interval: interval, Updated: time.Now().Unix(), Names: map[string]string{}, SetNames: map[string]string{}}
	if old != nil {
		sub.UseSystemProxy = old.UseSystemProxy
		sub.UserInfo = old.UserInfo
		sub.ServerInterval = old.ServerInterval
		sub.FollowInterval = old.FollowInterval
		sub.DownloadMode = old.DownloadMode
		sub.LastRoute = old.LastRoute
		sub.AutoUpdate = old.AutoUpdate
	}
	if p.UseSystemProxy != nil {
		sub.UseSystemProxy = *p.UseSystemProxy
	}
	if p.AutoUpdate != nil {
		sub.AutoUpdate = p.AutoUpdate
	}
	if sub.DownloadMode == "" {
		sub.DownloadMode = "auto"
	}
	if p.DownloadMode != "" {
		if p.DownloadMode != "auto" && p.DownloadMode != "direct" && p.DownloadMode != "proxy" {
			return nil, fail("invalid_params", "download_mode", "Invalid download mode")
		}
		sub.DownloadMode = p.DownloadMode
	}
	if p.FollowInterval != nil {
		sub.FollowInterval = *p.FollowInterval
	}
	if meta, ok := ctx.Value(subscriptionHeadersKey{}).(*subscriptionHeaders); ok {
		sub.UserInfo = parseSubscriptionUserInfo(meta.userinfo)
		sub.ServerInterval = parseSubscriptionInterval(meta.updateInterval)
	}
	if route, ok := ctx.Value(mainRouteKey{}).(string); ok {
		sub.LastRoute = route
	}
	if sub.FollowInterval && sub.ServerInterval > 0 {
		sub.Interval = sub.ServerInterval
	}
	if conversion != nil {
		q := conversion.Config
		sub.SourceOptions = &q
	}
	var kernelRaw map[string]json.RawMessage
	_ = json.Unmarshal(root["kernel"], &kernelRaw)
	if kernelRaw == nil {
		return nil, fail("subscription_failed", "kernel", "Invalid accepted kernel")
	}
	// Node-only subscriptions at the very same URL are explicitly upgraded, not
	// silently retained as a duplicate graph. Other providers remain untouched.
	ps := rawArray(kernelRaw, "providers")
	kept := []json.RawMessage{}
	for _, x := range ps {
		var q kernel.ProviderConfig
		_ = json.Unmarshal(x, &q)
		if !migrating && old == nil && p.URL != "" && q.Type == "http" && q.URL == p.URL {
			preview.Changes = append(preview.Changes, "同链接节点订阅将转换为完整配置订阅（其它订阅不变）")
			if q.Interval != 0 {
				sub.Interval = max(60, min(2592000, int(time.Duration(q.Interval)/time.Second)))
			}
			continue
		}
		kept = append(kept, x)
	}
	if len(kept) != len(ps) {
		kernelRaw["providers"] = rawJSON(kept)
	}
	// Only the active profile is projected into the runtime graph.
	insert := -1
	if old != nil && subActive(*old) {
		snap := effectiveSubscription(old, kernelRaw)
		var err error
		insert, err = detachSubscription(kernelRaw, snap, old.PriorFinal)
		if err != nil {
			return nil, subscriptionOwnershipFailure(err)
		}
	}
	var routing map[string]json.RawMessage
	_ = json.Unmarshal(kernelRaw["routing"], &routing)
	if routing == nil {
		routing = map[string]json.RawMessage{}
	}
	rules := rawArray(routing, "rules")
	if insert < 0 {
		insert = len(rules)
	}
	sub.Model = 2
	sub.Active = boolRef(len(subs) == 0)
	if old != nil {
		sub.Active = old.Active
		sub.Overlay = old.Overlay
		sub.State = old.State
		sub.RulePositions = old.RulePositions
		sub.Migration = old.Migration
		sub.PriorFinal = old.PriorFinal
	}
	occupied := map[string]bool{"direct": true, "reject": true}
	for _, n := range dynamicNames {
		owned := false
		if migrating {
			for _, name := range conversion.Roots {
				if n == name {
					owned = true
				}
			}
		}
		if !owned {
			occupied[n] = true
		}
	}
	for _, k := range []string{"outbounds", "groups"} {
		for _, v := range rawArray(kernelRaw, k) {
			occupied[rawName(v)] = true
		}
	}
	allocate := func(original string, previous map[string]string, taken map[string]bool) string {
		n := safeSubscriptionName(original)
		if previous != nil && previous[original] != "" {
			n = previous[original]
		}
		baseName := n
		for i := 0; taken[n]; i++ {
			n = fmt.Sprintf("%s@%s-%d", baseName, id[:6], i+1)
		}
		taken[n] = true
		return n
	}
	oldNames := map[string]string{}
	oldSets := map[string]string{}
	if old != nil {
		oldNames = old.Names
		oldSets = old.SetNames
	}
	for _, o := range f.Outbounds {
		sub.Names[o.Name] = allocate(o.Name, oldNames, occupied)
	}
	for _, g := range f.Groups {
		sub.Names[g.Name] = allocate(g.Name, oldNames, occupied)
	}
	remap := func(n string) string {
		if n == "" || n == "direct" || n == "reject" {
			return n
		}
		if mapped, ok := sub.Names[n]; ok {
			return mapped
		}
		return n
	}
	setTaken := map[string]bool{}
	for _, r := range rawArray(kernelRaw, "rule_sets") {
		setTaken[rawName(r)] = true
	}
	for _, s := range f.RuleSets {
		sub.SetNames[s.Name] = allocate(s.Name, oldSets, setTaken)
	}
	for i := range f.Outbounds {
		o := &f.Outbounds[i]
		original := o.Name
		o.Name = remap(o.Name)
		if o.Name != original {
			o.FilterName = original
		}
		o.Via = remap(o.Via)
	}
	remoteGroups := map[string]json.RawMessage{}
	selectionChanged := false
	oldGroups := map[string]json.RawMessage{}
	if old != nil {
		for _, g := range old.Snapshot.Groups {
			oldGroups[rawName(g)] = g
		}
		for name, state := range old.State {
			oldGroups[name] = rawJSON(state)
		}
	}
	for i := range f.Groups {
		g := &f.Groups[i]
		g.Name = remap(g.Name)
		g.IncludeGroup = remap(g.IncludeGroup)
		for j, m := range g.Members {
			g.Members[j] = remap(m)
		}
		g.Fixed = remap(g.Fixed)
		if g.Priority != nil {
			weights := map[string]float64{}
			for name, weight := range g.Priority {
				weights[remap(name)] = weight
			}
			g.Priority = weights
		}
		remoteGroups[g.Name] = rawJSON(g)
		if prev := oldGroups[g.Name]; prev != nil {
			var q struct {
				Selected string             `json:"selected"`
				Fixed    string             `json:"fixed"`
				Priority map[string]float64 `json:"priority"`
			}
			_ = json.Unmarshal(prev, &q)
			// Source overlays and their separate State are applied together below.
			// Do not copy dynamic preferences into a still-static remote graph:
			// that would either drop them or fail validation before the overlay.
			var localSource string
			if old != nil {
				_ = json.Unmarshal(old.Overlay.Groups[g.Name]["include_group"], &localSource)
			}
			if localSource != "" {
				continue
			}
			// User weights belong to stable internal IDs, not the refreshed source.
			if g.Type == group.TypeURLTest || g.Type == group.TypeSmart {
				g.Priority = map[string]float64{}
				for member, weight := range q.Priority {
					valid := g.Dynamic()
					for _, m := range g.Members {
						valid = valid || m == member
					}
					if valid {
						g.Priority[member] = weight
					} else {
						preview.Changes = append(preview.Changes, "已移除失效成员权重："+member)
					}
				}
			}
			foundSelected, foundFixed := q.Selected == "", q.Fixed == ""
			if g.Dynamic() {
				matches, _ := group.MemberFilter(*g)
				preserve := func(name, label, typ string) {
					if matches != nil && matches(label, typ) {
						if q.Selected == name {
							g.Selected = q.Selected
							foundSelected = true
						}
						if q.Fixed == name {
							g.Fixed = q.Fixed
							foundFixed = true
						}
					}
				}
				for _, n := range f.Outbounds {
					preserve(n.Name, n.FilterLabel(), n.Type)
				}
				// Other accepted manual/subscription nodes also join include_all. Preserve
				// explicit choices iff the node still exists and matches after refresh.
				for _, raw := range rawArray(kernelRaw, "outbounds") {
					var n struct {
						Name       string `json:"name"`
						Type       string `json:"type"`
						FilterName string `json:"filter_name"`
					}
					_ = json.Unmarshal(raw, &n)
					label := n.FilterName
					if label == "" {
						label = n.Name
					}
					preserve(n.Name, label, n.Type)
				}
			}
			for _, m := range g.Members {
				if q.Selected == m {
					g.Selected = m
					foundSelected = true
				}
				if q.Fixed == m {
					g.Fixed = m
					foundFixed = true
				}
			}
			if !foundSelected || !foundFixed {
				selectionChanged = true
				preview.Changes = append(preview.Changes, "组内手动选择的成员已移除，接纳后将使用新组可用成员："+g.Name)
			}
		}
	}
	for i := range f.Rules {
		r := &f.Rules[i]
		r.Outbound = remap(r.Outbound)
		if r.RuleSet != "" {
			if mapped, ok := sub.SetNames[r.RuleSet]; ok {
				r.RuleSet = mapped
			}
		}
	}
	f.Final = remap(f.Final)
	for i := range f.RuleSets {
		f.RuleSets[i].Name = sub.SetNames[f.RuleSets[i].Name]
	}
	if e = validateFullGraph(f, h.workspace); e != nil {
		if p.FullOnly {
			return nil, fail("subscription_conflict", "graph", "订阅图引用校验失败，原配置已保留")
		}
		preview.Issues = append(preview.Issues, "配置校验未通过："+quotedNameRx.ReplaceAllString(e.Error(), "[名称]"))
		return preview, nil
	}
	for from, to := range sub.Names {
		if from != to {
			preview.Changes = append(preview.Changes, "重名/长度限制："+from+" → "+to)
		}
	}
	for from, to := range sub.SetNames {
		if from != to {
			preview.Changes = append(preview.Changes, "规则集重名："+from+" → "+to)
		}
	}
	preview.Items = subscriptionItems(f)
	preview.Counts = map[string]int{"nodes": len(f.Outbounds), "groups": len(f.Groups), "rules": len(f.Rules), "rule_sets": len(f.RuleSets), "match": 0}
	if f.Final != "" {
		preview.Counts["match"] = 1
	}
	// Candidate resource content stays in memory until ALL references/formats
	// and required databases pass. Never reuse remote-provided cache paths.
	// The main file retains its saved download mode. Only dependencies choose
	// the already-running kernel; stopped imports retain their saved route.
	h.mu.Lock()
	resourcesViaKernel := h.server != nil
	h.mu.Unlock()
	ctx = context.WithValue(ctx, resourceKernelKey{}, resourcesViaKernel)
	if p.ResourceProxy != nil {
		if !validBootstrap(p.ResourceProxy) {
			return nil, resourceError(ctx, "resource_stage", 0, "download", "proxy_connect", "proxy_unsupported", nil)
		}
		ctx = context.WithValue(ctx, resourceProxyKey{}, p.ResourceProxy)
	}
	data := map[string][]byte{}
	localSources := map[string]struct {
		URL      string
		Updated  int64
		Interval int64
	}{}
	total := 0
	for i := range f.RuleSets {
		rs := &f.RuleSets[i]
		if !validImportURL(rs.URL) {
			return nil, resourceError(ctx, "rule_set", i+1, "download", "url_check", "address_refused", nil)
		}
		content, updated, err := h.subscriptionResource(ctx, old, rs.URL, rs.Interval.Value(), policy, 16<<20)
		if err != nil {
			return nil, resourceError(ctx, "rule_set", i+1, "download", "connect", "unknown", err)
		}
		total += len(content)
		if total > 96<<20 {
			return nil, resourceError(ctx, "rule_set", i+1, "download", "body_read", "total_size_limit", nil)
		}
		country, asn, err := subscriptionSetNeeds(*rs, content)
		if err != nil {
			return nil, resourceError(ctx, "rule_set", i+1, "download", "dependency_scan", "invalid_format", nil)
		}
		f.NeedsGeoIP = f.NeedsGeoIP || country
		f.NeedsASN = f.NeedsASN || asn
		data[fmt.Sprintf("set-%d", i)] = content
		localSources[fmt.Sprintf("set-%d", i)] = struct {
			URL      string
			Updated  int64
			Interval int64
		}{rs.URL, updated, int64(rs.Interval.Value() / time.Second)}
	}
	for _, res := range []struct {
		key, url, file string
		needed         bool
	}{{"geoip", subscriptionGeoURL, "country.mmdb", f.NeedsGeoIP}, {"asn", subscriptionASNURL, "asn.mmdb", f.NeedsASN}} {
		if !res.needed {
			continue
		}
		var content []byte
		var err error
		ownedDB := false
		if old != nil {
			var prior json.RawMessage
			if res.key == "geoip" {
				prior = old.Snapshot.GeoIP
			} else {
				prior = old.Snapshot.ASN
			}
			ownedDB = len(prior) > 0 && sameJSON(prior, kernelRaw[res.key]) && old.Resources[res.url].Path != ""
		}
		if b := kernelRaw[res.key]; b != nil && !ownedDB {
			var g route.GeoIPOptions
			if json.Unmarshal(b, &g) != nil {
				return nil, resourceError(ctx, res.key, 0, "local", "local_read", "invalid_format", nil)
			}
			content, err = readSubscriptionResource(g.Path, 64<<20)
		} else {
			var updated int64
			content, updated, err = h.subscriptionResource(ctx, old, res.url, 7*24*time.Hour, policy, 64<<20)
			localSources[res.file] = struct {
				URL      string
				Updated  int64
				Interval int64
			}{res.url, updated, int64(7 * 24 * time.Hour / time.Second)}
		}
		source, stage := "download", "connect"
		if kernelRaw[res.key] != nil && !ownedDB {
			source, stage = "local", "local_read"
		}
		if err != nil {
			return nil, resourceError(ctx, res.key, 0, source, stage, "unknown", err)
		}
		if validateSubscriptionDB(res.key, content) != nil {
			return nil, resourceError(ctx, res.key, 0, source, "format_check", "db_incompatible", nil)
		}
		if kernelRaw[res.key] == nil || ownedDB {
			total += len(content)
			if total > 96<<20 {
				return nil, resourceError(ctx, res.key, 0, "download", "body_read", "total_size_limit", nil)
			}
			data[res.file] = content
		}
	}
	for i, rs := range f.RuleSets {
		if _, err := route.ValidateSubscriptionSetWithDependencies(rs, data[fmt.Sprintf("set-%d", i)], route.SubscriptionSetDependencies{GeoIP: f.NeedsGeoIP || kernelRaw["geoip"] != nil, ASN: f.NeedsASN || kernelRaw["asn"] != nil, Geosite: kernelRaw["geosite"] != nil}); err != nil {
			if p.FullOnly {
				return nil, resourceError(ctx, "rule_set", i+1, "download", "format_check", "invalid_format", nil)
			}
			preview.Issues = append(preview.Issues, subscriptionSetIssues(i+1, err)...)
			return preview, nil
		}
	}
	if ctx.Err() != nil {
		return nil, requestCanceled()
	}
	// Unique private version directory; a rejected/canceled preview removes only
	// this version. Previously accepted versions remain valid for backups/flows.
	dir, ownedDir, err := h.stageResourceVersion(base, data)
	if err != nil {
		return nil, resourceError(ctx, "resource_stage", 0, "cache", "stage_create", "file_io", err)
	}
	keep := false
	defer func() {
		h.mu.Lock()
		h.resourceUsing[dir]--
		if h.resourceUsing[dir] <= 0 {
			delete(h.resourceUsing, dir)
		}
		h.mu.Unlock()
		if !keep && ownedDir != "" {
			userio.RemoveAll(ownedDir)
		}
	}()
	if ownedDir != "" {
		if err := secureWorkspace(dir); err != nil {
			return nil, resourceError(ctx, "resource_stage", 0, "cache", "stage_protect", "permission_denied", err)
		}
	}
	if ownedDir != "" {
		for k, v := range data {
			write := exclusiveDocumentWrite
			if h.stageWrite != nil {
				write = h.stageWrite
			}
			if err := write(filepath.Join(dir, k), v); err != nil {
				kind, ordinal := stageResource(k)
				return nil, resourceError(ctx, kind, ordinal, "cache", "stage_write", "file_io", err)
			}
		}
	}
	sub.Resources = map[string]subscriptionLocal{}
	for file, meta := range localSources {
		sum := sha256.Sum256(data[file])
		sub.Resources[meta.URL] = subscriptionLocal{Path: filepath.Join(dir, file), SHA256: hex.EncodeToString(sum[:]), Updated: meta.Updated, Interval: meta.Interval}
	}
	for i := range f.RuleSets {
		f.RuleSets[i].Path = filepath.Join(dir, fmt.Sprintf("set-%d", i))
		f.RuleSets[i].URL = ""
		f.RuleSets[i].Interval = 0
	}
	for key, file := range map[string]string{"geoip": "country.mmdb", "asn": "asn.mmdb"} {
		if data[file] != nil {
			b := rawJSON(route.GeoIPOptions{Path: filepath.Join(dir, file)})
			if key == "geoip" {
				sub.Snapshot.GeoIP = b
			} else {
				sub.Snapshot.ASN = b
			}
		}
	}
	for _, o := range f.Outbounds {
		sub.Snapshot.Outbounds = append(sub.Snapshot.Outbounds, rawJSON(o))
	}
	for _, g := range f.Groups {
		sub.Snapshot.Groups = append(sub.Snapshot.Groups, remoteGroups[g.Name])
	}
	for _, r := range f.Rules {
		sub.Snapshot.Rules = append(sub.Snapshot.Rules, rawJSON(r))
	}
	for _, s := range f.RuleSets {
		sub.Snapshot.RuleSets = append(sub.Snapshot.RuleSets, rawJSON(s))
	}
	var prevFinal string
	_ = json.Unmarshal(routing["final"], &prevFinal)
	if prevFinal == "" {
		prevFinal = "direct"
	}
	sub.Snapshot.Final = f.Final
	// The snapshot is the remote declaration; selection and field patches are
	// separate. A new inactive profile cannot change MATCH or any live object.
	if old == nil {
		sub.PriorFinal = prevFinal
	}
	effective := effectiveSubscription(&sub, kernelRaw)
	if subActive(sub) {
		attachSubscription(kernelRaw, effective, insert)
	}
	rules = rawArray(rawObject(kernelRaw["routing"]), "rules")
	root["kernel"] = rawJSON(kernelRaw)
	if old == nil {
		subs = append(subs, sub)
	} else {
		for i := range subs {
			if subs[i].ID == id {
				subs[i] = sub
			}
		}
	}
	root["subscriptions"] = rawJSON(subs)
	if migrating {
		if err := rewriteLegacy(root, kernelRaw, sub, conversion); err != nil {
			return nil, fail("legacy_migration_failed", "", "Cannot preserve legacy graph")
		}
	}
	text, err := renderSubscriptionSource(base, root)
	if err != nil {
		return nil, fail("subscription_failed", "source", "Cannot preserve source format")
	}
	candidate, de := parseDocument(text, h.workspace, base.format)
	if de != nil {
		if de.Detail != nil {
			if p.Proxy != nil {
				de.Detail.Route = "windows_static_http"
			}
			return nil, de
		}
		return nil, fail("subscription_conflict", "graph", "Candidate validation failed ("+de.Code+" / "+de.Path+"); previous configuration retained")
	}
	if de = validateSubscriptionResources(candidate.config, subs...); de != nil {
		if de.Detail != nil && p.Proxy != nil {
			de.Detail.Route = "windows_static_http"
		}
		return nil, de
	}
	preview.Token = subscriptionID()
	preview.ID = id
	preview.Text = text
	preview.Format = base.format
	preview.Items = subscriptionItems(f)
	preview.Counts = map[string]int{"nodes": len(f.Outbounds), "groups": len(f.Groups), "rules": len(f.Rules), "rule_sets": len(f.RuleSets), "match": 0}
	if f.Final != "" {
		preview.Counts["match"] = 1
	}
	preview.Changes = append(preview.Changes, fmt.Sprintf("规则插入位置 %d；其它 %d 条规则保持原顺序", insert+1, len(rules)-len(f.Rules)))
	final := "保留原终局"
	if f.Final != "" {
		final = prevFinal + " → " + f.Final
	}
	preview.Changes = append(preview.Changes, "MATCH："+final, "本机端口、当前模式（"+base.client.Mode+"）、DNS/监听/TUN设置及其它手动内容保持不变")
	if len(f.Ignored) > 0 {
		seen := map[string]bool{}
		unique := []string{}
		for _, v := range f.Ignored {
			if !seen[v] {
				seen[v] = true
				unique = append(unique, v)
			}
		}
		f.Ignored = unique
		sort.Strings(f.Ignored)
		preview.Changes = append(preview.Changes, "未导入本机/其它非路由字段："+strings.Join(f.Ignored, ", "))
	}
	preview.NeedsConfirmation = old == nil || selectionChanged
	if old != nil && !sameJSON(rawJSON(old.Snapshot.Rules), rawJSON(sub.Snapshot.Rules)) && len(rules) > len(sub.Snapshot.Rules) {
		preview.NeedsConfirmation = true
	}
	// A stable in-place refresh does not change manual precedence. Name remaps,
	// changing final or changes before/after an owned block need explicit review.
	if old != nil {
		for k, v := range sub.Names {
			if (old.Names[k] != "" && old.Names[k] != v) || (old.Names[k] == "" && k != v) {
				preview.NeedsConfirmation = true
			}
		}
		for k, v := range sub.SetNames {
			if (old.SetNames[k] != "" && old.SetNames[k] != v) || (old.SetNames[k] == "" && k != v) {
				preview.NeedsConfirmation = true
			}
		}
		if old.Snapshot.Final != sub.Snapshot.Final {
			preview.NeedsConfirmation = true
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.syncTUNEgressLocked()
	// Publication is the linearization point. Stage writes/validation can block
	// after the earlier cancellation check. Check the captured lifecycle itself
	// under the same lock as stop/egress changes, not just its asynchronous
	// AfterFunc propagation to the request context. Rejection retains defer cleanup.
	if ctx.Err() != nil {
		return nil, resourceError(ctx, "resource_stage", 0, "cache", "validate", "canceled", safeFailure(ctx, "validate", ctx.Err()))
	}
	if bootstrapLife != nil {
		if bootstrapLife.Err() != nil || h.bootstrapLife != bootstrapLife {
			return nil, resourceError(ctx, "resource_stage", 0, "cache", "validate", "canceled", nil)
		}
		if h.egressGeneration != generation || h.egress != policy || policy != nil && !policy.Ready() {
			return nil, resourceError(ctx, "resource_stage", 0, "cache", "validate", "egress_unavailable", nil)
		}
	}
	if h.doc.text != base.text || h.doc.format != base.format {
		return nil, fail("subscription_stale", "source", "Accepted source changed; preview again")
	}
	if h.fullCandidates == nil {
		h.fullCandidates = map[string]*subscriptionPending{}
	}
	h.pruneStaleCandidatesLocked(ownedDir)
	if prior := h.fullCandidates[id]; prior != nil {
		h.expireFullPendingLocked(prior)
		if prior.Dir != "" && prior.Dir != ownedDir {
			userio.RemoveAll(prior.Dir)
		}
	}
	h.fullPending = &subscriptionPending{Token: preview.Token, Base: base.text, Text: text, Dir: ownedDir, ID: id, Format: base.format, Created: time.Now(), Refresh: true}
	h.fullCandidates[id] = h.fullPending
	keep = true
	return preview, nil
}

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
		tasks = append(tasks, func() *Error {
			b, e := readSubscriptionResource(rs.Path, 16<<20)
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
			return nil
		})
	}
	if c.GeoIP != nil {
		geoPath := c.GeoIP.Path
		tasks = append(tasks, func() *Error {
			b, e := readSubscriptionResource(geoPath, 64<<20)
			if e != nil {
				return resourceError(context.Background(), "geoip", 0, "cache", "cache_verify", "unknown", e)
			}
			if route.ValidateSubscriptionGeoIPAt(geoPath, b) != nil {
				return resourceError(context.Background(), "geoip", 0, "cache", "format_check", "db_incompatible", nil)
			}
			return nil
		})
	}
	if c.ASN != nil {
		asnPath := c.ASN.Path
		tasks = append(tasks, func() *Error {
			b, e := readSubscriptionResource(asnPath, 64<<20)
			if e != nil {
				return resourceError(context.Background(), "asn", 0, "cache", "cache_verify", "unknown", e)
			}
			if validateSubscriptionDBAt("asn", asnPath, b) != nil {
				return resourceError(context.Background(), "asn", 0, "cache", "format_check", "db_incompatible", nil)
			}
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
	workers := runtime.GOMAXPROCS(0)
	if workers < 2 {
		workers = 2
	}
	if workers > len(tasks) {
		workers = len(tasks)
	}
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

// The test seam only replaces I/O, not conversion, ownership or commit logic.
func (h *Host) fetchFull(ctx context.Context, url string, p *clientegress.Policy, limit int64) ([]byte, error) {
	if h.fullFetch != nil {
		return h.fullFetch(ctx, url, p, limit)
	}
	ctx, done := h.ipContext(ctx)
	defer done()
	if runtime, _ := ctx.Value(resourceKernelKey{}).(bool); runtime {
		return h.fetchKernelAsset(ctx, url, limit)
	}
	return fetchImportBounded(ctx, url, p, nil, limit)
}

func safeSubscriptionName(s string) string {
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
	scanLine := func(l string) {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") || strings.HasPrefix(l, "//") {
			return
		}
		if !strings.Contains(l, "GEOIP") && !strings.Contains(l, "IP-ASN") {
			return
		}
		for _, m := range subscriptionSetNeedsRx.FindAllStringSubmatch(l, -1) {
			if strings.Contains(m[1], "ASN") {
				asn = true
			} else if !strings.EqualFold(m[2], "LAN") && !strings.EqualFold(m[2], "private") {
				country = true
			}
		}
	}
	if lines != nil {
		for _, l := range lines {
			scanLine(l)
			if country && asn {
				break
			}
		}
	} else {
		for rem := b; len(rem) > 0; {
			var line []byte
			if idx := bytes.IndexByte(rem, '\n'); idx >= 0 {
				line = rem[:idx]
				rem = rem[idx+1:]
			} else {
				line = rem
				rem = nil
			}
			if !bytes.Contains(line, []byte("GEOIP")) && !bytes.Contains(line, []byte("IP-ASN")) {
				continue
			}
			scanLine(string(line))
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
		groups = append(groups, map[string]any{"name": g.Name, "type": g.Type, "members": g.Members})
	}
	sets := []string{}
	for _, s := range f.RuleSets {
		sets = append(sets, s.Name)
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

var (
	defaultFullSubscriptionNameRx = regexp.MustCompile(`^完整配置 [0-9a-f]{6}$`)
	quotedNameRx                  = regexp.MustCompile(`"[^"\n]*"`)
	subscriptionSetNeedsRx        = regexp.MustCompile(`(?:^|[,(])\s*(GEOIP|SRC-GEOIP|IP-ASN|SRC-IP-ASN)\s*,\s*([^,)]+)`)
	subscriptionRuleTypeRx        = regexp.MustCompile(`^[A-Z][A-Z0-9-]{0,40}$`)
)

func (h *Host) expireFullPendingLocked(p *subscriptionPending) {
	if h.expiredFullTexts == nil || len(h.expiredFullTexts) >= 64 {
		h.expiredFullTexts = map[[32]byte]bool{}
	}
	h.expiredFullTexts[sha256.Sum256([]byte(p.Text))] = true
}

func (h *Host) pruneStaleCandidatesLocked(keepDir string) {
	now := time.Now()
	sharedDirs := map[string]bool{}
	for id, p := range h.fullCandidates {
		if p.Base == h.doc.text && p.Format == h.doc.format && now.Sub(p.Created) <= 30*time.Minute {
			if p.Dir != "" {
				sharedDirs[p.Dir] = true
			}
			continue
		}
		h.expireFullPendingLocked(p)
		delete(h.fullCandidates, id)
		if h.fullPending == p {
			h.fullPending = nil
		}
		if p.Dir == "" || p.Dir == keepDir || sharedDirs[p.Dir] || h.resourceUsing[p.Dir] > 0 {
			continue
		}
		stilReferenced := false
		for _, other := range h.fullCandidates {
			if other.Dir == p.Dir {
				stilReferenced = true
				break
			}
		}
		if stilReferenced {
			continue
		}
		name := h.resourceDir(p.Dir)
		if name == "" || filepath.Join(h.workspace, name) != filepath.Clean(p.Dir) {
			continue
		}
		if safeCacheDir(p.Dir) != nil {
			h.cacheFailure()
			continue
		}
		if _, err := userio.Lstat(filepath.Join(p.Dir, acceptedResourceMarker)); !os.IsNotExist(err) {
			if err != nil {
				h.cacheFailure()
			}
			continue
		}
		if err := removeResourceVersion(h.workspace, name); err != nil && !os.IsNotExist(err) {
			h.cacheFailure()
		}
	}
}
