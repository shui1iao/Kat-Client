package clientcore

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/outbound/group"
	"github.com/shui1iao/Kat/internal/provider"
	"github.com/shui1iao/Kat/internal/route"
	"github.com/shui1iao/Kat/internal/userio"
	"gopkg.in/yaml.v3"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

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

// Only new subscription snapshots use [] for empty lists. Do not normalize
// decoded snapshots: reading a preexisting source must not rewrite its bytes.
func newFullSnapshot() fullSnapshot {
	return fullSnapshot{Outbounds: []json.RawMessage{}, Groups: []json.RawMessage{}, Rules: []json.RawMessage{}, RuleSets: []json.RawMessage{}}
}

func sameSnapshotRules(a, b []json.RawMessage) bool {
	if len(a) == 0 && len(b) == 0 {
		return true // nil in older accepted documents
	}
	return sameJSON(rawJSON(a), rawJSON(b))
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
	if !provider.BeginsURIList(b) && yaml.Unmarshal(b, &header) == nil && len(header.Content) == 1 && header.Content[0].Kind == yaml.MappingNode {
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
	if !full && conversion == nil {
		if p.FullOnly || old != nil {
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
	sub := fullSubscription{Snapshot: newFullSnapshot(), ID: id, Name: name, URL: subURL, Interval: interval, Updated: time.Now().Unix(), Names: map[string]string{}, SetNames: map[string]string{}}
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
		reason := "配置校验未通过：" + quotedNameRx.ReplaceAllString(e.Error(), "[名称]")
		if p.FullOnly {
			return nil, fail("subscription_format_unsupported", "graph", reason+"，原配置已保留")
		}
		preview.Issues = append(preview.Issues, reason)
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
	if old != nil && len(rules) > len(sub.Snapshot.Rules) && !sameSnapshotRules(old.Snapshot.Rules, sub.Snapshot.Rules) {
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

var (
	defaultFullSubscriptionNameRx = regexp.MustCompile(`^完整配置 [0-9a-f]{6}$`)
	quotedNameRx                  = regexp.MustCompile(`"[^"\n]*"`)
	subscriptionSetNeedsRx        = regexp.MustCompile(`(?i)(?:^|[,(])\s*(GEOIP|SRC-GEOIP|IP-ASN|SRC-IP-ASN)\s*,\s*([^,)]+)`)
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

// No arbitrary error text is ever persisted: this file contains only closed
// reasons, section enums, numeric positions and the finite route diagnostics.
type subscriptionStatus struct {
	Finished int64           `json:"finished"`
	NextDue  int64           `json:"next_due"`
	Success  bool            `json:"success"`
	Reason   string          `json:"reason,omitempty"`
	Section  string          `json:"section,omitempty"`
	Detail   *ResourceDetail `json:"detail,omitempty"`
}

var subscriptionReasons = map[string]bool{"network_dns": true, "network_connect": true, "tls": true, "http_status": true, "redirect_denied": true, "format_unsupported": true, "ownership_conflict": true, "candidate_expired": true, "apply_failed": true, "canceled": true, "storage": true}

func subscriptionReason(code string, d *ResourceDetail) string {
	switch code {
	case "subscription_conflict":
		return "ownership_conflict"
	case "subscription_stale", "candidate_expired":
		return "candidate_expired"
	case "apply_failed", "rollback_failed":
		return "apply_failed"
	}
	if d != nil {
		switch d.Category {
		case "dns_failed", "fake_ip":
			return "network_dns"
		case "tls_certificate", "tls_handshake":
			return "tls"
		case "http_status", "proxy_http":
			return "http_status"
		case "redirect_refused":
			return "redirect_denied"
		case "invalid_format", "db_incompatible":
			return "format_unsupported"
		case "canceled":
			return "canceled"
		case "file_io", "permission_denied", "disk_full", "unsafe_file":
			return "storage"
		default:
			return "network_connect"
		}
	}
	switch code {
	case "subscription_conflict":
		return "ownership_conflict"
	case "subscription_stale", "candidate_expired":
		return "candidate_expired"
	case "subscription_format_unsupported", "subscription_native_config":
		return "format_unsupported"
	case "subscription_fetch_failed":
		return "network_connect"
	case "apply_failed", "rollback_failed":
		return "apply_failed"
	case "save_failed":
		return "storage"
	}
	return ""
}
func (h *Host) subscriptionStatusesLocked() map[string]subscriptionStatus {
	statuses := map[string]subscriptionStatus{}
	b, e := userio.ReadFile(filepath.Join(h.workspace, "subscription-attempts.json"))
	if e != nil || len(b) > 65536 {
		return statuses
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&statuses) != nil || len(statuses) > 16 {
		return map[string]subscriptionStatus{}
	}
	for id, s := range statuses {
		if len(id) != 32 || s.Finished < 0 || s.NextDue < 0 || s.Reason != "" && !subscriptionReasons[s.Reason] {
			return map[string]subscriptionStatus{}
		}
		if _, e := hex.DecodeString(id); e != nil {
			return map[string]subscriptionStatus{}
		}
	}
	return statuses
}
func (h *Host) recordSubscriptionStatusLocked(id string, failure *Error) {
	if len(id) != 32 {
		return
	}
	root, e := sourceJSON(h.doc)
	if e != nil {
		return
	}
	subs, e := subscriptionsOf(root)
	if e != nil {
		return
	}
	interval := 0
	for _, s := range subs {
		if s.ID == id {
			interval = s.Interval
		}
	}
	if interval == 0 {
		return
	}
	status := subscriptionStatus{Finished: time.Now().Unix(), Success: failure == nil}
	if failure != nil {
		status.Reason = subscriptionReason(failure.Code, failure.Detail)
		if status.Reason == "" {
			status.Reason = "apply_failed"
		}
		status.Detail = failure.Detail
		for _, section := range []string{"subscriptions", "groups", "outbounds", "rules", "final", "graph", "kernel", "source", "rule_sets", "geoip", "asn"} {
			if section == failure.Path {
				status.Section = section
			}
		}
		interval = min(interval, 1800)
	}
	status.NextDue = status.Finished + int64(interval)
	statuses := h.subscriptionStatusesLocked()
	statuses[id] = status
	b, _ := json.Marshal(statuses)
	_ = atomicWrite(filepath.Join(h.workspace, "subscription-attempts.json"), b)
}

func stageResource(key string) (string, int) {
	if key == "country.mmdb" {
		return "geoip", 0
	}
	if key == "asn.mmdb" {
		return "asn", 0
	}
	if strings.HasPrefix(key, "set-") {
		n, e := strconv.Atoi(strings.TrimPrefix(key, "set-"))
		if e == nil {
			return "rule_set", n + 1
		}
	}
	return "resource_stage", 0
}

// Only closed enums/numbers cross IPC. Never include a remote name, URL, path or raw cause.
type resourceKernelKey struct{}

type ResourceDetail struct {
	Resource            string            `json:"resource"`
	Ordinal             int               `json:"ordinal,omitempty"`
	SubscriptionOrdinal int               `json:"subscription_ordinal,omitempty"`
	Source              string            `json:"source"`
	Stage               string            `json:"stage"`
	Category            string            `json:"category"`
	HTTPStatus          int               `json:"http_status,omitempty"`
	Route               string            `json:"route"`
	Attempts            []ResourceAttempt `json:"attempts,omitempty"`
	FirstAttempt        *ResourceAttempt  `json:"first_attempt,omitempty"`
}
type downloadFailure struct {
	stage, category string
	status          int
}

func (e *downloadFailure) Error() string {
	return "subscription download: " + e.stage + "/" + e.category
}
func dl(stage, category string) error { return &downloadFailure{stage: stage, category: category} }
func safeFailure(ctx context.Context, stage string, e error) error {
	var f *downloadFailure
	if errors.As(e, &f) {
		return f
	}
	if errors.Is(e, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return dl(stage, "canceled")
	}
	if errors.Is(e, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return dl(stage, "timeout")
	}
	var ne net.Error
	if errors.As(e, &ne) && ne.Timeout() {
		return dl(stage, "timeout")
	}
	var ce *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	if errors.As(e, &ce) || errors.As(e, &ua) || errors.As(e, &hn) || errors.As(e, &ci) {
		return dl("tls", "tls_certificate")
	}
	if stage == "tls" {
		return dl(stage, "tls_handshake")
	}
	switch stage {
	case "resolve":
		return dl(stage, "dns_failed")
	case "connect":
		return dl(stage, "connect_failed")
	case "body_read":
		return dl(stage, "read_failed")
	case "proxy_connect":
		return dl(stage, "proxy_protocol")
	}
	return dl(stage, "unknown")
}
func localFailure(e error) string {
	if errors.Is(e, os.ErrPermission) {
		return "permission_denied"
	}
	if errors.Is(e, syscall.ENOSPC) {
		return "disk_full"
	}
	if errors.Is(e, errResourceLimit) {
		return "size_limit"
	}
	if errors.Is(e, errResourceShape) {
		return "unsafe_file"
	}
	return "file_io"
}

var errResourceLimit = errors.New("resource size limit")
var errResourceShape = errors.New("resource shape refused")

func resourceError(ctx context.Context, resource string, ordinal int, source, stage, category string, cause error) *Error {
	route := resourceRoute(ctx)
	detail := &ResourceDetail{Resource: resource, Ordinal: ordinal, Source: source, Stage: stage, Category: category, Route: route}
	if cause != nil {
		var attempts *resourceAttemptsError
		if errors.As(cause, &attempts) {
			detail.Route = attempts.last.Route
			detail.FirstAttempt = &attempts.first
			detail.Attempts = attempts.attempts
		}
		var f *downloadFailure
		if errors.As(cause, &f) {
			detail.Stage = f.stage
			detail.Category = f.category
			detail.HTTPStatus = f.status
		} else {
			detail.Category = localFailure(cause)
		}
	}
	code, path := "subscription_resource_failed", resource
	if resource == "subscription" {
		code = "subscription_fetch_failed"
	}
	if resource == "rule_set" {
		path = "rule_sets"
	}
	return &Error{Code: code, Message: "Subscription operation failed; accepted configuration retained", Path: path, Detail: detail, Reason: subscriptionReason(code, detail)}
}
