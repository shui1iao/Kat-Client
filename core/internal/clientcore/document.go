// Package clientcore embeds the real Kat kernel for the normal-user desktop.
package clientcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/outbound"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"unicode/utf8"
)

const MaxFrame = 2 << 20
const maxDocument = 1 << 20
const initialDocument = `{"schema_version":1,"client":{"mode":"rule","global_group":"","probe_url":"https://www.gstatic.com/generate_204","http_port":7890,"socks_port":7891,"ipv6":false},"kernel":{}}` + "\n"

type Error struct {
	Code    string          `json:"code"`
	Reason  string          `json:"reason,omitempty"`
	Message string          `json:"message"`
	Path    string          `json:"path,omitempty"`
	Detail  *ResourceDetail `json:"detail,omitempty"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }
func fail(code, path, message string) *Error {
	return &Error{Code: code, Message: message, Path: path, Reason: subscriptionReason(code, nil)}
}

type ClientSniff struct {
	Enabled             bool   `json:"enabled"`
	OverrideDestination bool   `json:"override_destination"`
	TCPPorts            string `json:"tcp_ports,omitempty"`
	UDPPorts            string `json:"udp_ports,omitempty"`
	Timeout             string `json:"timeout,omitempty"`
}
type Client struct {
	IPv6              bool            `json:"ipv6"`
	CloseOnSwitch     *bool           `json:"close_on_switch,omitempty"`
	Sniff             *ClientSniff    `json:"sniff,omitempty"`
	Mode              string          `json:"mode"`
	GlobalGroup       string          `json:"global_group"`
	ProbeURL          string          `json:"probe_url"`
	HTTPPort          int             `json:"http_port"`
	SOCKSPort         int             `json:"socks_port"`
	ProbeTimeout      kernel.Duration `json:"probe_timeout,omitempty"`
	ProbeRoundTimeout kernel.Duration `json:"probe_round_timeout,omitempty"`
	UnifiedDelay      *bool           `json:"unified_delay,omitempty"`
	ProbeConcurrency  int             `json:"probe_concurrency,omitempty"`
}
type document struct {
	text   string
	format DocumentFormat
	counts documentCounts
	client Client
	config kernel.Config
}

// Reject duplicate keys before UI and kernel decoders can disagree.
func uniqueJSON(b []byte) error {
	if !utf8.Valid(b) {
		return errors.New("UTF-8 required")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return errors.New("nesting")
		}
		tok, e := d.Token()
		if e != nil {
			return e
		}
		x, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch x {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return errors.New("duplicate key")
				}
				seen[s] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e = value(depth + 1); e != nil {
					return e
				}
			}
		default:
			return errors.New("delimiter")
		}
		_, e = d.Token()
		return e
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

// The omitted format retains the original Go JSON parser API. Host callers
// resolve their optional format against the currently accepted document.
func parseDocument(text, workspace string, formats ...DocumentFormat) (document, *Error) {
	format := FormatJSON
	if len(formats) != 0 {
		format = formats[0]
	}
	out := document{text: text, format: format}
	if !format.valid() {
		return out, fail("invalid_params", "params.format", "Expected json, yaml or yml")
	}
	encoded, _ := json.Marshal(text)
	if len(encoded)+len(workspace) > MaxFrame-2048 {
		return out, fail("document_too_large", "text", "Encoded document cannot fit a protocol response")
	}

	if len(text) > maxDocument {
		return out, fail("document_too_large", "text", "Document exceeds 1 MiB")
	}
	projection := []byte(text)
	if format != FormatJSON {
		var err error
		projection, err = yamlJSON(projection)
		if err != nil {
			return out, fail("invalid_document", "text", "Invalid, unsupported or ambiguous UTF-8 YAML")
		}
	}
	if uniqueJSON(projection) != nil {
		return out, fail("invalid_document", "text", "Invalid or ambiguous UTF-8 JSON")
	}
	var legacyErr error
	text, projection, legacyErr = normalizeLegacySmartSource(text, format, projection)
	if legacyErr != nil {
		if errors.Is(legacyErr, errLegacySmartSubscription) {
			return out, fail("legacy_smart_subscription_unsupported", "subscriptions", "含 Smart 的旧版订阅（Model<2）所有权升级可能回灌旧凭据，暂不支持；未创建备份，未修改配置或运行态")
		}
		return out, fail("invalid_document", "kernel.groups", "Invalid Smart or group declaration")
	}
	out.text = text
	encoded, _ = json.Marshal(text)
	if len(text) > maxDocument || len(encoded)+len(workspace) > MaxFrame-2048 {
		return out, fail("document_too_large", "text", "Converted document exceeds source or protocol response limits")
	}
	var root struct {
		Schema        int             `json:"schema_version"`
		Client        json.RawMessage `json:"client"`
		Kernel        json.RawMessage `json:"kernel"`
		Subscriptions json.RawMessage `json:"subscriptions,omitempty"`
	}
	d := json.NewDecoder(bytes.NewReader(projection))
	d.DisallowUnknownFields()
	if d.Decode(&root) != nil || root.Schema != 1 {
		return out, fail("invalid_document", "schema_version", "Expected client schema_version 1")
	}
	if root.Subscriptions != nil {
		if _, e := subscriptionsOf(map[string]json.RawMessage{"subscriptions": root.Subscriptions}); e != nil {
			return out, fail("invalid_document", "subscriptions", "Invalid full subscription ownership")
		}
	}
	cb := bytes.TrimSpace(root.Client)
	if len(cb) == 0 || cb[0] != '{' || json.Unmarshal(cb, &out.client) != nil {
		return out, fail("invalid_document", "client", "Expected client object")
	}
	var clientFields map[string]json.RawMessage
	_ = json.Unmarshal(cb, &clientFields)
	if v, ok := clientFields["ipv6"]; ok && string(v) != "true" && string(v) != "false" {
		return out, fail("invalid_document", "client.ipv6", "Expected boolean")
	}
	if v, ok := clientFields["close_on_switch"]; ok && string(v) != "true" && string(v) != "false" {
		return out, fail("invalid_document", "client.close_on_switch", "Expected boolean")
	}
	if e := validateSniff(cb); e != nil {
		return out, e
	}
	if e := validateProbeSettings(cb, &out.client); e != nil {
		return out, e
	}
	cl := out.client
	if cl.Mode != "rule" && cl.Mode != "global" && cl.Mode != "direct" {
		return out, fail("invalid_document", "client.mode", "Expected rule, global or direct")
	}
	if cl.HTTPPort < 1 || cl.HTTPPort > 65535 || cl.SOCKSPort < 1 || cl.SOCKSPort > 65535 || cl.HTTPPort == cl.SOCKSPort {
		return out, fail("invalid_document", "client", "Distinct HTTP/SOCKS ports in 1..65535 required")
	}
	u, e := url.Parse(cl.ProbeURL)
	if e != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return out, fail("invalid_document", "client.probe_url", "Absolute HTTP(S) probe URL required")
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(root.Kernel, &raw) != nil || raw == nil {
		return out, fail("invalid_document", "kernel", "Expected real Kat kernel object")
	}
	if format != FormatJSON {
		if e := preserveYAMLDNSPolicy(text, raw); e != nil {
			return out, fail("invalid_document", "kernel.dns.nameserver-policy", "Invalid ordered DNS policy")
		}
	}
	if b, ok := raw["inbounds"]; ok {
		var ins []json.RawMessage
		if json.Unmarshal(b, &ins) != nil || string(bytes.TrimSpace(b)) == "null" || len(ins) != 0 {
			return out, fail("unsupported_inbound", "kernel.inbounds", "Omit inbounds or use []; client generates loopback SOCKS")
		}
	}
	inbound := kernel.Inbound{Protocol: "socks5", Listen: portAddress(cl.SOCKSPort), Name: "kat-client"}
	if cl.Sniff != nil && cl.Sniff.Enabled {
		var timeout kernel.Duration
		if cl.Sniff.Timeout != "" {
			_ = timeout.UnmarshalJSON([]byte(strconv.Quote(cl.Sniff.Timeout)))
		} // validated by validateSniff
		inbound.Sniff = &kernel.SniffOptions{Enabled: true, OverrideDestination: cl.Sniff.OverrideDestination, TCPPorts: cl.Sniff.TCPPorts, UDPPorts: cl.Sniff.UDPPorts, Timeout: timeout}
	}
	raw["inbounds"], _ = json.Marshal([]kernel.Inbound{inbound})
	b, _ := json.Marshal(raw)
	c, e := kernel.DecodeConfig(b)
	if e != nil {
		return out, fail("invalid_kernel", "kernel", "Invalid Kat field, type, configuration or reference")
	}
	out.counts = documentCounts{Nodes: len(c.Outbounds), Groups: len(c.Groups), Providers: func() int {
		v, _ := subscriptionsOf(map[string]json.RawMessage{"subscriptions": root.Subscriptions})
		return len(v)
	}()}
	if c.Routing != nil {
		out.counts.Rules = len(c.Routing.Rules)
	}
	// Strictly validate originals before the host-only projections. Never write
	// normalized Config, provider expansion, logs or modes back to user bytes.
	level := "info"
	if c.Log != nil && c.Log.Level != "" {
		level = c.Log.Level
	}
	c.Log = &kernel.LogOptions{Level: level}
	off := false
	c.API = &kernel.APIOptions{Enabled: &off}
	if c.Stats == nil {
		c.Stats = &kernel.StatsOptions{}
	}
	c.Stats.File = filepath.Join(workspace, "runtime.stats.json")
	c.Stats.Persist = &off
	for _, p := range c.Providers {
		if p.Type == "file" {
			if st, e := os.Stat(p.Path); e == nil && !st.Mode().IsRegular() {
				return out, fail("invalid_kernel", "kernel.providers", "File provider must reference a regular file")
			}
		}
	}
	for i := range c.Providers {
		// Legacy source has no pinned dependency probe URL. Supply the accepted
		// client default only in this runtime projection; never rewrite user bytes.
		if c.Providers[i].DependencyProbeURL == "" {
			c.Providers[i].DependencyProbeURL = cl.ProbeURL
		}
		if c.Providers[i].Type == "http" {
			c.Providers[i].Path = filepath.Join(workspace, "providers", c.Providers[i].Name+".cache")
		}
	}
	switch cl.Mode {
	case "global":
		found := false
		for _, g := range c.Groups {
			if g.Name == cl.GlobalGroup {
				found = true
			}
		}
		if !found {
			return out, fail("invalid_document", "client.global_group", "Global mode requires an existing policy group")
		}
		c.Routing = &kernel.RoutingOptions{Final: cl.GlobalGroup}
	case "direct":
		c.Routing = &kernel.RoutingOptions{Final: "direct"}
	}
	b, e = json.Marshal(c)
	if e != nil {
		return out, fail("invalid_kernel", "kernel", "Cannot encode runtime")
	}
	c, e = kernel.DecodeConfig(b)
	if e != nil {
		return out, fail("invalid_kernel", "kernel", "Invalid runtime projection")
	}
	// Only desktop projection defaults to physical/system DNS. Explicit source
	// upstreams (including old custom values) and server defaults are untouched.
	if c.DNS == nil {
		c.DNS = &kernel.DNSOptions{Server: "system"}
	} else if c.DNS.Server == "" && len(c.DNS.Servers) == 0 && c.DNS.CacheEntries == nil {
		v := *c.DNS
		v.Server = "system"
		c.DNS = &v
	}
	c.SetClientIPv6(cl.IPv6)
	c.SetClientUnifiedDelay(cl.UnifiedDelay == nil || *cl.UnifiedDelay)
	ownedGroups := map[string]bool{}
	owners, _ := subscriptionsOf(map[string]json.RawMessage{"subscriptions": root.Subscriptions})
	for _, s := range owners {
		for _, g := range s.Snapshot.Groups {
			ownedGroups[rawName(g)] = true
		}
	}
	for i := range c.Groups {
		g := &c.Groups[i]
		if ownedGroups[g.Name] && g.Probe != nil && g.Probe.Interval == 0 {
			probe := *g.Probe
			probe.Interval = outbound.Duration(300 * time.Second)
			if g.Type == "url-test" {
				probe.Interval = outbound.Duration(time.Minute)
			}
			g.Probe = &probe
		}
	}
	// New source references can inherit built-ins or nested dynamic groups.
	// Check their effective local projection before accepting even a stopped
	// document; a reject leaf in an automatic group must never land on disk.
	for _, g := range c.Groups {
		if g.IncludeGroup != "" {
			if _, _, e := kernel.CheckProviders(c); e != nil {
				return out, fail("invalid_kernel", "kernel.groups", "Invalid source-group expansion or member configuration")
			}
			break
		}
	}
	out.config = c
	if root.Subscriptions != nil {
		if e := validateSubscriptionResources(c, func() []fullSubscription {
			v, _ := subscriptionsOf(map[string]json.RawMessage{"subscriptions": root.Subscriptions})
			return v
		}()...); e != nil {
			return out, e
		}
	}
	return out, nil
}
func privateRegular(path string) error {
	st, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !st.Mode().IsRegular() {
		return errors.New("not a private regular file")
	}
	if e := rejectReparse(path); e != nil {
		return e
	}
	return secureFile(path)
}
func readPrivate(path string, limit int64) ([]byte, error) {
	if e := privateRegular(path); e != nil {
		return nil, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, errors.New("file read limit")
	}
	return b, nil
}
func atomicWrite(path string, b []byte, unchanged ...func() bool) error {
	return atomicWriteContext(context.Background(), path, b, unchanged...)
}
func atomicWriteContext(ctx context.Context, path string, b []byte, unchanged ...func() bool) error {
	if st, e := os.Lstat(path); e == nil && (!st.Mode().IsRegular() || rejectReparse(path) != nil) {
		return errors.New("nonregular destination")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".kat-write-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	// Recheck immediately before publication, including every Windows
	// retry. A failed rename has not committed; successful rename has.
	return replaceAtomicFile(ctx, tmp, path, unchanged)
}
