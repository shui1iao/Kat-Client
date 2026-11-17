// Package clientcore embeds the real Kat kernel for the normal-user desktop.
package clientcore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/shui1iao/Kat/internal/kernel"
	"github.com/shui1iao/Kat/internal/outbound"
	"github.com/shui1iao/Kat/internal/tunplatform"
	"github.com/shui1iao/Kat/internal/userio"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
	"unicode/utf8"
)

const MaxFrame = 2 << 20
const maxDocument = 1 << 20
const initialDocument = `{"schema_version":1,"client":{"mode":"rule","global_group":"","probe_url":"https://www.gstatic.com/generate_204","http_port":7890,"socks_port":7891,"ipv6":false,"sniff":{"enabled":true,"override_destination":true}},"kernel":{}}` + "\n"

type Error struct {
	Transport *TransportDiagnostic    `json:"transport,omitempty"`
	Code      string                  `json:"code"`
	Reason    string                  `json:"reason,omitempty"`
	Message   string                  `json:"message"`
	Path      string                  `json:"path,omitempty"`
	Detail    *ResourceDetail         `json:"detail,omitempty"`
	Tun       *tunplatform.Diagnostic `json:"tun,omitempty"`
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
	TunDNS            *kernel.ClientDNSOptions `json:"tun_dns,omitempty"`
	IPv6              bool                     `json:"ipv6"`
	CloseOnSwitch     *bool                    `json:"close_on_switch,omitempty"`
	Sniff             *ClientSniff             `json:"sniff,omitempty"`
	Mode              string                   `json:"mode"`
	GlobalGroup       string                   `json:"global_group"`
	ProbeURL          string                   `json:"probe_url"`
	HTTPPort          int                      `json:"http_port"`
	SOCKSPort         int                      `json:"socks_port"`
	ProbeTimeout      kernel.Duration          `json:"probe_timeout,omitempty"`
	ProbeRoundTimeout kernel.Duration          `json:"probe_round_timeout,omitempty"`
	UnifiedDelay      *bool                    `json:"unified_delay,omitempty"`
	ProbeConcurrency  int                      `json:"probe_concurrency,omitempty"`
}
type document struct {
	advancedDNS   bool
	ruleRouting   *kernel.RoutingOptions // accepted rule-mode projection; never the editor draft
	text          string
	format        DocumentFormat
	projection    []byte
	projectedText string
	counts        documentCounts
	client        Client
	config        kernel.Config
}

func encodedJSONStringLen(s string) int {
	if len(s)*6+2 <= MaxFrame-2048-4096 {
		return len(s) + 2
	}
	encoded, _ := json.Marshal(s)
	return len(encoded)
}

func fastUniqueJSON(b []byte) (handled bool, err error) {
	if !utf8.Valid(b) {
		return true, errors.New("UTF-8 required")
	}
	n := len(b)
	i := 0
	skipWS := func() {
		for i < n {
			c := b[i]
			if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
				i++
			} else {
				break
			}
		}
	}
	skipStringValue := func() bool {
		i++
		for i < n {
			c := b[i]
			if c == '"' {
				i++
				return true
			}
			if c < 0x20 {
				return false
			}
			if c == '\\' {
				i++
				if i >= n {
					return false
				}
				switch b[i] {
				case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
					i++
				case 'u':
					if i+4 >= n {
						return false
					}
					var cp uint16
					for k := 1; k <= 4; k++ {
						hc := b[i+k]
						cp <<= 4
						switch {
						case hc >= '0' && hc <= '9':
							cp |= uint16(hc - '0')
						case hc >= 'a' && hc <= 'f':
							cp |= uint16(hc - 'a' + 10)
						case hc >= 'A' && hc <= 'F':
							cp |= uint16(hc - 'A' + 10)
						default:
							return false
						}
					}
					if cp >= 0xD800 && cp <= 0xDFFF {
						return false
					}
					i += 5
				default:
					return false
				}
				continue
			}
			i++
		}
		return false
	}
	skipNumber := func() bool {
		if i < n && b[i] == '-' {
			i++
		}
		if i >= n {
			return false
		}
		if b[i] == '0' {
			i++
			if i < n && b[i] >= '0' && b[i] <= '9' {
				return false
			}
		} else if b[i] >= '1' && b[i] <= '9' {
			i++
			for i < n && b[i] >= '0' && b[i] <= '9' {
				i++
			}
		} else {
			return false
		}
		if i < n && b[i] == '.' {
			i++
			if i >= n || b[i] < '0' || b[i] > '9' {
				return false
			}
			for i < n && b[i] >= '0' && b[i] <= '9' {
				i++
			}
		}
		if i < n && (b[i] == 'e' || b[i] == 'E') {
			i++
			if i < n && (b[i] == '+' || b[i] == '-') {
				i++
			}
			if i >= n || b[i] < '0' || b[i] > '9' {
				return false
			}
			for i < n && b[i] >= '0' && b[i] <= '9' {
				i++
			}
		}
		return true
	}

	keyPool := make([][2]int, 0, 64)
	var scanVal func(depth int) (bool, error)
	scanVal = func(depth int) (bool, error) {
		if depth > 64 {
			return true, errors.New("nesting")
		}
		skipWS()
		if i >= n {
			return false, nil
		}
		switch b[i] {
		case '{':
			i++
			skipWS()
			if i < n && b[i] == '}' {
				i++
				return true, nil
			}
			frameBase := len(keyPool)
			defer func() { keyPool = keyPool[:frameBase] }()
			var seen map[string]struct{}
			for {
				skipWS()
				if i >= n || b[i] != '"' {
					return false, nil
				}
				i++
				ks := i
				for i < n {
					c := b[i]
					if c == '"' {
						break
					}
					if c == '\\' || c < 0x20 {
						return false, nil
					}
					i++
				}
				if i >= n {
					return false, nil
				}
				ke := i
				i++
				kBytes := b[ks:ke]
				if seen != nil {
					if _, dup := seen[string(kBytes)]; dup {
						return true, errors.New("duplicate key")
					}
					seen[string(kBytes)] = struct{}{}
				} else {
					curKeys := keyPool[frameBase:]
					for _, sp := range curKeys {
						if bytes.Equal(b[sp[0]:sp[1]], kBytes) {
							return true, errors.New("duplicate key")
						}
					}
					if len(curKeys) >= 16 {
						seen = make(map[string]struct{}, 32)
						for _, sp := range curKeys {
							seen[string(b[sp[0]:sp[1]])] = struct{}{}
						}
						seen[string(kBytes)] = struct{}{}
					} else {
						keyPool = append(keyPool, [2]int{ks, ke})
					}
				}
				skipWS()
				if i >= n || b[i] != ':' {
					return false, nil
				}
				i++
				if ok, e := scanVal(depth + 1); !ok || e != nil {
					return ok, e
				}
				skipWS()
				if i >= n {
					return false, nil
				}
				if b[i] == '}' {
					i++
					return true, nil
				}
				if b[i] != ',' {
					return false, nil
				}
				i++
			}
		case '[':
			i++
			skipWS()
			if i < n && b[i] == ']' {
				i++
				return true, nil
			}
			for {
				if ok, e := scanVal(depth + 1); !ok || e != nil {
					return ok, e
				}
				skipWS()
				if i >= n {
					return false, nil
				}
				if b[i] == ']' {
					i++
					return true, nil
				}
				if b[i] != ',' {
					return false, nil
				}
				i++
			}
		case '"':
			if !skipStringValue() {
				return false, nil
			}
			return true, nil
		case 't':
			if i+4 <= n && string(b[i:i+4]) == "true" {
				i += 4
				return true, nil
			}
			return false, nil
		case 'f':
			if i+5 <= n && string(b[i:i+5]) == "false" {
				i += 5
				return true, nil
			}
			return false, nil
		case 'n':
			if i+4 <= n && string(b[i:i+4]) == "null" {
				i += 4
				return true, nil
			}
			return false, nil
		default:
			if b[i] == '-' || (b[i] >= '0' && b[i] <= '9') {
				if !skipNumber() {
					return false, nil
				}
				return true, nil
			}
			return false, nil
		}
	}
	ok, err := scanVal(0)
	if err != nil {
		return true, err
	}
	if !ok {
		return false, nil
	}
	skipWS()
	if i != n {
		return true, errors.New("trailing JSON")
	}
	return true, nil
}

// Reject duplicate keys before UI and kernel decoders can disagree.
func uniqueJSON(b []byte) error {
	if handled, err := fastUniqueJSON(b); handled {
		return err
	}
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
	encodedLen := encodedJSONStringLen(text)
	if encodedLen+len(workspace) > MaxFrame-2048 {
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
	} else if uniqueJSON(projection) != nil {
		return out, fail("invalid_document", "text", "Invalid or ambiguous UTF-8 JSON")
	}
	prevText := text
	var legacyErr error
	text, projection, legacyErr = normalizeLegacySmartSource(text, format, projection)
	if legacyErr != nil {
		if errors.Is(legacyErr, errLegacySmartSubscription) {
			return out, fail("legacy_smart_subscription_unsupported", "subscriptions", "含 Smart 的旧版订阅（Model<2）所有权升级可能回灌旧凭据，暂不支持；未创建备份，未修改配置或运行态")
		}
		return out, fail("invalid_document", "kernel.groups", "Invalid Smart or group declaration")
	}
	out.text = text
	out.projection = projection
	out.projectedText = text
	if text != prevText {
		encodedLen = encodedJSONStringLen(text)
	}
	if len(text) > maxDocument || encodedLen+len(workspace) > MaxFrame-2048 {
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
	var clientFields map[string]json.RawMessage
	if len(cb) == 0 || cb[0] != '{' || json.Unmarshal(cb, &clientFields) != nil {
		return out, fail("invalid_document", "client", "Expected client object")
	}
	if runtime.GOOS == "windows" {
		var kernelFields map[string]json.RawMessage
		_ = json.Unmarshal(root.Kernel, &kernelFields)
		out.advancedDNS = advancedDNSFields(clientFields, kernelFields)
		if out.advancedDNS {
			safeClient := map[string]json.RawMessage{}
			for k, v := range clientFields {
				if k != "tun_dns" {
					safeClient[k] = v
				}
			}
			cb, _ = json.Marshal(safeClient)
		}
	}
	if json.Unmarshal(cb, &out.client) != nil {
		return out, fail("invalid_document", "client", "Expected client object")
	}
	if v, ok := clientFields["ipv6"]; ok && string(v) != "true" && string(v) != "false" {
		return out, fail("invalid_document", "client.ipv6", "Expected boolean")
	}
	if v, ok := clientFields["close_on_switch"]; ok && string(v) != "true" && string(v) != "false" {
		return out, fail("invalid_document", "client.close_on_switch", "Expected boolean")
	}
	if e := validateTunDNS(cb); e != nil {
		return out, e
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
	if runtime.GOOS == "windows" {
		out.advancedDNS = advancedDNSFields(clientFields, raw)
		// Retired inputs are kept in out.text only. They never execute, even when
		// latent/empty; the accepted enable/apply boundary requires explicit choice.
		if out.advancedDNS {
			sanitizeDNSProjection(raw)
			out.client.TunDNS = nil
		}
	}
	if format != FormatJSON && !out.advancedDNS {
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
	if cl.Sniff == nil {
		inbound.Sniff = &kernel.SniffOptions{Enabled: true, OverrideDestination: true}
	} else if cl.Sniff.Enabled {
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
	if c.Stats == nil {
		c.Stats = &kernel.StatsOptions{}
	}
	c.Stats.File = filepath.Join(workspace, "runtime.stats.json")
	c.Stats.Persist = &off
	for _, p := range c.Providers {
		if p.Type == "file" {
			if st, e := userio.Stat(p.Path); e == nil && !st.Mode().IsRegular() {
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
	out.ruleRouting = c.Routing
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
	detour := ""
	if out.ruleRouting != nil {
		detour = out.ruleRouting.Final
	}
	if cl.Mode == "global" {
		detour = cl.GlobalGroup
	}
	// Capture the original DNS settings before projecting the desktop's system
	// default. Hosts/rules/cache alone do not select a root upstream, and the
	// original cache value stays available to explicit per-domain upstreams.
	tunDNS := cl.TunDNS
	if out.advancedDNS {
		tunDNS = nil
	}
	c.SetClientDNSConfig(c.DNS, tunDNS, cl.Mode, detour)
	c.SetClientIPv6(cl.IPv6)
	c.SetClientUnifiedDelay(cl.UnifiedDelay == nil || *cl.UnifiedDelay)
	ownedGroups := map[string]bool{}
	customProbeURLGroups := map[string]bool{}
	owners, _ := subscriptionsOf(map[string]json.RawMessage{"subscriptions": root.Subscriptions})
	for _, s := range owners {
		for _, g := range s.Snapshot.Groups {
			name := rawName(g)
			ownedGroups[name] = true
			if patch, ok := s.Overlay.Groups[name]; ok {
				if pm := rawObject(patch["probe"]); pm["url"] != nil {
					customProbeURLGroups[name] = true
				}
			}
		}
	}
	for i := range c.Groups {
		g := &c.Groups[i]
		if ownedGroups[g.Name] && g.Probe != nil {
			probe := *g.Probe
			if probe.Interval == 0 {
				probe.Interval = outbound.Duration(300 * time.Second)
				if g.Type == "url-test" {
					probe.Interval = outbound.Duration(time.Minute)
				}
			}
			if !customProbeURLGroups[g.Name] && probe.URL == "https://www.gstatic.com/generate_204" && cl.ProbeURL != "" {
				probe.URL = cl.ProbeURL
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
	st, e := userio.Lstat(path)
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
	f, e := userio.Open(path)
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
	if st, e := userio.Lstat(path); e == nil && (!st.Mode().IsRegular() || rejectReparse(path) != nil) {
		return errors.New("nonregular destination")
	} else if e != nil && !os.IsNotExist(e) {
		return e
	}
	f, e := userio.CreateTemp(filepath.Dir(path), ".kat-write-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer userio.Remove(tmp)
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
