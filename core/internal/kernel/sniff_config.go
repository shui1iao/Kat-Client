package kernel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/procattr"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/shui1iao/Kat/internal/route"
)

// DefaultSkipDomains is the built-in skip_domain exclusion list used when
// SniffOptions.SkipDomain is nil (omitted in user configuration).
var DefaultSkipDomains = []string{"+.push.apple.com", "Mijia Cloud", "+.io.mi.com", "+.cloudflare-ech.com"}

var defaultSkipPatterns = func() []sniffSkipPattern {
	p, _ := compileSkipDomains(DefaultSkipDomains)
	return p
}()

type sniffSkipPattern struct {
	suffix bool
	value  string // lower-case normalized
}

func validateSkipSuffixBody(rest string) error {
	body := strings.TrimSuffix(rest, ".")
	if body == "" || strings.IndexFunc(body, unicode.IsSpace) >= 0 {
		return errors.New("sniff skip_domain suffix must not be empty")
	}
	for _, label := range strings.Split(body, ".") {
		if label == "" {
			return errors.New("sniff skip_domain suffix must not contain empty labels")
		}
	}
	return nil
}

func ValidateSkipDomains(list []string) error {
	if len(list) > 128 {
		return errors.New("sniff skip_domain allows at most 128 entries")
	}
	for _, raw := range list {
		if !utf8.ValidString(raw) {
			return errors.New("sniff skip_domain must be valid UTF-8")
		}
		for _, r := range raw {
			if unicode.IsControl(r) {
				return errors.New("sniff skip_domain must not contain control characters")
			}
		}
		s := strings.TrimSpace(raw)
		if len(s) < 1 || len(s) > 253 {
			return errors.New("sniff skip_domain entry must be 1..253 bytes")
		}
		switch {
		case strings.HasPrefix(s, "+."), strings.HasPrefix(s, "*."):
			if err := validateSkipSuffixBody(s[2:]); err != nil {
				return err
			}
		case strings.HasPrefix(s, "."):
			if err := validateSkipSuffixBody(s[1:]); err != nil {
				return err
			}
		default:
			if strings.Trim(s, ". ") == "" {
				return errors.New("sniff skip_domain entry must not be empty")
			}
		}
	}
	return nil
}

func compileSkipDomains(list []string) ([]sniffSkipPattern, error) {
	if err := ValidateSkipDomains(list); err != nil {
		return nil, err
	}
	out := make([]sniffSkipPattern, 0, len(list))
	for _, raw := range list {
		s := strings.ToLower(strings.TrimSpace(raw))
		switch {
		case strings.HasPrefix(s, "+."):
			v := strings.TrimSuffix(s[2:], ".")
			out = append(out, sniffSkipPattern{suffix: true, value: v})
		case strings.HasPrefix(s, "*."):
			v := strings.TrimSuffix(s[2:], ".")
			out = append(out, sniffSkipPattern{suffix: true, value: v})
		case strings.HasPrefix(s, "."):
			v := strings.TrimSuffix(s[1:], ".")
			out = append(out, sniffSkipPattern{suffix: true, value: v})
		default:
			v := strings.TrimSuffix(s, ".")
			if v == "" {
				v = s
			}
			out = append(out, sniffSkipPattern{suffix: false, value: v})
		}
	}
	return out, nil
}

// SniffOptions enables traffic sniffing on one inbound (0.7.0). The sniffed
// domain (TLS SNI, HTTP Host, QUIC SNI) and protocol are used by the rules;
// with override_destination an IP destination is replaced by the domain and
// resolved by the server.
type SniffOptions struct {
	Enabled             bool     `json:"enabled"`
	TCPPorts            string   `json:"tcp_ports,omitempty"` // default 80,443,8080,8443; "none" disables
	UDPPorts            string   `json:"udp_ports,omitempty"` // default 443; "none" disables
	Timeout             Duration `json:"timeout,omitempty"`   // first-data wait, default 300ms
	OverrideDestination bool     `json:"override_destination,omitempty"`
	SkipDomain          []string `json:"skip_domain,omitempty"`

	tcp, udp  route.PortList
	skip      []sniffSkipPattern
	skipReady bool
}

func (o SniffOptions) MarshalJSON() ([]byte, error) {
	m := map[string]any{
		"enabled": o.Enabled,
	}
	if o.TCPPorts != "" {
		m["tcp_ports"] = o.TCPPorts
	}
	if o.UDPPorts != "" {
		m["udp_ports"] = o.UDPPorts
	}
	if o.Timeout != 0 {
		m["timeout"] = o.Timeout
	}
	if o.OverrideDestination {
		m["override_destination"] = true
	}
	if o.SkipDomain != nil {
		m["skip_domain"] = o.SkipDomain
	}
	return json.Marshal(m)
}

func (o *SniffOptions) UnmarshalJSON(b []byte) error {
	type plain SniffOptions
	var p plain
	if e := strictNetworkJSON(b, &p); e != nil {
		return e
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(b, &m)
	if raw, ok := m["skip_domain"]; ok {
		var items []json.RawMessage
		if json.Unmarshal(raw, &items) != nil {
			return errNetworkConfig
		}
		for _, item := range items {
			it := bytes.TrimSpace(item)
			if len(it) == 0 || it[0] != '"' {
				return errNetworkConfig
			}
		}
		if p.SkipDomain == nil {
			p.SkipDomain = []string{}
		}
	}
	*o = SniffOptions(p)
	return nil
}

const (
	defaultSniffTCPPorts = "80,443,8080,8443"
	defaultSniffUDPPorts = "443"
	defaultSniffTimeout  = 300 * time.Millisecond
	maxSniffTimeout      = 2 * time.Second
)

func (o *SniffOptions) normalize() error {
	parse := func(s *string, def string, dst *route.PortList) error {
		if *s == "" {
			*s = def
		}
		if *s == "none" {
			*dst = nil
			return nil
		}
		l, ok := route.ParsePorts(*s)
		if !ok {
			return errors.New("sniff ports must be ports, ranges a-b or a list of them (or none)")
		}
		*dst = l
		return nil
	}
	if e := parse(&o.TCPPorts, defaultSniffTCPPorts, &o.tcp); e != nil {
		return e
	}
	if e := parse(&o.UDPPorts, defaultSniffUDPPorts, &o.udp); e != nil {
		return e
	}
	if o.Timeout == 0 {
		o.Timeout = Duration(defaultSniffTimeout)
	}
	if o.Timeout.value() < time.Millisecond || o.Timeout.value() > maxSniffTimeout {
		return errors.New("sniff timeout must be between 1ms and 2s")
	}
	if o.SkipDomain == nil {
		o.skip = defaultSkipPatterns
	} else {
		p, e := compileSkipDomains(o.SkipDomain)
		if e != nil {
			return e
		}
		o.skip = p
	}
	o.skipReady = true
	return nil
}

func (o *SniffOptions) skipDomain(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false
	}
	patterns := defaultSkipPatterns
	if o != nil {
		if o.skipReady {
			patterns = o.skip
		} else if o.SkipDomain != nil {
			patterns, _ = compileSkipDomains(o.SkipDomain)
		}
	}
	for _, p := range patterns {
		if p.suffix {
			if h == p.value || (len(h) > len(p.value) && strings.HasSuffix(h, p.value) && h[len(h)-len(p.value)-1] == '.') {
				return true
			}
		} else if h == p.value {
			return true
		}
	}
	return false
}

// sniffTCP reports whether a TCP stream to port is sniffed on this inbound.
func (in *Inbound) sniffTCP(port uint16) bool {
	return in.Sniff != nil && in.Sniff.Enabled && in.Sniff.tcp.Contains(port)
}

// validateInboundRefs checks inbound names, sniff options and that every
// in_name rule refers to a named inbound.
func (c *Config) validateInboundRefs(ro route.Options) error {
	names := map[string]bool{}
	for i := range c.Inbounds {
		in := &c.Inbounds[i]
		if in.Name != "" {
			if !validOutboundName(in.Name) || names[in.Name] {
				return fmt.Errorf("inbound %d: invalid or duplicate name", i)
			}
			names[in.Name] = true
		}
		if in.Sniff != nil {
			if e := in.Sniff.normalize(); e != nil {
				return fmt.Errorf("inbound %d: %v", i, e)
			}
		}
	}
	for _, n := range ro.ReferencedInboundNames() {
		if !names[n] {
			return fmt.Errorf("routing: in_name %q is not the name of an inbound", n)
		}
	}
	return nil
}

// inboundMeta carries the routing attributes of the accepting inbound.
type inboundMeta struct {
	name, typ     string
	port          uint16
	srcPort       uint16
	local, remote netip.AddrPort
	process       *inboundProcess
	sniff         *SniffOptions // nil or disabled: no sniffing
}

// The attribution cache belongs to the accepted connection and is shared by
// reload-specific metadata views. Never copy a used sync.Once.
type inboundProcess struct {
	once     sync.Once
	identity procattr.Identity
}

type inMetaKey struct{}

// withInboundMeta attaches the inbound's name, type, local port (from the
// accepted socket, so port 0 listeners report the real port) and sniffing.
func withInboundMeta(ctx context.Context, in *Inbound, local, remote net.Addr) context.Context {
	m := &inboundMeta{process: &inboundProcess{}, name: in.Name, typ: in.Protocol, srcPort: addrPort(remote).Port(), local: procattr.Addr(local), remote: procattr.Addr(remote)}
	if a := addrPort(local); a.IsValid() {
		m.port = a.Port()
	} else if _, p, e := net.SplitHostPort(in.Listen); e == nil {
		n, _ := strconv.Atoi(p)
		m.port = uint16(n)
	}
	if in.Sniff != nil {
		m.sniff = in.Sniff
	}
	return context.WithValue(ctx, inMetaKey{}, m)
}

// listenerSlot is the reload identity of inbound i of inbounds: its listen
// key, with port 0 listeners numbered per address as reload numbers them.
func listenerSlot(inbounds []Inbound, i int) string {
	key := listenKey(inbounds[i].Listen)
	if !ephemeralPort(key) {
		return key
	}
	n := 0
	for j := 0; j < i; j++ {
		if listenKey(inbounds[j].Listen) == key {
			n++
		}
	}
	return key + "#" + strconv.Itoa(n)
}

// currentInboundMeta gives a stream of a session accepted by an older
// generation (AnyTLS) the inbound attributes (name, sniffing) of the current
// generation's inbound on the same listener, as its routing is the current
// one. Without such an inbound the accepting attributes stay.
func (s *Server) currentInboundMeta(ctx context.Context, acc *Server) context.Context {
	m := inboundMetaOf(ctx)
	i := inboundOf(ctx)
	if m == nil || s == acc || i < 0 || i >= len(acc.cfg.Inbounds) {
		return ctx
	}
	slot := listenerSlot(acc.cfg.Inbounds, i)
	for j := range s.cfg.Inbounds {
		in := &s.cfg.Inbounds[j]
		if in.Protocol != m.typ || listenerSlot(s.cfg.Inbounds, j) != slot {
			continue
		}
		n := *m
		n.name, n.sniff = in.Name, nil
		if in.Sniff != nil {
			n.sniff = in.Sniff
		}
		return context.WithValue(ctx, inMetaKey{}, &n)
	}
	return ctx
}

func inboundMetaOf(ctx context.Context) *inboundMeta {
	m, _ := ctx.Value(inMetaKey{}).(*inboundMeta)
	return m
}

func addrPort(a net.Addr) netip.AddrPort {
	switch v := a.(type) {
	case *net.TCPAddr:
		if v != nil {
			return v.AddrPort()
		}
	case *net.UDPAddr:
		if v != nil {
			return v.AddrPort()
		}
	case nil:
	default:
		if ap, e := netip.ParseAddrPort(a.String()); e == nil {
			return ap
		}
	}
	return netip.AddrPort{}
}
