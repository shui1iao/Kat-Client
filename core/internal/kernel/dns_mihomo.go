package kernel

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// DNSHosts accepts mihomo's scalar-or-list values, but marshals the native
// multi-address form. Source documents are never marshalled from this runtime.
type DNSHosts map[string][]string

func (h *DNSHosts) UnmarshalJSON(b []byte) error {
	var raw map[string]json.RawMessage
	if json.Unmarshal(b, &raw) != nil || raw == nil {
		return errNetworkConfig
	}
	out := DNSHosts{}
	for name, v := range raw {
		var addresses []string
		var one string
		if json.Unmarshal(v, &one) == nil {
			addresses = []string{one}
		} else if json.Unmarshal(v, &addresses) != nil || addresses == nil {
			return errNetworkConfig
		}
		out[name] = addresses
	}
	*h = out
	return nil
}

// DecodeMihomoDNSPolicy preserves declaration order (first match wins). The
// supported import subset is exact / +.suffix. Document export retains the
// original DNS field spelling in both JSON and YAML; native keyword rules stay
// in rules and never undergo a forced mihomo conversion. Unsupported selectors
// are rejected on import, not guessed or silently dropped.
func DecodeMihomoDNSPolicy(b []byte) ([]DNSRule, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	tok, e := d.Token()
	if e != nil || tok != json.Delim('{') {
		return nil, errNetworkConfig
	}
	rules := []DNSRule{}
	seen := map[string]bool{}
	for d.More() {
		tok, e := d.Token()
		if e != nil {
			return nil, errNetworkConfig
		}
		key, ok := tok.(string)
		if !ok || seen[key] {
			return nil, errNetworkConfig
		}
		seen[key] = true
		r := DNSRule{Match: "domain", Domain: key}
		switch {
		case strings.HasPrefix(key, "+."):
			r.Match = "domain_suffix"
			r.Domain = key[2:]
		case strings.ContainsAny(key, ":*+"):
			return nil, errNetworkConfig
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, errNetworkConfig
		}
		var server string
		if json.Unmarshal(value, &server) == nil {
			r.Servers = []string{server}
		} else if json.Unmarshal(value, &r.Servers) != nil {
			return nil, errNetworkConfig
		}
		rules = append(rules, r)
	}
	if _, e = d.Token(); e != nil {
		return nil, errNetworkConfig
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errNetworkConfig
	}
	if e := validateDNSPolicy(&DNSOptions{Rules: rules}); e != nil {
		return nil, e
	}
	return rules, nil
}
func effectiveDNSRules(o *DNSOptions) ([]DNSRule, error) {
	if o == nil {
		return nil, nil
	}
	if o.NameserverPolicy != nil {
		if len(o.Rules) > 0 {
			return nil, errNetworkConfig
		}
		return DecodeMihomoDNSPolicy(o.NameserverPolicy)
	}
	return o.Rules, nil
}
