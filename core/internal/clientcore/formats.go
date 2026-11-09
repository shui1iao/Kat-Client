package clientcore

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"regexp"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// DocumentFormat is extension-specific, not a format auto-detection hint.
type DocumentFormat string

const (
	FormatJSON DocumentFormat = "json"
	FormatYAML DocumentFormat = "yaml"
	FormatYML  DocumentFormat = "yml"
)

func (f DocumentFormat) valid() bool      { return f == FormatJSON || f == FormatYAML || f == FormatYML }
func (f DocumentFormat) filename() string { return "kat-client." + string(f) }

type documentCounts struct {
	Nodes     int `json:"nodes"`
	Groups    int `json:"groups"`
	Rules     int `json:"rules"`
	Providers int `json:"providers"`
}

func (d document) validation() any {
	return map[string]any{"advanced_dns": d.advancedDNS, "valid": true, "format": d.format,
		"ports": map[string]int{"http": d.client.HTTPPort, "socks": d.client.SOCKSPort}, "counts": d.counts}
}

const maxYAMLNodes = 65536

var decimalYAML = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)
var errYAML = errors.New("unsupported YAML")

// Decode to a bounded syntax tree, never into interface{}: yaml's generic
// decoder can silently coerce keys, lose integer precision, or expand aliases.
// The projection is validation-only; the caller always retains original bytes.
func yamlJSON(b []byte) ([]byte, error) {
	if !utf8.Valid(b) || len(b) > maxDocument {
		return nil, errYAML
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errYAML
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, errYAML
	}
	budget := maxYAMLNodes
	v, err := yamlValue(root.Content[0], 0, &budget)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(v)
	if err != nil || len(out) > maxDocument {
		return nil, errYAML
	}
	return out, nil
}
func yamlValue(n *yaml.Node, depth int, budget *int) (any, error) {
	*budget--
	if depth > 64 || *budget < 0 || n.Anchor != "" || n.Alias != nil || n.Kind == yaml.AliasNode {
		return nil, errYAML
	}
	switch n.Kind {
	case yaml.MappingNode:
		if n.Tag != "!!map" || len(n.Content)%2 != 0 || len(n.Content) > *budget {
			return nil, errYAML
		}
		m := make(map[string]any, len(n.Content)/2)
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i]
			// Visit keys too: tagged keys and anchors must not evade the budget/policy.
			key, err := yamlValue(k, depth+1, budget)
			if err != nil || k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
				return nil, errYAML
			}
			s, ok := key.(string)
			if !ok || s == "<<" {
				return nil, errYAML
			}
			if _, exists := m[s]; exists {
				return nil, errYAML
			}
			v, err := yamlValue(n.Content[i+1], depth+1, budget)
			if err != nil {
				return nil, err
			}
			m[s] = v
		}
		return m, nil
	case yaml.SequenceNode:
		if n.Tag != "!!seq" || len(n.Content) > *budget {
			return nil, errYAML
		}
		a := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := yamlValue(c, depth+1, budget)
			if err != nil {
				return nil, err
			}
			a = append(a, v)
		}
		return a, nil
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str":
			// yaml.v3's resolver falls back to !!str on machine-number overflow.
			// Recover only unquoted numeric lexemes, without any float64 round trip.
			// Explicit !!str and quoted/block strings must remain strings.
			if n.Style == 0 {
				s := strings.ReplaceAll(n.Value, "_", "")
				if decimalYAML.MatchString(s) {
					u := strings.TrimLeft(s, "+-")
					if !strings.ContainsAny(s, ".eE") && len(u) > 1 && u[0] == '0' {
						// Only legacy octal needs radix conversion; decimal overflow
						// can stay a lexeme, with no large-integer arithmetic.
						if v, ok := new(big.Int).SetString(s, 0); ok {
							return json.Number(v.String()), nil
						}
					}
					return yamlDecimal(s)
				}
				u := strings.TrimPrefix(strings.TrimPrefix(s, "+"), "-")
				if strings.HasPrefix(u, "0x") || strings.HasPrefix(u, "0o") || strings.HasPrefix(u, "0b") {
					if v, ok := new(big.Int).SetString(s, 0); ok {
						return json.Number(v.String()), nil
					}
				}
			}
			return n.Value, nil
		case "!!null":
			if n.Value == "" || n.Value == "~" || strings.EqualFold(n.Value, "null") {
				return nil, nil
			}
		case "!!bool":
			if strings.EqualFold(n.Value, "true") {
				return true, nil
			}
			if strings.EqualFold(n.Value, "false") {
				return false, nil
			}
		case "!!int":
			s := strings.ReplaceAll(n.Value, "_", "")
			// yaml.v3 resolves legacy leading-zero octal as well as 0o/0x/0b.
			v, ok := new(big.Int).SetString(s, 0)
			if ok {
				return json.Number(v.String()), nil
			}
		case "!!float":
			return yamlDecimal(n.Value)
		}
	}
	// Includes custom tags, timestamps, sets, binary, non-finite numbers, aliases.
	return nil, errYAML
}

// Normalize only the JSON number spelling, never its precision or source text.
func yamlDecimal(value string) (any, error) {
	s := strings.ReplaceAll(value, "_", "")
	if !decimalYAML.MatchString(s) {
		return nil, errYAML
	}
	sign := ""
	if s[0] == '+' || s[0] == '-' {
		if s[0] == '-' {
			sign = "-"
		}
		s = s[1:]
	}
	mantissa, exponent := s, ""
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		mantissa, exponent = s[:i], s[i:]
	}
	whole, fraction, dot := strings.Cut(mantissa, ".")
	whole = strings.TrimLeft(whole, "0")
	if whole == "" {
		whole = "0"
	}
	s = sign + whole
	if dot {
		if fraction == "" {
			fraction = "0"
		}
		s += "." + fraction
	}
	// No float64 conversion: even long decimals and >53-bit integers survive.
	return json.Number(s + exponent), nil
}
