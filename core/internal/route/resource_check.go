package route

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"gopkg.in/yaml.v3"
)

// SubscriptionSetDependencies describes configured databases, not fabricated
// lookup results. Validate their bytes separately before importing the policy.
type SubscriptionSetDependencies struct{ GeoIP, ASN, Geosite bool }

// SubscriptionSetIssue uses 1-based payload Entry and physical Line (0 when
// unavailable). Rule text, URLs, paths and credentials are not included.
type SubscriptionSetIssue struct {
	Resource   string `json:"resource,omitempty"`
	Entry      int    `json:"entry,omitempty"`
	Line       int    `json:"line,omitempty"`
	RuleType   string `json:"rule_type,omitempty"`
	Code       string `json:"code"`
	Dependency string `json:"dependency,omitempty"`
}
type SubscriptionSetValidationError struct{ Issues []SubscriptionSetIssue }

func (e *SubscriptionSetValidationError) Error() string {
	if len(e.Issues) == 0 {
		return "route: invalid rule set"
	}
	i := e.Issues[0]
	return fmt.Sprintf("route: %s at payload entry %d (line %d), type %s, dependency %s (%d issue(s))", i.Code, i.Entry, i.Line, i.RuleType, i.Dependency, len(e.Issues))
}

// ValidateSubscriptionSet is the compatible country-only wrapper. It does not
// pretend that passing a country database also enables ASN or geosite.
func ValidateSubscriptionSet(s RuleSetOptions, b []byte, geo bool) (int, error) {
	return ValidateSubscriptionSetWithDependencies(s, b, SubscriptionSetDependencies{GeoIP: geo})
}

func ValidateSubscriptionSetWithDependencies(s RuleSetOptions, b []byte, deps SubscriptionSetDependencies) (int, error) {
	if len(b) > 16<<20 {
		return 0, errTooLarge
	}
	env := parseEnv{geoip: deps.GeoIP, asn: deps.ASN, geosite: deps.Geosite}
	// Preflight line formats with the actual runtime condition parser. Preserve
	// every invalid entry's position rather than allowing parseLines to skip it.
	var lines []string
	var positions []int
	behavior := s.Behavior
	dialect := dialMihom
	switch s.Format {
	case FormatYAML:
		var err error
		lines, err = yamlPayload(b)
		if err != nil {
			return 0, err
		}
		var doc yaml.Node
		if yaml.Unmarshal(b, &doc) == nil && len(doc.Content) > 0 {
			m := doc.Content[0]
			for j := 0; j+1 < len(m.Content); j += 2 {
				if m.Content[j].Value == "payload" {
					for _, n := range m.Content[j+1].Content {
						positions = append(positions, n.Line)
					}
				}
			}
		}
	case FormatDomain, FormatIPCIDR, FormatClassical, FormatSurgeDomainSet, FormatSurgeRuleSet:
		text, err := textOf(b)
		if err != nil {
			return 0, err
		}
		lines = strings.Split(text, "\n")
		for j := range lines {
			positions = append(positions, j+1)
		}
		switch s.Format {
		case FormatDomain:
			behavior = "domain"
			dialect = dialKat
		case FormatIPCIDR:
			behavior = "ipcidr"
			dialect = dialKat
		case FormatClassical:
			behavior = "classical"
		case FormatSurgeDomainSet:
			behavior = "domain"
			dialect = dialSurge
		case FormatSurgeRuleSet:
			behavior = "classical"
			dialect = dialSurge
		}
	}
	var issues []SubscriptionSetIssue
	for j, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		var err error
		typ := ""
		dependency := ""
		switch behavior {
		case "classical":
			typ, _, _ = strings.Cut(line, ",")
			typ = strings.ToUpper(strings.TrimSpace(typ))
			_, err = parseClassical(line, dialect, fullEnv, 0) // Syntax before dependency.
			if err == nil {
				_, err = parseClassical(line, dialect, env, 0)
			}
			if err == nil && !deps.GeoIP {
				dependency = missingCountryDependency(line, dialect)
				if dependency != "" {
					err = unsupported("database dependency")
				}
			}
		case "domain":
			var d domainSet
			if !d.addDomainEntry(line, dialect) {
				err = errMalformed
			}
		case "ipcidr":
			if _, ok := parseCIDR(line, true); !ok {
				err = errMalformed
			}
		}
		if err == nil {
			continue
		}
		code := "invalid_format"
		var u *unsupportedError
		if errors.As(err, &u) {
			code = "unsupported_type"
			switch {
			case strings.Contains(u.msg, "without an asn block"):
				dependency = "asn"
			case strings.Contains(u.msg, "without a geosite block"):
				dependency = "geosite"
			case strings.HasPrefix(u.msg, "option "):
				code = "unsupported_option"
			}
		}
		if dependency != "" {
			code = "missing_dependency"
		}
		n := 0
		if j < len(positions) {
			n = positions[j]
		}
		issues = append(issues, SubscriptionSetIssue{Resource: s.Name, Entry: j + 1, Line: n, RuleType: typ, Code: code, Dependency: dependency})
	}
	if len(issues) > 0 {
		return 0, &SubscriptionSetValidationError{Issues: issues}
	}
	d, err := parseRuleSetAs(s.Format, s.Behavior, b, maxSetEntries, env)
	if err != nil {
		return 0, err
	}
	if d.skipped != 0 {
		return 0, &SubscriptionSetValidationError{Issues: []SubscriptionSetIssue{{Resource: s.Name, Code: "invalid_format"}}}
	}
	return d.entries, nil
}

// Recursively inspect a parsed condition so GEOIP in logical classical rules
// receives the same explicit dependency check as a direct country rule.
func missingCountryDependency(line string, dialect int) string {
	c, err := parseClassical(line, dialect, fullEnv, 0)
	if err != nil {
		return ""
	}
	var country func(*cond) bool
	country = func(c *cond) bool {
		if (c.kind == kGeoIP || c.kind == kSrcGeoIP) && c.s != geoPrivate {
			return true
		}
		for _, s := range c.subs {
			if country(s) {
				return true
			}
		}
		return false
	}
	if country(c) {
		return "geoip"
	}
	return ""
}

// ValidateSubscriptionASN checks the same MMDB reader used at runtime and
// requires real nonzero autonomous_system_number fields, not just a valid
// country DB container. No database path/source selection is performed here.
func ValidateSubscriptionASN(b []byte) error {
	if len(b) > 64<<20 {
		return errTooLarge
	}
	db, err := parseASNDB(b)
	if err != nil {
		return err
	}
	defer db.r.Close()
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "223.5.5.5", "114.114.114.114"} {
		if db.lookup(netip.MustParseAddr(s)) != 0 {
			return nil
		}
	}
	// Sparse but valid ASN databases need not include the public probes.
	networks := db.r.Networks()
	for networks.Next() {
		var rec asnRecord
		_, err := networks.Network(&rec)
		if err != nil {
			return err
		}
		if rec.ASN != 0 {
			return nil
		}
	}
	if err := networks.Err(); err != nil {
		return err
	}
	return errors.New("MMDB has no compatible autonomous_system_number fields")
}

// ValidateSubscriptionGeoIP verifies the same MMDB reader and country fields
// used by Decide. It never supplies a fabricated country for missing data.
func ValidateSubscriptionGeoIP(b []byte) error {
	if len(b) > 64<<20 {
		return errTooLarge
	}
	db, e := parseGeoIP(b)
	if e != nil {
		return e
	}
	defer db.r.Close()
	found := false
	for _, s := range []string{"223.5.5.5", "114.114.114.114", "1.1.1.1", "8.8.8.8"} {
		c := db.country(netip.MustParseAddr(s))
		if len(c) == 2 {
			found = true
		}
	}
	if !found {
		return errors.New("MMDB has no compatible country fields")
	}
	return nil
}
