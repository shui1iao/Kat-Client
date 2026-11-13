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

func setUsesCountryGeoIP(d *setData) bool {
	if d == nil {
		return false
	}
	var hasCountry func(*cond) bool
	hasCountry = func(c *cond) bool {
		if c == nil {
			return false
		}
		if (c.kind == kGeoIP || c.kind == kSrcGeoIP) && c.s != geoPrivate {
			return true
		}
		for _, sub := range c.subs {
			if hasCountry(sub) {
				return true
			}
		}
		return false
	}
	for _, code := range d.geo {
		if code != geoPrivate {
			return true
		}
	}
	for _, code := range d.geoNR {
		if code != geoPrivate {
			return true
		}
	}
	for _, c := range d.extra {
		if hasCountry(c) {
			return true
		}
	}
	return false
}

func yamlLinePositions(b []byte) []int {
	var positions []int
	var doc yaml.Node
	if yaml.Unmarshal(b, &doc) == nil && len(doc.Content) > 0 {
		m := doc.Content[0]
		for j := 0; j+1 < len(m.Content); j += 2 {
			if m.Content[j].Value == "payload" {
				positions = make([]int, 0, len(m.Content[j+1].Content))
				for _, n := range m.Content[j+1].Content {
					positions = append(positions, n.Line)
				}
			}
		}
	}
	return positions
}

func ValidateSubscriptionSetWithDependencies(s RuleSetOptions, b []byte, deps SubscriptionSetDependencies) (int, error) {
	if len(b) > 16<<20 {
		return 0, errTooLarge
	}
	env := parseEnv{geoip: deps.GeoIP, asn: deps.ASN, geosite: deps.Geosite}
	src := &source{kind: "rule_set", name: s.Name, path: s.Path, stamp: "rule_set|" + s.Format + "|" + s.Behavior + "|" + env.String()}
	key := cacheKey(src, b)
	if s.Path != "" {
		if d, ok := cacheGet(s.Path, key).(*setData); ok && d != nil && d.skipped == 0 {
			return d.entries, nil
		}
	}
	var lines []string
	var positions []int
	positionsLoaded := false
	behavior := s.Behavior
	dialect := dialMihom
	switch s.Format {
	case FormatYAML:
		var err error
		lines, err = yamlPayload(b)
		if err != nil {
			return 0, err
		}
		if behavior == "domain" || behavior == "ipcidr" || behavior == "classical" {
			if d, perr := parseLines(behavior, dialMihom, lines, maxSetEntries, env); perr == nil && d != nil && d.skipped == 0 && (deps.GeoIP || !setUsesCountryGeoIP(d)) {
				if s.Path != "" {
					cachePut(s.Path, key, d)
				}
				return d.entries, nil
			}
		}
	case FormatDomain, FormatIPCIDR, FormatClassical, FormatSurgeDomainSet, FormatSurgeRuleSet:
		text, err := textOf(b)
		if err != nil {
			return 0, err
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
		lines = strings.Split(text, "\n")
		if d, perr := parseLines(behavior, dialect, lines, maxSetEntries, env); perr == nil && d != nil && d.skipped == 0 && (deps.GeoIP || !setUsesCountryGeoIP(d)) {
			if s.Path != "" {
				cachePut(s.Path, key, d)
			}
			return d.entries, nil
		}
		positions = make([]int, len(lines))
		for j := range lines {
			positions[j] = j + 1
		}
		positionsLoaded = true
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
		if !positionsLoaded {
			positionsLoaded = true
			if s.Format == FormatYAML {
				positions = yamlLinePositions(b)
			}
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
	var d *setData
	var err error
	if s.Format == FormatYAML {
		d, err = parseLines(s.Behavior, dialMihom, lines, maxSetEntries, env)
	} else {
		d, err = parseRuleSetAs(s.Format, s.Behavior, b, maxSetEntries, env)
	}
	if err != nil {
		return 0, err
	}
	if d.skipped != 0 {
		return 0, &SubscriptionSetValidationError{Issues: []SubscriptionSetIssue{{Resource: s.Name, Code: "invalid_format"}}}
	}
	if s.Path != "" {
		cachePut(s.Path, key, d)
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
	return ValidateSubscriptionASNAt("", b)
}

func ValidateSubscriptionASNAt(path string, b []byte) error {
	if len(b) > 64<<20 {
		return errTooLarge
	}
	src := &source{kind: "asn", path: path, stamp: "asn"}
	key := cacheKey(src, b)
	if path != "" {
		if db, ok := cacheGet(path, key).(*asnDB); ok && db != nil {
			return nil
		}
	}
	db, err := parseASNDB(b)
	if err != nil {
		return err
	}
	valid := false
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "223.5.5.5", "114.114.114.114"} {
		if db.lookup(netip.MustParseAddr(s)) != 0 {
			valid = true
			break
		}
	}
	if !valid {
		networks := db.r.Networks()
		for networks.Next() {
			var rec asnRecord
			_, err := networks.Network(&rec)
			if err != nil {
				db.r.Close()
				return err
			}
			if rec.ASN != 0 {
				valid = true
				break
			}
		}
		if !valid {
			if err := networks.Err(); err != nil {
				db.r.Close()
				return err
			}
			db.r.Close()
			return errors.New("MMDB has no compatible autonomous_system_number fields")
		}
	}
	if path != "" {
		cachePut(path, key, db)
	} else {
		db.r.Close()
	}
	return nil
}

// ValidateSubscriptionGeoIP verifies the same MMDB reader and country fields
// used by Decide. It never supplies a fabricated country for missing data.
func ValidateSubscriptionGeoIP(b []byte) error {
	return ValidateSubscriptionGeoIPAt("", b)
}

func ValidateSubscriptionGeoIPAt(path string, b []byte) error {
	if len(b) > 64<<20 {
		return errTooLarge
	}
	src := &source{kind: "geoip", path: path, stamp: "geoip"}
	key := cacheKey(src, b)
	if path != "" {
		if db, ok := cacheGet(path, key).(*geoDB); ok && db != nil {
			return nil
		}
	}
	db, e := parseGeoIP(b)
	if e != nil {
		return e
	}
	found := false
	for _, s := range []string{"223.5.5.5", "114.114.114.114", "1.1.1.1", "8.8.8.8"} {
		c := db.country(netip.MustParseAddr(s))
		if len(c) == 2 {
			found = true
		}
	}
	if !found {
		db.r.Close()
		return errors.New("MMDB has no compatible country fields")
	}
	if path != "" {
		cachePut(path, key, db)
	} else {
		db.r.Close()
	}
	return nil
}
