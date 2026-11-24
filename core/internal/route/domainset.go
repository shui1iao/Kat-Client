package route

import (
	"regexp"
	"slices"
	"strings"
)

// packedSet stores sorted unique lowercase domain strings in a single
// pointer-free byte arena plus uint32 offsets (len == N+1 when non-empty).
// Compared to map[string]struct{}, it reduces memory by ~4-5x and removes
// per-domain heap pointers from Go GC scanning.
type packedSet struct {
	data []byte
	offs []uint32
}

func (p *packedSet) count() int {
	if len(p.offs) <= 1 {
		return 0
	}
	return len(p.offs) - 1
}

func compareBytesString(b []byte, s string) int {
	n := len(b)
	if len(s) < n {
		n = len(s)
	}
	for i := 0; i < n; i++ {
		if b[i] != s[i] {
			if b[i] < s[i] {
				return -1
			}
			return 1
		}
	}
	if len(b) < len(s) {
		return -1
	}
	if len(b) > len(s) {
		return 1
	}
	return 0
}

func (p *packedSet) contains(s string) bool {
	n := len(p.offs) - 1
	if n <= 0 {
		return false
	}
	lo, hi := 0, n
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		cmp := compareBytesString(p.data[p.offs[mid]:p.offs[mid+1]], s)
		if cmp == 0 {
			return true
		}
		if cmp < 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return false
}

func packStrings(m *map[string]struct{}, dst *packedSet) {
	mlen := len(*m)
	if mlen == 0 {
		*m = nil
		return
	}
	existing := dst.count()
	keys := make([]string, 0, mlen+existing)
	if existing > 0 {
		for i := 0; i < existing; i++ {
			keys = append(keys, string(dst.data[dst.offs[i]:dst.offs[i+1]]))
		}
	}
	for k := range *m {
		keys = append(keys, k)
	}
	*m = nil
	slices.Sort(keys)
	keys = slices.Compact(keys)
	total := 0
	for _, k := range keys {
		total += len(k)
	}
	data := make([]byte, 0, total)
	offs := make([]uint32, len(keys)+1)
	for i, k := range keys {
		offs[i] = uint32(len(data))
		data = append(data, k...)
	}
	offs[len(keys)] = uint32(len(data))
	dst.data = data
	dst.offs = offs
}

// ---- domains: exact/suffix/sub/wild1 packed sets (label-suffix walk), then linear lists ----

type domainSet struct {
	exact, suffix map[string]struct{}
	sub           map[string]struct{} // proper subdomains only (".x" in mihomo/sing-box)
	wild1         map[string]struct{} // "*.x": exactly one label followed by x
	pExact        packedSet
	pSuffix       packedSet
	pSub          packedSet
	pWild1        packedSet
	keywords      []string
	globs         []string   // DOMAIN-WILDCARD: '*' any run, '?' one character
	labelPats     [][]string // other mihomo '*' label wildcards
	regex         []*regexp.Regexp
}

func put(m *map[string]struct{}, k string) {
	if *m == nil {
		*m = map[string]struct{}{}
	}
	(*m)[k] = struct{}{}
}

func (d *domainSet) compact() {
	packStrings(&d.exact, &d.pExact)
	packStrings(&d.suffix, &d.pSuffix)
	packStrings(&d.sub, &d.pSub)
	packStrings(&d.wild1, &d.pWild1)
	d.keywords = slices.Clip(d.keywords)
	d.globs = slices.Clip(d.globs)
	d.labelPats = slices.Clip(d.labelPats)
	d.regex = slices.Clip(d.regex)
}

func (d *domainSet) empty() bool {
	return len(d.exact)+len(d.suffix)+len(d.sub)+len(d.wild1)+
		d.pExact.count()+d.pSuffix.count()+d.pSub.count()+d.pWild1.count()+
		len(d.keywords)+len(d.globs)+len(d.labelPats)+len(d.regex) == 0
}

func (d *domainSet) hasExact(host string) bool {
	if _, ok := d.exact[host]; ok {
		return true
	}
	return d.pExact.contains(host)
}

func (d *domainSet) hasSuffix(s string) bool {
	if _, ok := d.suffix[s]; ok {
		return true
	}
	return d.pSuffix.contains(s)
}

func (d *domainSet) hasSub(s string) bool {
	if _, ok := d.sub[s]; ok {
		return true
	}
	return d.pSub.contains(s)
}

func (d *domainSet) hasWild1(s string) bool {
	if _, ok := d.wild1[s]; ok {
		return true
	}
	return d.pWild1.contains(s)
}

func (d *domainSet) match(host string) bool {
	if host == "" {
		return false
	}
	if d.hasExact(host) {
		return true
	}
	hasSuffixLike := len(d.suffix)+d.pSuffix.count()+len(d.sub)+d.pSub.count()+len(d.wild1)+d.pWild1.count() > 0
	if hasSuffixLike {
		hasWild := len(d.wild1)+d.pWild1.count() > 0
		first := true
		for s := host; ; {
			if d.hasSuffix(s) {
				return true
			}
			if !first && d.hasSub(s) {
				return true
			}
			i := strings.IndexByte(s, '.')
			if i < 0 {
				break
			}
			s = s[i+1:]
			if first && hasWild && d.hasWild1(s) {
				return true
			}
			first = false
		}
	}
	for _, k := range d.keywords {
		if strings.Contains(host, k) {
			return true
		}
	}
	for _, g := range d.globs {
		if wildcardMatch(g, host) {
			return true
		}
	}
	if len(d.labelPats) > 0 {
		labels := strings.Split(host, ".")
		for _, p := range d.labelPats {
			if labelPatMatch(p, labels) {
				return true
			}
		}
	}
	for _, re := range d.regex {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

func labelPatMatch(p, labels []string) bool {
	if len(p) != len(labels) {
		return false
	}
	for i := range p {
		if p[i] != "*" && p[i] != labels[i] {
			return false
		}
	}
	return true
}

// Domain list dialects.
const (
	dialKat   = iota // Kat 0.6 text: "+.x" and ".x" = x and subdomains, "*" label wildcard
	dialMihom        // mihomo: "+.x" = x and subdomains, ".x" = subdomains only, "*" label wildcard
	dialSurge        // Surge DOMAIN-SET: ".x" = x and subdomains, otherwise exact
)

// addDomainEntry adds one domain-list entry; false = malformed.
func (d *domainSet) addDomainEntry(s string, dialect int) bool {
	switch {
	case dialect != dialSurge && strings.HasPrefix(s, "+."):
		v, ok := normDomain(s[2:])
		if !ok {
			return false
		}
		put(&d.suffix, v)
		return true
	case strings.HasPrefix(s, "."):
		v, ok := normDomain(s[1:])
		if !ok {
			return false
		}
		if dialect == dialMihom {
			put(&d.sub, v)
		} else {
			put(&d.suffix, v)
		}
		return true
	case strings.IndexByte(s, '*') >= 0:
		if dialect == dialSurge {
			return false
		}
		return d.addLabelWildcard(s)
	}
	v, ok := normDomain(s)
	if !ok {
		return false
	}
	put(&d.exact, v)
	return true
}

// addLabelWildcard: labels are "*" (exactly one label) or ordinary labels.
func (d *domainSet) addLabelWildcard(s string) bool {
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if l == "*" {
			continue
		}
		if _, ok := normDomain(l); !ok || strings.IndexByte(l, '*') >= 0 {
			return false
		}
	}
	if len(labels) < 2 {
		return false
	}
	rest := strings.Join(labels[1:], ".")
	if labels[0] == "*" && strings.IndexByte(rest, '*') < 0 {
		put(&d.wild1, rest)
		return true
	}
	d.labelPats = append(d.labelPats, labels)
	return true
}
