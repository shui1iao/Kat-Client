package procattr

import (
	"strconv"
	"strings"
)

// Mirrors the existing installer read-only policy; no ACLs/registry are changed.
func trustedOwner(s string) bool {
	return s == "S-1-5-18" || s == "S-1-5-32-544" || s == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}
func safeGrant(owner, sid string, mask uint32, flags uint8, kind string, leaf, volume bool) bool {
	if !trustedOwner(owner) {
		return false
	}
	if kind == "registry" && !leaf && sid == "S-1-3-0" && mask == 0xf003f && flags == 2 {
		return true
	}
	if kind != "protected" && flags&8 != 0 {
		return true
	}
	// Match Rust service_self_read::binding_ancestor_safe exactly. Creating
	// unrelated children is not replacing the existing protected/pinned runtime.
	if kind == "runtime" {
		return trustedOwner(sid) || mask&0x500d0040 == 0
	}
	if kind == "protected" {
		if owner != "S-1-5-18" && owner != "S-1-5-32-544" {
			return false
		}
		if sid == "S-1-5-18" || sid == "S-1-5-32-544" {
			return true
		}
		return mask&(0x10000000|0x40000000|0x40000|0x80000|0x10000|2|4|0x40|0x10|0x100) == 0
	}
	if trustedOwner(sid) {
		return true
	}
	forbid := uint32(0x10000000 | 0x40000000 | 0x40000 | 0x80000)
	if kind == "registry" {
		forbid |= 0x10000 | 2 | 4 | 0x20
	} else {
		forbid |= 0x40
		if !volume {
			forbid |= 0x10000 | 2 | 0x100
		}
	}
	return mask&forbid == 0
}
func validRoot(p string) bool {
	if len(p) < 4 || len(p) > 240 || !((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) || p[1:3] != ":\\" || strings.ContainsAny(p, "/\x00") {
		return false
	}
	for _, part := range strings.Split(p[3:], "\\") {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return false
		}
		for _, c := range part {
			if c < ' ' || strings.ContainsRune(`<>:"/|?*`, c) {
				return false
			}
		}
		stem := strings.ToUpper(strings.Split(part, ".")[0])
		if stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL" || (len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '1' && stem[3] <= '9') {
			return false
		}
	}
	return true
}
func validUserSID(s string) bool {
	p := strings.Split(s, "-")
	if len(p) != 8 || strings.Join(p[:4], "-") != "S-1-5-21" {
		return false
	}
	for _, v := range p[4:] {
		n, e := strconv.ParseUint(v, 10, 32)
		if e != nil || strconv.FormatUint(n, 10) != v {
			return false
		}
	}
	return true
}
