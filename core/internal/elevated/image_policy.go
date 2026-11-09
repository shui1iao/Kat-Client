package elevated

func trusted(s string) bool {
	return s == "S-1-5-18" || s == "S-1-5-32-544" || s == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}

// Shared Runtime ancestors follow the installed Rust binding_ancestor_safe
// contract: allow creation of unrelated children, never replacement of a pinned
// existing child. Runtime root, image leaf, App paths and registry stay strict.
func imageGrantSafe(sid string, mask uint32, volume, leaf, runtimeAncestor bool) bool {
	if trusted(sid) {
		return true
	}
	forbidden := uint32(0x10000000 | 0x40000000 | 0x40000 | 0x80000 | 0x40)
	if runtimeAncestor {
		forbidden |= 0x10000
	}
	if leaf {
		forbidden |= 4 | 0x10
	}
	if !volume && !runtimeAncestor {
		forbidden |= 0x10000 | 2 | 0x100
	}
	return mask&forbidden == 0
}
