package route

import (
	"hash/crc32"
	"strconv"
	"sync"
	"time"
	"weak"
)

// Parsed data is shared between engines (configuration generations) while the
// file and the parse parameters are unchanged, so a reload neither re-parses
// a large rule set nor keeps one copy per retained generation. Entries are
// weak for long-term reuse, with a brief strong pin so preflight validation in
// Open() is guaranteed to hand off parsed sets/MMDBs to Start() without GC loss.
type cacheEntry struct {
	key    string
	pin    any
	pinSeq uint64
	set    weak.Pointer[setData]
	geo    weak.Pointer[geoDB]
	asn    weak.Pointer[asnDB]
	site   weak.Pointer[siteDB]
}

const startupCachePinTTL = 15 * time.Second

var parsedCache struct {
	sync.Mutex
	seq uint64
	m   map[string]cacheEntry
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// cacheKey identifies the content (length and CRC-32C) and parse parameters.
func cacheKey(s *source, b []byte) string {
	return s.kind + "|" + s.stamp + "|" + strconv.Itoa(len(b)) + "|" + strconv.FormatUint(uint64(crc32.Checksum(b, castagnoli)), 16)
}

func cacheGet(path, key string) any {
	parsedCache.Lock()
	defer parsedCache.Unlock()
	c, ok := parsedCache.m[path]
	if !ok || c.key != key {
		return nil
	}
	if c.pin != nil {
		return c.pin
	}
	switch {
	case c.set.Value() != nil:
		return c.set.Value()
	case c.geo.Value() != nil:
		return c.geo.Value()
	case c.asn.Value() != nil:
		return c.asn.Value()
	case c.site.Value() != nil:
		return c.site.Value()
	}
	delete(parsedCache.m, path)
	return nil
}

func cachePut(path, key string, v any) {
	if path == "" {
		return
	}
	c := cacheEntry{key: key, pin: v}
	switch x := v.(type) {
	case *setData:
		c.set = weak.Make(x)
	case *geoDB:
		c.geo = weak.Make(x)
	case *asnDB:
		c.asn = weak.Make(x)
	case *siteDB:
		c.site = weak.Make(x)
	default:
		return
	}
	parsedCache.Lock()
	if parsedCache.m == nil {
		parsedCache.m = map[string]cacheEntry{}
	}
	parsedCache.seq++
	seq := parsedCache.seq
	c.pinSeq = seq
	parsedCache.m[path] = c
	parsedCache.Unlock()

	time.AfterFunc(startupCachePinTTL, func() {
		parsedCache.Lock()
		if cur, ok := parsedCache.m[path]; ok && cur.pinSeq == seq {
			cur.pin = nil
			parsedCache.m[path] = cur
		}
		parsedCache.Unlock()
	})
}
