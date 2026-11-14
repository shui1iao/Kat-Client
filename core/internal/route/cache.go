package route

import (
	"hash/crc32"
	"os"
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
	key     string
	statKey string
	size    int
	mtime   time.Time
	pin     any
	pinSeq  uint64
	set     weak.Pointer[setData]
	geo     weak.Pointer[geoDB]
	asn     weak.Pointer[asnDB]
	site    weak.Pointer[siteDB]
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

func fileStatKey(s *source, fi os.FileInfo) string {
	if fi == nil {
		return ""
	}
	return s.kind + "|" + s.stamp + "|" + strconv.FormatInt(fi.Size(), 10) + "|" + strconv.FormatInt(fi.ModTime().UnixNano(), 10)
}

func (c cacheEntry) resolve() any {
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
	return nil
}

func cacheGet(path, key string) any {
	parsedCache.Lock()
	defer parsedCache.Unlock()
	c, ok := parsedCache.m[path]
	if !ok || c.key != key {
		return nil
	}
	if v := c.resolve(); v != nil {
		return v
	}
	delete(parsedCache.m, path)
	return nil
}

func cacheGetStat(path string, s *source, fi os.FileInfo) (any, string, int, bool) {
	if path == "" || fi == nil || !fi.Mode().IsRegular() {
		return nil, "", 0, false
	}
	sk := fileStatKey(s, fi)
	if sk == "" {
		return nil, "", 0, false
	}
	parsedCache.Lock()
	defer parsedCache.Unlock()
	c, ok := parsedCache.m[path]
	if !ok || c.statKey == "" || c.statKey != sk {
		return nil, "", 0, false
	}
	if v := c.resolve(); v != nil {
		return v, c.key, c.size, true
	}
	delete(parsedCache.m, path)
	return nil, "", 0, false
}

func cachePut(path, key string, v any) {
	cachePutWithStat(path, key, "", 0, time.Time{}, v)
}

func CacheRecordStat(path, kind, stamp string, fi os.FileInfo) {
	if path == "" || fi == nil {
		return
	}
	src := &source{kind: kind, path: path, stamp: stamp}
	sk := fileStatKey(src, fi)
	if sk == "" {
		return
	}
	parsedCache.Lock()
	if cur, ok := parsedCache.m[path]; ok {
		cur.statKey = sk
		cur.size = int(fi.Size())
		cur.mtime = fi.ModTime()
		parsedCache.m[path] = cur
	}
	parsedCache.Unlock()
}

func cachePutWithStat(path, key, statKey string, size int, mtime time.Time, v any) {
	if path == "" {
		return
	}
	c := cacheEntry{key: key, statKey: statKey, size: size, mtime: mtime, pin: v}
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
	if prev, ok := parsedCache.m[path]; ok && prev.key == key && c.statKey == "" && prev.statKey != "" {
		c.statKey = prev.statKey
		c.size = prev.size
		c.mtime = prev.mtime
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
