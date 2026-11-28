package route

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"unsafe"

	"github.com/shui1iao/Kat/internal/userio"
)

const (
	kidxMagic      = "KIDX0003"
	kidxHeaderSize = 128

	kidxKindGeoIP   uint32 = 1
	kidxKindASN     uint32 = 2
	kidxKindGeosite uint32 = 3
	kidxKindRuleSet uint32 = 4

	kidxFastSampleMaxFull = 128 << 10
	kidxFastSampleChunk   = 4 << 10
)

func kidxLittleEndian() bool {
	var x uint16 = 0x0102
	return *(*byte)(unsafe.Pointer(&x)) == 0x02
}

func kidxStructTag() uint32 {
	if !kidxLittleEndian() {
		return 0
	}
	return uint32(unsafe.Sizeof(v4Range{})) |
		(uint32(unsafe.Sizeof(v6Range{})) << 8) |
		(uint32(unsafe.Sizeof(r4{})) << 16) |
		(uint32(unsafe.Sizeof(r6{})) << 24)
}

func kidxCacheDir() string {
	if env := os.Getenv("KAT_ROUTE_INDEX_CACHE_DIR"); env != "" {
		if env == "off" || env == "none" {
			return ""
		}
		return env
	}
	if d, err := os.UserCacheDir(); err == nil && d != "" {
		return filepath.Join(d, "kat-route-idx-v1")
	}
	return filepath.Join(os.TempDir(), "kat-route-idx-v1")
}

func kidxPathFor(s *source) (string, [32]byte, uint32) {
	var kindTag uint32
	switch s.kind {
	case "geoip":
		kindTag = kidxKindGeoIP
	case "asn":
		kindTag = kidxKindASN
	case "geosite":
		kindTag = kidxKindGeosite
	case "rule_set":
		kindTag = kidxKindRuleSet
	default:
		return "", [32]byte{}, 0
	}
	dir := kidxCacheDir()
	if dir == "" || s.path == "" {
		return "", [32]byte{}, 0
	}
	abs, err := filepath.Abs(s.path)
	if err != nil {
		abs = s.path
	}
	stampHash := sha256.Sum256([]byte(s.kind + "|" + s.stamp))
	nameHash := sha256.Sum256([]byte(abs + "|" + s.kind + "|" + s.stamp))
	return filepath.Join(dir, hex.EncodeToString(nameHash[:12])+".kidx"), stampHash, kindTag
}

func kidxVersionedPath(baseIdxPath string, fastHash [32]byte) string {
	ext := filepath.Ext(baseIdxPath)
	stem := strings.TrimSuffix(baseIdxPath, ext)
	return stem + "-" + hex.EncodeToString(fastHash[:6]) + ext
}

func sweepStaleKidx(baseIdxPath, keepPath string) {
	dir := filepath.Dir(baseIdxPath)
	baseName := filepath.Base(baseIdxPath)
	stem := strings.TrimSuffix(baseName, filepath.Ext(baseName))
	keepName := filepath.Base(keepPath)
	entries, err := userio.ReadDir(dir)
	if err != nil {
		return
	}
	prefix := stem + "-"
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		n := ent.Name()
		if n == keepName {
			continue
		}
		if n == baseName || (strings.HasPrefix(n, prefix) && strings.HasSuffix(n, ".kidx")) {
			_ = userio.Remove(filepath.Join(dir, n))
		}
	}
}

// promoteToMmap persists val as a zero-heap KIDX0003 read-only index and
// immediately remaps it so the caller can drop Go-heap tables on the next GC.
// On any error (unsupported shape or I/O failure) it returns val unchanged.
func promoteToMmap(s *source, fi os.FileInfo, b []byte, val any) (any, string) {
	if fi != nil && fi.Mode().IsRegular() && s.path != "" {
		fh := computeSourceFastHashFromBytes(b)
		if saveMmapIndex(s, fi, fh, val) {
			if mv, _, ok := tryLoadMmapIndex(s, fi); ok {
				return mv, s.kind + "|" + s.stamp + "|kidx|" + hex.EncodeToString(fh[:8])
			}
		}
	}
	return val, cacheKey(s, b)
}

// computeSourceFastHash computes a fast content fingerprint: full SHA-256 for
// files <= 128 KiB, or head+mid+tail 4 KiB chunks + length for larger DB files.
func computeSourceFastHashFromFile(path string, size int64) ([32]byte, error) {
	var zero [32]byte
	f, err := userio.Open(path)
	if err != nil {
		return zero, err
	}
	defer f.Close()
	h := sha256.New()
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(size))
	h.Write(lenBuf[:])
	if size <= kidxFastSampleMaxFull {
		if _, err := io.CopyN(h, f, size); err != nil {
			return zero, err
		}
		var out [32]byte
		copy(out[:], h.Sum(nil))
		return out, nil
	}
	var chunk [kidxFastSampleChunk]byte
	offsets := [3]int64{0, (size - kidxFastSampleChunk) / 2, size - kidxFastSampleChunk}
	for _, off := range offsets {
		if _, err := f.ReadAt(chunk[:], off); err != nil {
			return zero, err
		}
		h.Write(chunk[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

func computeSourceFastHashFromBytes(b []byte) [32]byte {
	h := sha256.New()
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(b)))
	h.Write(lenBuf[:])
	if len(b) <= kidxFastSampleMaxFull {
		h.Write(b)
	} else {
		sz := len(b)
		h.Write(b[:kidxFastSampleChunk])
		mid := (sz - kidxFastSampleChunk) / 2
		h.Write(b[mid : mid+kidxFastSampleChunk])
		h.Write(b[sz-kidxFastSampleChunk:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// --- Binary writer helpers ---

type kidxMetaWriter struct {
	buf []byte
}

func (w *kidxMetaWriter) u32(v uint32) { w.buf = binary.LittleEndian.AppendUint32(w.buf, v) }
func (w *kidxMetaWriter) u64(v uint64) { w.buf = binary.LittleEndian.AppendUint64(w.buf, v) }
func (w *kidxMetaWriter) str(s string) {
	w.u32(uint32(len(s)))
	w.buf = append(w.buf, s...)
}
func (w *kidxMetaWriter) strs(ss []string) {
	w.u32(uint32(len(ss)))
	for _, s := range ss {
		w.str(s)
	}
}

type kidxMetaReader struct {
	b   []byte
	off int
}

func (r *kidxMetaReader) u32() (uint32, bool) {
	if r.off+4 > len(r.b) {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(r.b[r.off : r.off+4])
	r.off += 4
	return v, true
}
func (r *kidxMetaReader) u64() (uint64, bool) {
	if r.off+8 > len(r.b) {
		return 0, false
	}
	v := binary.LittleEndian.Uint64(r.b[r.off : r.off+8])
	r.off += 8
	return v, true
}
func (r *kidxMetaReader) str() (string, bool) {
	n, ok := r.u32()
	if !ok || r.off+int(n) > len(r.b) {
		return "", false
	}
	s := string(r.b[r.off : r.off+int(n)])
	r.off += int(n)
	return s, true
}
func (r *kidxMetaReader) strs() ([]string, bool) {
	n, ok := r.u32()
	if !ok || n > 1<<20 {
		return nil, false
	}
	if n == 0 {
		return nil, true
	}
	out := make([]string, n)
	for i := range out {
		s, ok := r.str()
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

type kidxFlatBuilder struct {
	buf []byte
}

func (fb *kidxFlatBuilder) align8() {
	if rem := len(fb.buf) & 7; rem != 0 {
		var z [8]byte
		fb.buf = append(fb.buf, z[:8-rem]...)
	}
}

func (fb *kidxFlatBuilder) appendBytes(b []byte) (off, n uint64) {
	fb.align8()
	off = uint64(len(fb.buf))
	fb.buf = append(fb.buf, b...)
	return off, uint64(len(b))
}

func appendTypedSlice[T any](fb *kidxFlatBuilder, s []T) (off, count uint64) {
	fb.align8()
	off = uint64(len(fb.buf))
	count = uint64(len(s))
	if count == 0 {
		return off, 0
	}
	byteLen := int(count) * int(unsafe.Sizeof(s[0]))
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&s[0])), byteLen)
	fb.buf = append(fb.buf, raw...)
	return off, count
}

func mapTypedSlice[T any](flat []byte, off, count uint64) ([]T, bool) {
	if count == 0 {
		return nil, true
	}
	var zero T
	elemSize := uint64(unsafe.Sizeof(zero))
	if off&7 != 0 || count > (1<<30) || off > uint64(len(flat)) || count*elemSize > uint64(len(flat))-off {
		return nil, false
	}
	ptr := (*T)(unsafe.Pointer(&flat[off]))
	return unsafe.Slice(ptr, int(count)), true
}

func mapByteSlice(flat []byte, off, length uint64) ([]byte, bool) {
	if length == 0 {
		return nil, true
	}
	if off > uint64(len(flat)) || length > uint64(len(flat))-off {
		return nil, false
	}
	return flat[off : off+length], true
}

func writePackedMeta(mw *kidxMetaWriter, fb *kidxFlatBuilder, ps *packedSet) {
	dOff, dLen := fb.appendBytes(ps.data)
	oOff, oCnt := appendTypedSlice(fb, ps.offs)
	mw.u64(dOff)
	mw.u64(dLen)
	mw.u64(oOff)
	mw.u64(oCnt)
}

func readPackedMeta(mr *kidxMetaReader, flat []byte) (packedSet, bool) {
	dOff, ok1 := mr.u64()
	dLen, ok2 := mr.u64()
	oOff, ok3 := mr.u64()
	oCnt, ok4 := mr.u64()
	if !(ok1 && ok2 && ok3 && ok4) {
		return packedSet{}, false
	}
	data, ok := mapByteSlice(flat, dOff, dLen)
	if !ok {
		return packedSet{}, false
	}
	offs, ok := mapTypedSlice[uint32](flat, oOff, oCnt)
	if !ok {
		return packedSet{}, false
	}
	return packedSet{data: data, offs: offs}, true
}

func writeDomainSetMeta(mw *kidxMetaWriter, fb *kidxFlatBuilder, d *domainSet) bool {
	// Ensure maps have been compacted into packedSets.
	if len(d.exact)+len(d.suffix)+len(d.sub)+len(d.wild1) > 0 {
		return false
	}
	writePackedMeta(mw, fb, &d.pExact)
	writePackedMeta(mw, fb, &d.pSuffix)
	writePackedMeta(mw, fb, &d.pSub)
	writePackedMeta(mw, fb, &d.pWild1)
	mw.strs(d.keywords)
	mw.strs(d.globs)
	mw.u32(uint32(len(d.labelPats)))
	for _, lp := range d.labelPats {
		mw.strs(lp)
	}
	mw.u32(uint32(len(d.regex)))
	for _, re := range d.regex {
		mw.str(re.String())
	}
	return true
}

func readDomainSetMeta(mr *kidxMetaReader, flat []byte) (domainSet, bool) {
	var d domainSet
	var ok bool
	if d.pExact, ok = readPackedMeta(mr, flat); !ok {
		return d, false
	}
	if d.pSuffix, ok = readPackedMeta(mr, flat); !ok {
		return d, false
	}
	if d.pSub, ok = readPackedMeta(mr, flat); !ok {
		return d, false
	}
	if d.pWild1, ok = readPackedMeta(mr, flat); !ok {
		return d, false
	}
	if d.keywords, ok = mr.strs(); !ok {
		return d, false
	}
	if d.globs, ok = mr.strs(); !ok {
		return d, false
	}
	nLP, ok := mr.u32()
	if !ok || nLP > 1<<20 {
		return d, false
	}
	if nLP > 0 {
		d.labelPats = make([][]string, nLP)
		for i := range d.labelPats {
			lp, ok := mr.strs()
			if !ok {
				return d, false
			}
			d.labelPats[i] = lp
		}
	}
	nRe, ok := mr.u32()
	if !ok || nRe > 1<<16 {
		return d, false
	}
	if nRe > 0 {
		d.regex = make([]*regexp.Regexp, 0, nRe)
		for i := uint32(0); i < nRe; i++ {
			pat, ok := mr.str()
			if !ok {
				return d, false
			}
			re, err := compileDomainRegex(pat)
			if err != nil {
				return d, false
			}
			d.regex = append(d.regex, re)
		}
	}
	return d, true
}

func writeIPSetMeta(mw *kidxMetaWriter, fb *kidxFlatBuilder, ip *ipSet) {
	v4Off, v4Cnt := appendTypedSlice(fb, ip.v4)
	v6Off, v6Cnt := appendTypedSlice(fb, ip.v6)
	mw.u64(v4Off)
	mw.u64(v4Cnt)
	mw.u64(v6Off)
	mw.u64(v6Cnt)
}

func readIPSetMeta(mr *kidxMetaReader, flat []byte) (ipSet, bool) {
	v4Off, ok1 := mr.u64()
	v4Cnt, ok2 := mr.u64()
	v6Off, ok3 := mr.u64()
	v6Cnt, ok4 := mr.u64()
	if !(ok1 && ok2 && ok3 && ok4) {
		return ipSet{}, false
	}
	v4, ok := mapTypedSlice[r4](flat, v4Off, v4Cnt)
	if !ok {
		return ipSet{}, false
	}
	v6, ok := mapTypedSlice[r6](flat, v6Off, v6Cnt)
	if !ok {
		return ipSet{}, false
	}
	return ipSet{v4: v4, v6: v6}, true
}

func writeCondMeta(mw *kidxMetaWriter, fb *kidxFlatBuilder, c *cond) bool {
	if c == nil || c.set != nil {
		return false
	}
	mw.u32(uint32(c.kind))
	var f uint32
	if c.noResolve {
		f |= 1
	}
	if c.re != nil {
		f |= 2
	}
	if c.prefix.IsValid() {
		f |= 4
	}
	if c.inline != nil {
		f |= 8
	}
	if c.ipset != nil {
		f |= 16
	}
	mw.u32(f)
	mw.str(c.s)
	mw.u32(c.num)
	if c.re != nil {
		mw.str(c.re.String())
	}
	if c.prefix.IsValid() {
		mw.str(c.prefix.String())
	}
	pOff, pCnt := appendTypedSlice(fb, c.ports)
	mw.u64(pOff)
	mw.u64(pCnt)
	mw.u32(uint32(len(c.subs)))
	for _, sub := range c.subs {
		if !writeCondMeta(mw, fb, sub) {
			return false
		}
	}
	if c.inline != nil {
		if !writeSetDataBody(mw, fb, c.inline) {
			return false
		}
	}
	if c.ipset != nil {
		writeIPSetMeta(mw, fb, c.ipset)
	}
	return true
}

func readCondMeta(mr *kidxMetaReader, flat []byte, depth int) (*cond, bool) {
	if depth > 16 {
		return nil, false
	}
	k, ok1 := mr.u32()
	f, ok2 := mr.u32()
	str, ok3 := mr.str()
	num, ok4 := mr.u32()
	if !(ok1 && ok2 && ok3 && ok4) {
		return nil, false
	}
	c := &cond{
		kind:      condKind(k),
		noResolve: f&1 != 0,
		s:         str,
		num:       num,
	}
	if f&2 != 0 {
		pat, ok := mr.str()
		if !ok {
			return nil, false
		}
		re, err := compileDomainRegex(pat)
		if err != nil {
			return nil, false
		}
		c.re = re
	}
	if f&4 != 0 {
		ps, ok := mr.str()
		if !ok {
			return nil, false
		}
		pfx, err := netip.ParsePrefix(ps)
		if err != nil {
			return nil, false
		}
		c.prefix = pfx
	}
	pOff, ok1 := mr.u64()
	pCnt, ok2 := mr.u64()
	if !(ok1 && ok2) {
		return nil, false
	}
	ports, ok := mapTypedSlice[portRange](flat, pOff, pCnt)
	if !ok {
		return nil, false
	}
	c.ports = ports
	nSubs, ok := mr.u32()
	if !ok || nSubs > 1<<16 {
		return nil, false
	}
	if nSubs > 0 {
		c.subs = make([]*cond, nSubs)
		for i := range c.subs {
			sub, ok := readCondMeta(mr, flat, depth+1)
			if !ok {
				return nil, false
			}
			c.subs[i] = sub
		}
	}
	if f&8 != 0 {
		inl, ok := readSetDataBody(mr, flat, depth+1)
		if !ok {
			return nil, false
		}
		c.inline = inl
	}
	if f&16 != 0 {
		ips, ok := readIPSetMeta(mr, flat)
		if !ok {
			return nil, false
		}
		c.ipset = &ips
	}
	return c, true
}

func writeSetDataBody(mw *kidxMetaWriter, fb *kidxFlatBuilder, x *setData) bool {
	if !writeDomainSetMeta(mw, fb, &x.dom) {
		return false
	}
	writeIPSetMeta(mw, fb, &x.ip)
	writeIPSetMeta(mw, fb, &x.ipNR)
	pOff, pCnt := appendTypedSlice(fb, x.ports)
	mw.u64(pOff)
	mw.u64(pCnt)
	mw.strs(x.geo)
	mw.strs(x.geoNR)
	var fl uint32
	if x.mono {
		fl |= 1
	}
	if x.extraIP {
		fl |= 2
	}
	mw.u32(fl)
	mw.u32(uint32(x.entries))
	mw.u32(uint32(x.skipped))
	mw.u32(uint32(len(x.extra)))
	for _, c := range x.extra {
		if !writeCondMeta(mw, fb, c) {
			return false
		}
	}
	return true
}

func readSetDataBody(mr *kidxMetaReader, flat []byte, depth int) (*setData, bool) {
	if depth > 8 {
		return nil, false
	}
	dom, ok := readDomainSetMeta(mr, flat)
	if !ok {
		return nil, false
	}
	ip, ok := readIPSetMeta(mr, flat)
	if !ok {
		return nil, false
	}
	ipNR, ok := readIPSetMeta(mr, flat)
	if !ok {
		return nil, false
	}
	pOff, ok1 := mr.u64()
	pCnt, ok2 := mr.u64()
	if !(ok1 && ok2) {
		return nil, false
	}
	ports, ok := mapTypedSlice[portRange](flat, pOff, pCnt)
	if !ok {
		return nil, false
	}
	geo, ok := mr.strs()
	if !ok {
		return nil, false
	}
	geoNR, ok := mr.strs()
	if !ok {
		return nil, false
	}
	fl, ok1 := mr.u32()
	ent, ok2 := mr.u32()
	skp, ok3 := mr.u32()
	nExtra, ok4 := mr.u32()
	if !(ok1 && ok2 && ok3 && ok4) || nExtra > 1<<20 {
		return nil, false
	}
	var extra []*cond
	if nExtra > 0 {
		extra = make([]*cond, nExtra)
		for i := range extra {
			c, ok := readCondMeta(mr, flat, depth+1)
			if !ok {
				return nil, false
			}
			extra[i] = c
		}
	}
	return &setData{
		dom:     dom,
		ports:   ports,
		ip:      ip,
		ipNR:    ipNR,
		geo:     geo,
		geoNR:   geoNR,
		extra:   extra,
		extraIP: fl&2 != 0,
		mono:    fl&1 != 0,
		entries: int(int32(ent)),
		skipped: int(int32(skp)),
	}, true
}

// saveMmapIndex atomically writes a read-only zero-heap binary index file.
// Errors are non-fatal (the caller still has the valid in-memory object).
func saveMmapIndex(s *source, fi os.FileInfo, fastHash [32]byte, val any) bool {
	if fi == nil || !kidxLittleEndian() || kidxStructTag() == 0 {
		return false
	}
	baseIdxPath, stampHash, kindTag := kidxPathFor(s)
	if baseIdxPath == "" || kindTag == 0 {
		return false
	}
	idxPath := kidxVersionedPath(baseIdxPath, fastHash)

	var mw kidxMetaWriter
	var fb kidxFlatBuilder
	var entries, skipped, categories int32
	var flags uint32

	switch x := val.(type) {
	case *geoDB:
		if kindTag != kidxKindGeoIP {
			return false
		}
		v4Off, v4Cnt := appendTypedSlice(&fb, x.table.v4)
		v6Off, v6Cnt := appendTypedSlice(&fb, x.table.v6)
		mw.u64(v4Off)
		mw.u64(v4Cnt)
		mw.u64(v6Off)
		mw.u64(v6Cnt)
		mw.strs(x.codes)
	case *asnDB:
		if kindTag != kidxKindASN {
			return false
		}
		v4Off, v4Cnt := appendTypedSlice(&fb, x.table.v4)
		v6Off, v6Cnt := appendTypedSlice(&fb, x.table.v6)
		mw.u64(v4Off)
		mw.u64(v4Cnt)
		mw.u64(v6Off)
		mw.u64(v6Cnt)
	case *setData:
		if kindTag != kidxKindRuleSet {
			return false
		}
		if !writeSetDataBody(&mw, &fb, x) {
			return false
		}
		entries = int32(x.entries)
		skipped = int32(x.skipped)
		if x.mono {
			flags |= 1
		}
	case *siteDB:
		if kindTag != kidxKindGeosite {
			return false
		}
		categories = int32(x.categories)
		var keys []string
		x.compiled.Range(func(k, _ any) bool {
			if ks, ok := k.(string); ok {
				keys = append(keys, ks)
			}
			return true
		})
		sort.Strings(keys)
		mw.u32(uint32(len(keys)))
		for _, k := range keys {
			v, _ := x.compiled.Load(k)
			sm, ok := v.(*siteMatcher)
			if !ok {
				return false
			}
			mw.str(k)
			if sm.missing {
				mw.u32(1)
				continue
			}
			mw.u32(0)
			if !writeDomainSetMeta(&mw, &fb, &sm.dom) {
				return false
			}
		}
		// Also store lazy raw-category index into mmap flat section if unpruned.
		if len(x.index) > 0 {
			idxKeys := make([]string, 0, len(x.index))
			for k := range x.index {
				idxKeys = append(idxKeys, k)
			}
			sort.Strings(idxKeys)
			mw.u32(uint32(len(idxKeys)))
			for _, k := range idxKeys {
				msg := x.index[k]
				mOff, mLen := fb.appendBytes(msg)
				mw.str(k)
				mw.u64(mOff)
				mw.u64(mLen)
			}
		} else {
			mw.u32(0)
		}
	default:
		return false
	}

	// Pad metadata to 8-byte alignment so flat section starts 8-byte aligned.
	metaBytes := mw.buf
	if rem := len(metaBytes) & 7; rem != 0 {
		var z [8]byte
		metaBytes = append(metaBytes, z[:8-rem]...)
	}
	totalSize := uint64(kidxHeaderSize) + uint64(len(metaBytes)) + uint64(len(fb.buf))

	var hdr [kidxHeaderSize]byte
	copy(hdr[0:8], kidxMagic)
	binary.LittleEndian.PutUint32(hdr[8:12], kindTag)
	binary.LittleEndian.PutUint32(hdr[12:16], kidxStructTag())
	binary.LittleEndian.PutUint64(hdr[16:24], uint64(fi.Size()))
	binary.LittleEndian.PutUint64(hdr[24:32], uint64(fi.ModTime().UnixNano()))
	copy(hdr[32:64], fastHash[:])
	copy(hdr[64:96], stampHash[:])
	binary.LittleEndian.PutUint32(hdr[96:100], crc32.Checksum(metaBytes, castagnoli))
	binary.LittleEndian.PutUint32(hdr[100:104], uint32(len(metaBytes)))
	binary.LittleEndian.PutUint64(hdr[104:112], totalSize)
	binary.LittleEndian.PutUint32(hdr[112:116], uint32(entries))
	binary.LittleEndian.PutUint32(hdr[116:120], uint32(skipped))
	binary.LittleEndian.PutUint32(hdr[120:124], uint32(categories))
	binary.LittleEndian.PutUint32(hdr[124:128], flags)

	dir := filepath.Dir(idxPath)
	if err := userio.MkdirAll(dir, 0o700); err != nil {
		return false
	}
	tmp, err := userio.CreateTemp(dir, "kidx-*.tmp")
	if err != nil {
		return false
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = userio.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(hdr[:]); err != nil {
		return false
	}
	if len(metaBytes) > 0 {
		if _, err := tmp.Write(metaBytes); err != nil {
			return false
		}
	}
	if len(fb.buf) > 0 {
		if _, err := tmp.Write(fb.buf); err != nil {
			return false
		}
	}
	if err := tmp.Close(); err != nil {
		return false
	}
	if err := userio.Rename(tmpName, idxPath); err != nil {
		_ = userio.Remove(tmpName)
		return false
	}
	ok = true
	sweepStaleKidx(baseIdxPath, idxPath)
	return true
}

// tryLoadMmapIndex validates version, source stat, and fast content hash, then
// maps the zero-heap binary index directly into read-only virtual memory.
func tryLoadMmapIndex(s *source, fi os.FileInfo) (any, [32]byte, bool) {
	var zero [32]byte
	if fi == nil || !kidxLittleEndian() || kidxStructTag() == 0 {
		return nil, zero, false
	}
	baseIdxPath, stampHash, kindTag := kidxPathFor(s)
	if baseIdxPath == "" || kindTag == 0 {
		return nil, zero, false
	}
	// Compute real source file content hash (head+mid+tail 4 KiB or full <=128 KiB)
	// so we address the immutable versioned .kidx directly (safe on Windows when
	// older versions remain memory-mapped during live refresh).
	fastHash, err := computeSourceFastHashFromFile(s.path, fi.Size())
	if err != nil {
		return nil, zero, false
	}
	idxPath := kidxVersionedPath(baseIdxPath, fastHash)
	f, err := userio.Open(idxPath)
	if err != nil {
		f, err = userio.Open(baseIdxPath)
		if err != nil {
			return nil, zero, false
		}
	}
	defer f.Close()
	cfi, err := f.Stat()
	if err != nil || !cfi.Mode().IsRegular() || cfi.Size() < kidxHeaderSize {
		return nil, zero, false
	}
	reg, err := mapReadOnlyFile(f, cfi.Size())
	if err != nil {
		return nil, zero, false
	}
	raw := reg.bytes()
	fail := func() (any, [32]byte, bool) {
		cleanupMmapRegion(reg)
		return nil, zero, false
	}
	if len(raw) < kidxHeaderSize || string(raw[0:8]) != kidxMagic {
		return fail()
	}
	if binary.LittleEndian.Uint32(raw[8:12]) != kindTag || binary.LittleEndian.Uint32(raw[12:16]) != kidxStructTag() {
		return fail()
	}
	if binary.LittleEndian.Uint64(raw[16:24]) != uint64(fi.Size()) {
		return fail()
	}
	if int64(binary.LittleEndian.Uint64(raw[24:32])) != fi.ModTime().UnixNano() {
		return fail()
	}
	if !bytes.Equal(raw[32:64], fastHash[:]) {
		return fail()
	}
	if !bytes.Equal(raw[64:96], stampHash[:]) {
		return fail()
	}
	totalSize := binary.LittleEndian.Uint64(raw[104:112])
	metaLen := uint64(binary.LittleEndian.Uint32(raw[100:104]))
	if totalSize != uint64(len(raw)) || metaLen&7 != 0 || uint64(kidxHeaderSize)+metaLen > totalSize {
		return fail()
	}
	metaBytes := raw[kidxHeaderSize : kidxHeaderSize+int(metaLen)]
	if crc32.Checksum(metaBytes, castagnoli) != binary.LittleEndian.Uint32(raw[96:100]) {
		return fail()
	}

	flat := raw[kidxHeaderSize+int(metaLen):]
	mr := &kidxMetaReader{b: metaBytes}
	categories := int(int32(binary.LittleEndian.Uint32(raw[120:124])))

	switch kindTag {
	case kidxKindGeoIP:
		v4Off, ok1 := mr.u64()
		v4Cnt, ok2 := mr.u64()
		v6Off, ok3 := mr.u64()
		v6Cnt, ok4 := mr.u64()
		codes, ok5 := mr.strs()
		if !(ok1 && ok2 && ok3 && ok4 && ok5) {
			return fail()
		}
		v4, ok := mapTypedSlice[v4Range](flat, v4Off, v4Cnt)
		if !ok {
			return fail()
		}
		v6, ok := mapTypedSlice[v6Range](flat, v6Off, v6Cnt)
		if !ok {
			return fail()
		}
		db := &geoDB{table: mmdbTable{v4: v4, v6: v6}, codes: codes, mmapBacked: true}
		runtime.AddCleanup(db, cleanupMmapRegion, reg)
		return db, fastHash, true

	case kidxKindASN:
		v4Off, ok1 := mr.u64()
		v4Cnt, ok2 := mr.u64()
		v6Off, ok3 := mr.u64()
		v6Cnt, ok4 := mr.u64()
		if !(ok1 && ok2 && ok3 && ok4) {
			return fail()
		}
		v4, ok := mapTypedSlice[v4Range](flat, v4Off, v4Cnt)
		if !ok {
			return fail()
		}
		v6, ok := mapTypedSlice[v6Range](flat, v6Off, v6Cnt)
		if !ok {
			return fail()
		}
		db := &asnDB{table: mmdbTable{v4: v4, v6: v6}, mmapBacked: true}
		runtime.AddCleanup(db, cleanupMmapRegion, reg)
		return db, fastHash, true

	case kidxKindRuleSet:
		sd, ok := readSetDataBody(mr, flat, 0)
		if !ok {
			return fail()
		}
		sd.mmapBacked = true
		runtime.AddCleanup(sd, cleanupMmapRegion, reg)
		return sd, fastHash, true

	case kidxKindGeosite:
		nKeys, ok := mr.u32()
		if !ok || nKeys > 1<<16 {
			return fail()
		}
		db := &siteDB{categories: categories, mmapBacked: true}
		for i := uint32(0); i < nKeys; i++ {
			k, ok := mr.str()
			if !ok {
				return fail()
			}
			miss, ok := mr.u32()
			if !ok {
				return fail()
			}
			if miss != 0 {
				db.compiled.Store(k, &siteMatcher{missing: true})
				continue
			}
			dom, ok := readDomainSetMeta(mr, flat)
			if !ok {
				return fail()
			}
			db.compiled.Store(k, &siteMatcher{dom: dom})
		}
		nIdx, ok := mr.u32()
		if !ok || nIdx > 1<<20 {
			return fail()
		}
		if nIdx > 0 {
			db.index = make(map[string][]byte, nIdx)
			for i := uint32(0); i < nIdx; i++ {
				k, ok1 := mr.str()
				mOff, ok2 := mr.u64()
				mLen, ok3 := mr.u64()
				if !(ok1 && ok2 && ok3) {
					return fail()
				}
				msg, ok := mapByteSlice(flat, mOff, mLen)
				if !ok {
					return fail()
				}
				db.index[k] = msg
			}
		}
		runtime.AddCleanup(db, cleanupMmapRegion, reg)
		return db, fastHash, true
	}
	return fail()
}
