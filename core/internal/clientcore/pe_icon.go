package clientcore

import (
	"bytes"
	"debug/pe"
	"encoding/base64"
	"encoding/binary"
	"image"
	"image/color"
	_ "image/gif"
	_ "image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"strings"
)

func rvaToSectionData(f *pe.File, rva, size uint32) ([]byte, bool) {
	if size == 0 || size > 4<<20 {
		return nil, false
	}
	for _, sec := range f.Sections {
		span := sec.VirtualSize
		if sec.Size > span {
			span = sec.Size
		}
		if rva >= sec.VirtualAddress && rva < sec.VirtualAddress+span {
			off := rva - sec.VirtualAddress
			if uint64(off)+uint64(size) > uint64(sec.Size) {
				return nil, false
			}
			b, err := sec.Data()
			if err != nil || uint64(off)+uint64(size) > uint64(len(b)) {
				return nil, false
			}
			return b[off : off+size], true
		}
	}
	return nil, false
}

func downscaleImage64(src image.Image) image.Image {
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	if sw <= 96 && sh <= 96 {
		return src
	}
	const dstSize = 64
	dst := image.NewNRGBA(image.Rect(0, 0, dstSize, dstSize))
	// Clean area-box averaging for crisp downscaling from 256x256 / 128x128 -> 64x64
	for dy := 0; dy < dstSize; dy++ {
		y0 := b.Min.Y + (dy*sh)/dstSize
		y1 := b.Min.Y + ((dy+1)*sh)/dstSize
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for dx := 0; dx < dstSize; dx++ {
			x0 := b.Min.X + (dx*sw)/dstSize
			x1 := b.Min.X + ((dx+1)*sw)/dstSize
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var sr, sg, sb, sa, cnt uint64
			for sy := y0; sy < y1; sy++ {
				for sx := x0; sx < x1; sx++ {
					cr, cg, cb, ca := src.At(sx, sy).RGBA()
					sr += uint64(cr)
					sg += uint64(cg)
					sb += uint64(cb)
					sa += uint64(ca)
					cnt++
				}
			}
			if cnt == 0 || sa == 0 {
				continue
			}
			// RGBA() is alpha-premultiplied in [0..65535]; unpremultiply back to NRGBA
			avgA := sa / cnt
			r8 := uint8(min(255, ((sr/cnt)*255+(avgA/2))/avgA))
			g8 := uint8(min(255, ((sg/cnt)*255+(avgA/2))/avgA))
			b8 := uint8(min(255, ((sb/cnt)*255+(avgA/2))/avgA))
			a8 := uint8((avgA + 128) / 257)
			dst.SetNRGBA(dx, dy, color.NRGBA{R: r8, G: g8, B: b8, A: a8})
		}
	}
	return dst
}

func decodeRTIconBlobToPNG(raw []byte) ([]byte, bool) {
	if len(raw) < 16 {
		return nil, false
	}
	// Case 1: Vista+ PNG-compressed icon resource
	if bytes.HasPrefix(raw, []byte("\x89PNG\r\n\x1a\n")) {
		img, err := png.Decode(bytes.NewReader(raw))
		if err != nil {
			if len(raw) <= maxIconBytes {
				return raw, true
			}
			return nil, false
		}
		if img.Bounds().Dx() <= 96 && img.Bounds().Dy() <= 96 && len(raw) <= maxIconBytes {
			return raw, true
		}
		var out bytes.Buffer
		if err := png.Encode(&out, downscaleImage64(img)); err == nil && out.Len() > 0 && out.Len() <= maxIconBytes {
			return out.Bytes(), true
		}
		return nil, false
	}

	// Case 2: Classic BITMAPINFOHEADER DIB (32 / 24 / 8 / 4 / 1 bpp)
	if len(raw) < 40 {
		return nil, false
	}
	hdrSize := int(binary.LittleEndian.Uint32(raw[0:4]))
	if hdrSize < 40 || hdrSize > 124 || hdrSize > len(raw) {
		return nil, false
	}
	w := int(int32(binary.LittleEndian.Uint32(raw[4:8])))
	h2 := int(int32(binary.LittleEndian.Uint32(raw[8:12])))
	bpp := int(binary.LittleEndian.Uint16(raw[14:16]))
	comp := binary.LittleEndian.Uint32(raw[16:20])
	clrUsed := int(binary.LittleEndian.Uint32(raw[32:36]))
	h := h2 / 2
	if w <= 0 || w > 512 || h <= 0 || h > 512 || comp != 0 {
		return nil, false
	}
	if bpp != 32 && bpp != 24 && bpp != 8 && bpp != 4 && bpp != 1 {
		return nil, false
	}

	paletteColors := 0
	if bpp <= 8 {
		if clrUsed > 0 && clrUsed <= (1<<bpp) {
			paletteColors = clrUsed
		} else {
			paletteColors = 1 << bpp
		}
	}
	palOff := hdrSize
	xorOff := palOff + paletteColors*4
	rowStride := ((w*bpp + 31) / 32) * 4
	andStride := ((w + 31) / 32) * 4
	andOff := xorOff + rowStride*h
	if xorOff+rowStride*h > len(raw) {
		return nil, false
	}

	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	hasAlpha := false
	if bpp == 32 {
		for y := 0; y < h && !hasAlpha; y++ {
			row := raw[xorOff+y*rowStride:]
			for x := 0; x < w; x++ {
				if row[x*4+3] != 0 {
					hasAlpha = true
					break
				}
			}
		}
	}

	for y := 0; y < h; y++ {
		srcY := h - 1 - y
		row := raw[xorOff+srcY*rowStride:]
		var andRow []byte
		if andOff+andStride*h <= len(raw) {
			andRow = raw[andOff+srcY*andStride:]
		}
		for x := 0; x < w; x++ {
			var b, g, r, a byte
			switch bpp {
			case 32:
				b, g, r, a = row[x*4], row[x*4+1], row[x*4+2], row[x*4+3]
			case 24:
				b, g, r, a = row[x*3], row[x*3+1], row[x*3+2], 255
			case 8:
				idx := int(row[x])
				if idx < paletteColors {
					po := palOff + idx*4
					b, g, r, a = raw[po], raw[po+1], raw[po+2], 255
				}
			case 4:
				byteVal := row[x/2]
				idx := int((byteVal >> 4) & 0x0F)
				if x%2 == 1 {
					idx = int(byteVal & 0x0F)
				}
				if idx < paletteColors {
					po := palOff + idx*4
					b, g, r, a = raw[po], raw[po+1], raw[po+2], 255
				}
			case 1:
				idx := int((row[x/8] >> uint(7-(x%8))) & 1)
				if idx < paletteColors {
					po := palOff + idx*4
					b, g, r, a = raw[po], raw[po+1], raw[po+2], 255
				}
			}
			if !hasAlpha {
				if len(andRow) > x/8 && (andRow[x/8]&(0x80>>uint(x%8))) != 0 {
					a = 0
				} else {
					a = 255
				}
			}
			img.SetNRGBA(x, y, color.NRGBA{R: r, G: g, B: b, A: a})
		}
	}

	var out bytes.Buffer
	if err := png.Encode(&out, downscaleImage64(img)); err != nil || out.Len() == 0 || out.Len() > maxIconBytes {
		return nil, false
	}
	return out.Bytes(), true
}

// extractPEIconDataURI parses RT_GROUP_ICON (14) & RT_ICON (3) directly from a Windows PE (.exe/.dll)
// in pure Go without GDI/COM dependencies.
func extractPEIconDataURI(exePath string) string {
	f, err := pe.Open(exePath)
	if err != nil {
		return ""
	}
	defer f.Close()

	rsrc := f.Section(".rsrc")
	if rsrc == nil || rsrc.Size == 0 || rsrc.Size > 64<<20 {
		return ""
	}
	data, err := rsrc.Data()
	if err != nil || len(data) < 16 {
		return ""
	}

	readU16 := func(off uint32) (uint16, bool) {
		if uint64(off)+2 > uint64(len(data)) {
			return 0, false
		}
		return binary.LittleEndian.Uint16(data[off : off+2]), true
	}
	readU32 := func(off uint32) (uint32, bool) {
		if uint64(off)+4 > uint64(len(data)) {
			return 0, false
		}
		return binary.LittleEndian.Uint32(data[off : off+4]), true
	}

	type resEntry struct {
		id     uint32
		isName bool
		isDir  bool
		offset uint32
	}
	listDir := func(dirOff uint32) []resEntry {
		if uint64(dirOff)+16 > uint64(len(data)) {
			return nil
		}
		named, ok1 := readU16(dirOff + 12)
		ids, ok2 := readU16(dirOff + 14)
		if !ok1 || !ok2 {
			return nil
		}
		total := int(named) + int(ids)
		if total > 512 {
			total = 512
		}
		out := make([]resEntry, 0, total)
		cur := dirOff + 16
		for i := 0; i < total && uint64(cur)+8 <= uint64(len(data)); i++ {
			nameOrID, _ := readU32(cur)
			offOrDir, _ := readU32(cur + 4)
			out = append(out, resEntry{
				id:     nameOrID & 0x7FFFFFFF,
				isName: (nameOrID & 0x80000000) != 0,
				isDir:  (offOrDir & 0x80000000) != 0,
				offset: offOrDir & 0x7FFFFFFF,
			})
			cur += 8
		}
		return out
	}

	resolveLeafBlob := func(e resEntry) ([]byte, bool) {
		cur := e
		for depth := 0; depth < 4 && cur.isDir; depth++ {
			kids := listDir(cur.offset)
			if len(kids) == 0 {
				return nil, false
			}
			cur = kids[0]
		}
		if cur.isDir || uint64(cur.offset)+16 > uint64(len(data)) {
			return nil, false
		}
		rva, ok1 := readU32(cur.offset)
		sz, ok2 := readU32(cur.offset + 4)
		if !ok1 || !ok2 {
			return nil, false
		}
		return rvaToSectionData(f, rva, sz)
	}

	iconsByID := make(map[uint16][]byte)
	var groupBlobs [][]byte
	for _, e := range listDir(0) {
		if e.isName || !e.isDir {
			continue
		}
		if e.id == 3 { // RT_ICON
			for _, ie := range listDir(e.offset) {
				if !ie.isName && ie.id <= 0xFFFF {
					if b, ok := resolveLeafBlob(ie); ok {
						iconsByID[uint16(ie.id)] = b
					}
				}
			}
		} else if e.id == 14 { // RT_GROUP_ICON
			for _, ge := range listDir(e.offset) {
				if b, ok := resolveLeafBlob(ge); ok {
					groupBlobs = append(groupBlobs, b)
				}
			}
		}
	}
	if len(iconsByID) == 0 {
		return ""
	}

	type candidate struct {
		id    uint16
		score int
	}
	var candidates []candidate
	for _, grp := range groupBlobs {
		if len(grp) < 6 {
			continue
		}
		typ := binary.LittleEndian.Uint16(grp[2:4])
		cnt := int(binary.LittleEndian.Uint16(grp[4:6]))
		if typ != 1 || cnt <= 0 {
			continue
		}
		off := 6
		for i := 0; i < cnt && off+14 <= len(grp); i++ {
			w := int(grp[off])
			if w == 0 {
				w = 256
			}
			bpp := int(binary.LittleEndian.Uint16(grp[off+6 : off+8]))
			if bpp == 0 {
				bpp = 32
			}
			nid := binary.LittleEndian.Uint16(grp[off+12 : off+14])
			if _, ok := iconsByID[nid]; ok {
				score := bpp * 1000
				if w >= 48 && w <= 128 {
					score += 60000 + w
				} else if w == 256 {
					score += 50000
				} else if w >= 32 {
					score += 30000 + w
				} else {
					score += w
				}
				candidates = append(candidates, candidate{id: nid, score: score})
			}
			off += 14
		}
		if len(candidates) > 0 {
			break // First group icon is the primary application icon in Windows Explorer
		}
	}

	// Sort candidates descending by score
	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			if candidates[j].score > candidates[i].score {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}
	for _, c := range candidates {
		if pngBytes, ok := decodeRTIconBlobToPNG(iconsByID[c.id]); ok {
			return "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBytes)
		}
	}
	// Fallback: try largest raw RT_ICON entry directly
	var bestRaw []byte
	for _, b := range iconsByID {
		if len(b) > len(bestRaw) {
			bestRaw = b
		}
	}
	if pngBytes, ok := decodeRTIconBlobToPNG(bestRaw); ok {
		return "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBytes)
	}
	return ""
}

// extractMSIXLogoFromPath locates AppxManifest.xml for Microsoft Store / MSIX / WindowsApps
// binaries (or packaged apps) and extracts the highest-quality transparent PNG asset.
func extractMSIXLogoFromPath(exePath string) string {
	dir := filepath.Dir(exePath)
	var manifestPath, pkgRoot string
	for depth := 0; depth < 4 && dir != "" && dir != "." && dir != filepath.Dir(dir); depth++ {
		cand := filepath.Join(dir, "AppxManifest.xml")
		if st, err := os.Stat(cand); err == nil && !st.IsDir() && st.Size() > 0 && st.Size() <= 512<<10 {
			manifestPath = cand
			pkgRoot = dir
			break
		}
		dir = filepath.Dir(dir)
	}
	if manifestPath == "" {
		return ""
	}
	rawXML, err := os.ReadFile(manifestPath)
	if err != nil || len(rawXML) == 0 {
		return ""
	}
	xmlStr := string(rawXML)
	var relLogos []string
	// Extract Square44x44Logo, Square150x150Logo, and <Logo>...</Logo>
	for _, attr := range []string{`Square44x44Logo="`, `Square150x150Logo="`, `Logo="`} {
		if idx := strings.Index(xmlStr, attr); idx >= 0 {
			rest := xmlStr[idx+len(attr):]
			if end := strings.IndexByte(rest, '"'); end > 0 && end < 260 {
				relLogos = append(relLogos, rest[:end])
			}
		}
	}
	if idx := strings.Index(xmlStr, "<Logo>"); idx >= 0 {
		rest := xmlStr[idx+6:]
		if end := strings.Index(rest, "</Logo>"); end > 0 && end < 260 {
			relLogos = append(relLogos, strings.TrimSpace(rest[:end]))
		}
	}

	seen := map[string]bool{}
	var candidates []string
	addCand := func(p string) {
		clean := filepath.Clean(p)
		if !strings.HasPrefix(strings.ToLower(clean), strings.ToLower(pkgRoot)) {
			return
		}
		if !seen[clean] {
			seen[clean] = true
			candidates = append(candidates, clean)
		}
	}
	for _, rel := range relLogos {
		relOS := filepath.FromSlash(strings.ReplaceAll(rel, `\`, "/"))
		full := filepath.Join(pkgRoot, relOS)
		ext := filepath.Ext(full)
		stem := strings.TrimSuffix(full, ext)
		for _, suffix := range []string{
			".targetsize-64_altform-unplated.png",
			".targetsize-48_altform-unplated.png",
			".targetsize-256_altform-unplated.png",
			".targetsize-64.png",
			".targetsize-48.png",
			".scale-200" + ext,
			".scale-150" + ext,
			".scale-125" + ext,
			".scale-100" + ext,
			ext,
		} {
			addCand(stem + suffix)
		}
	}

	for _, c := range candidates {
		b, err := os.ReadFile(c)
		if err != nil || len(b) == 0 || len(b) > 2<<20 {
			continue
		}
		if pngBytes, ok := decodeRTIconBlobToPNG(b); ok {
			return "data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBytes)
		}
		if img, _, err := image.Decode(bytes.NewReader(b)); err == nil {
			var out bytes.Buffer
			if err := png.Encode(&out, downscaleImage64(img)); err == nil && out.Len() > 0 && out.Len() <= maxIconBytes {
				return "data:image/png;base64," + base64.StdEncoding.EncodeToString(out.Bytes())
			}
		}
	}
	return ""
}
