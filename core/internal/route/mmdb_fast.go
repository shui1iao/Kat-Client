package route

import (
	"encoding/binary"
	"math"

	"github.com/oschwald/maxminddb-golang"
)

// walkMMDBFast traverses the MaxMind DB binary search tree directly using
// integer bit arithmetic (no net.IP/net.IPMask allocations) and deduplicates
// data section lookups by offset. It skips IPv4 aliases in IPv6 trees with the
// exact same semantics as maxminddb.SkipAliasedNetworks.
func walkMMDBFast(b []byte, r *maxminddb.Reader, table *mmdbTable, decodeVal func(offset uint32) (uint32, error)) error {
	nodeCount := uint32(r.Metadata.NodeCount)
	recordSize := r.Metadata.RecordSize
	if nodeCount == 0 || (recordSize != 24 && recordSize != 28 && recordSize != 32) {
		return errParse
	}
	nodeSize := uint32(recordSize) / 4 // 6, 7, or 8 bytes per node
	treeSize := uint64(nodeCount) * uint64(nodeSize)
	if treeSize+16 > uint64(len(b)) {
		return errParse
	}
	tree := b[:treeSize]

	readNode := func(idx uint32) (left, right uint32) {
		off := uint64(idx) * uint64(nodeSize)
		switch recordSize {
		case 24:
			left = uint32(tree[off])<<16 | uint32(tree[off+1])<<8 | uint32(tree[off+2])
			right = uint32(tree[off+3])<<16 | uint32(tree[off+4])<<8 | uint32(tree[off+5])
		case 28:
			mid := tree[off+3]
			left = uint32(mid>>4)<<24 | uint32(tree[off])<<16 | uint32(tree[off+1])<<8 | uint32(tree[off+2])
			right = uint32(mid&0x0f)<<24 | uint32(tree[off+4])<<16 | uint32(tree[off+5])<<8 | uint32(tree[off+6])
		case 32:
			left = binary.BigEndian.Uint32(tree[off : off+4])
			right = binary.BigEndian.Uint32(tree[off+4 : off+8])
		}
		return left, right
	}

	if r.Metadata.IPVersion == 4 {
		type frame4 struct {
			ptr uint32
			ip  uint32
			bit uint8
		}
		var stack [40]frame4
		sp := 1
		stack[0] = frame4{ptr: 0, ip: 0, bit: 0}
		for sp > 0 {
			sp--
			f := stack[sp]
			for f.ptr != nodeCount {
				if f.ptr > nodeCount {
					if f.ptr < nodeCount+16 {
						return errParse
					}
					val, err := decodeVal(f.ptr - nodeCount - 16)
					if err != nil {
						return err
					}
					if val != 0 {
						table.appendV4(f.ip, f.bit, val)
					}
					break
				}
				if f.bit >= 32 {
					return errParse
				}
				left, right := readNode(f.ptr)
				nextBit := f.bit + 1
				rightIP := f.ip | (uint32(1) << (31 - f.bit))
				stack[sp] = frame4{ptr: right, ip: rightIP, bit: nextBit}
				sp++
				f.ptr = left
				f.bit = nextBit
			}
		}
		table.finalize()
		return nil
	}

	// IPv6 tree: locate ipv4Start by walking 96 zero bits (::/96).
	var ipv4Start uint32
	{
		ptr := uint32(0)
		for i := 0; i < 96 && ptr < nodeCount; i++ {
			ptr, _ = readNode(ptr)
		}
		ipv4Start = ptr
	}

	type frame6 struct {
		ptr uint32
		hi  uint64
		lo  uint64
		bit uint8
	}
	var stack [136]frame6
	sp := 1
	stack[0] = frame6{ptr: 0, hi: 0, lo: 0, bit: 0}
	for sp > 0 {
		sp--
		f := stack[sp]
		for f.ptr != nodeCount {
			inV4 := f.hi == 0 && (f.lo>>32) == 0
			if ipv4Start != 0 && f.ptr == ipv4Start && !inV4 {
				break
			}
			if f.ptr > nodeCount {
				if f.ptr < nodeCount+16 {
					return errParse
				}
				val, err := decodeVal(f.ptr - nodeCount - 16)
				if err != nil {
					return err
				}
				if val != 0 {
					if inV4 && f.bit >= 96 {
						table.appendV4(uint32(f.lo), f.bit-96, val)
					} else {
						table.appendV6(f.hi, f.lo, f.bit, val)
					}
				}
				break
			}
			if f.bit >= 128 {
				return errParse
			}
			left, right := readNode(f.ptr)
			nextBit := f.bit + 1
			rHi, rLo := f.hi, f.lo
			if f.bit < 64 {
				rHi |= uint64(1) << (63 - f.bit)
			} else {
				rLo |= uint64(1) << (127 - f.bit)
			}
			stack[sp] = frame6{ptr: right, hi: rHi, lo: rLo, bit: nextBit}
			sp++
			f.ptr = left
			f.bit = nextBit
		}
	}
	table.finalize()
	return nil
}

// appendV4 appends an IPv4 prefix in DFS order, coalescing immediately with
// the previous range when contiguous and carrying the same value.
func (t *mmdbTable) appendV4(ip uint32, ones uint8, val uint32) {
	var hostMask uint32
	if ones == 0 {
		hostMask = 0xffffffff
	} else if ones < 32 {
		hostMask = uint32(0xffffffff) >> ones
	}
	lo := ip &^ hostMask
	hi := lo | hostMask
	if n := len(t.v4); n > 0 {
		prev := &t.v4[n-1]
		if prev.val == val && lo >= prev.lo && (lo <= prev.hi || (prev.hi < math.MaxUint32 && prev.hi+1 == lo)) {
			if hi > prev.hi {
				prev.hi = hi
			}
			return
		}
	}
	t.v4 = append(t.v4, v4Range{lo: lo, hi: hi, val: val})
}

func (t *mmdbTable) appendV6(ipHi, ipLo uint64, ones uint8, val uint32) {
	var maskHi, maskLo uint64
	switch {
	case ones == 0:
		maskHi, maskLo = math.MaxUint64, math.MaxUint64
	case ones < 64:
		maskHi = math.MaxUint64 >> ones
		maskLo = math.MaxUint64
	case ones == 64:
		maskLo = math.MaxUint64
	case ones < 128:
		maskLo = math.MaxUint64 >> (ones - 64)
	}
	loHi := ipHi &^ maskHi
	loLo := ipLo &^ maskLo
	hiHi := loHi | maskHi
	hiLo := loLo | maskLo
	if n := len(t.v6); n > 0 {
		prev := &t.v6[n-1]
		if prev.val == val && cmp128(loHi, loLo, prev.loHi, prev.loLo) >= 0 &&
			(cmp128(loHi, loLo, prev.hiHi, prev.hiLo) <= 0 || contiguous128(prev.hiHi, prev.hiLo, loHi, loLo)) {
			if cmp128(hiHi, hiLo, prev.hiHi, prev.hiLo) > 0 {
				prev.hiHi, prev.hiLo = hiHi, hiLo
			}
			return
		}
	}
	t.v6 = append(t.v6, v6Range{loHi: loHi, loLo: loLo, hiHi: hiHi, hiLo: hiLo, val: val})
}

// fastDecodeASN decodes autonomous_system_number directly from an MMDB data
// section map without reflection. Returns (asn, true) on success or (0, false)
// to fall back to maxminddb.Reader.Decode.
func fastDecodeASN(data []byte, offset uint32) (uint32, bool) {
	pos := int(offset)
	if pos < 0 || pos >= len(data) {
		return 0, false
	}
	typ, size, next, ok := mmdbReadCtrl(data, pos)
	if !ok {
		return 0, false
	}
	if typ == 1 { // pointer
		ptr, _, ok := mmdbReadPointer(data, pos, size)
		if !ok || ptr >= len(data) {
			return 0, false
		}
		typ, size, next, ok = mmdbReadCtrl(data, ptr)
		if !ok {
			return 0, false
		}
	}
	if typ != 7 { // map
		return 0, false
	}
	pos = next
	for i := 0; i < size; i++ {
		key, afterKey, ok := mmdbReadString(data, pos)
		if !ok {
			return 0, false
		}
		pos = afterKey
		if string(key) == "autonomous_system_number" {
			v, _, ok := mmdbReadUint32(data, pos)
			return v, ok
		}
		afterVal, ok := mmdbSkipValue(data, pos, 0)
		if !ok {
			return 0, false
		}
		pos = afterVal
	}
	return 0, true
}

func mmdbReadCtrl(data []byte, pos int) (typ uint8, size int, next int, ok bool) {
	if pos >= len(data) {
		return 0, 0, 0, false
	}
	ctrl := data[pos]
	pos++
	typ = ctrl >> 5
	if typ == 0 {
		if pos >= len(data) {
			return 0, 0, 0, false
		}
		typ = data[pos] + 7
		pos++
	}
	size = int(ctrl & 0x1f)
	if typ == 1 { // pointer encodes size in low 5 bits differently
		return typ, size, pos, true
	}
	if size >= 29 {
		switch size {
		case 29:
			if pos >= len(data) {
				return 0, 0, 0, false
			}
			size = 29 + int(data[pos])
			pos++
		case 30:
			if pos+2 > len(data) {
				return 0, 0, 0, false
			}
			size = 285 + int(binary.BigEndian.Uint16(data[pos:pos+2]))
			pos += 2
		case 31:
			if pos+3 > len(data) {
				return 0, 0, 0, false
			}
			size = 65821 + (int(data[pos])<<16 | int(data[pos+1])<<8 | int(data[pos+2]))
			pos += 3
		}
	}
	return typ, size, pos, true
}

func mmdbReadPointer(data []byte, ctrlPos int, ctrlLow int) (ptr int, next int, ok bool) {
	pSize := (ctrlLow >> 3) & 0x3
	pVal := ctrlLow & 0x7
	pos := ctrlPos + 1
	switch pSize {
	case 0:
		if pos >= len(data) {
			return 0, 0, false
		}
		return (pVal << 8) | int(data[pos]), pos + 1, true
	case 1:
		if pos+2 > len(data) {
			return 0, 0, false
		}
		return ((pVal << 16) | int(data[pos])<<8 | int(data[pos+1])) + 2048, pos + 2, true
	case 2:
		if pos+3 > len(data) {
			return 0, 0, false
		}
		return ((pVal << 24) | int(data[pos])<<16 | int(data[pos+1])<<8 | int(data[pos+2])) + 526336, pos + 3, true
	case 3:
		if pos+4 > len(data) {
			return 0, 0, false
		}
		return int(binary.BigEndian.Uint32(data[pos : pos+4])), pos + 4, true
	}
	return 0, 0, false
}

func mmdbReadString(data []byte, pos int) ([]byte, int, bool) {
	typ, size, next, ok := mmdbReadCtrl(data, pos)
	if !ok {
		return nil, 0, false
	}
	if typ == 1 {
		ptr, afterPtr, ok := mmdbReadPointer(data, pos, size)
		if !ok {
			return nil, 0, false
		}
		s, _, ok := mmdbReadString(data, ptr)
		return s, afterPtr, ok
	}
	if typ != 2 || next+size > len(data) {
		return nil, 0, false
	}
	return data[next : next+size], next + size, true
}

func mmdbReadUint32(data []byte, pos int) (uint32, int, bool) {
	typ, size, next, ok := mmdbReadCtrl(data, pos)
	if !ok {
		return 0, 0, false
	}
	if typ == 1 {
		ptr, afterPtr, ok := mmdbReadPointer(data, pos, size)
		if !ok {
			return 0, 0, false
		}
		v, _, ok := mmdbReadUint32(data, ptr)
		return v, afterPtr, ok
	}
	if (typ != 5 && typ != 6 && typ != 9) || size > 8 || next+size > len(data) {
		return 0, 0, false
	}
	var v uint64
	for i := 0; i < size; i++ {
		v = (v << 8) | uint64(data[next+i])
	}
	if v > math.MaxUint32 {
		return 0, 0, false
	}
	return uint32(v), next + size, true
}

func mmdbSkipValue(data []byte, pos int, depth int) (int, bool) {
	if depth > 16 {
		return 0, false
	}
	typ, size, next, ok := mmdbReadCtrl(data, pos)
	if !ok {
		return 0, false
	}
	switch typ {
	case 1: // pointer
		_, afterPtr, ok := mmdbReadPointer(data, pos, size)
		return afterPtr, ok
	case 2, 3, 4, 5, 6, 8, 9, 10, 15: // fixed/sized scalars & strings & bytes
		if next+size > len(data) {
			return 0, false
		}
		return next + size, true
	case 14: // bool (0 bytes payload)
		return next, true
	case 7: // map
		cur := next
		for i := 0; i < size; i++ {
			var ok bool
			if cur, ok = mmdbSkipValue(data, cur, depth+1); !ok {
				return 0, false
			}
			if cur, ok = mmdbSkipValue(data, cur, depth+1); !ok {
				return 0, false
			}
		}
		return cur, true
	case 11: // array
		cur := next
		for i := 0; i < size; i++ {
			var ok bool
			if cur, ok = mmdbSkipValue(data, cur, depth+1); !ok {
				return 0, false
			}
		}
		return cur, true
	default:
		return 0, false
	}
}
