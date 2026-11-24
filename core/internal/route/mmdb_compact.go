package route

import (
	"encoding/binary"
	"math"
	"net"
	"net/netip"
	"sort"
)

// v4Range and v6Range are pointer-free sorted, non-overlapping inclusive IP
// ranges mapped to a compact uint32 value (e.g., country code index or ASN).
// Go GC marks their backing slices noscan, eliminating both raw MMDB byte
// retention (multi-language metadata / ISP org names) and GC pointer scanning.
type v4Range struct {
	lo, hi uint32
	val    uint32
}

type v6Range struct {
	loHi, loLo uint64
	hiHi, hiLo uint64
	val        uint32
}

type mmdbTable struct {
	v4 []v4Range
	v6 []v6Range
}

func (t *mmdbTable) addNet(nw *net.IPNet, val uint32) {
	if nw == nil || nw.Mask == nil || val == 0 {
		return
	}
	ones, bits := nw.Mask.Size()
	if bits == 32 {
		ip4 := nw.IP.To4()
		if ip4 == nil || ones < 0 || ones > 32 {
			return
		}
		lo := binary.BigEndian.Uint32(ip4)
		var hostMask uint32
		if ones == 0 {
			hostMask = 0xffffffff
		} else if ones < 32 {
			hostMask = uint32(0xffffffff) >> uint(ones)
		}
		lo &^= hostMask
		hi := lo | hostMask
		t.v4 = append(t.v4, v4Range{lo: lo, hi: hi, val: val})
		return
	}
	if bits == 128 {
		ip16 := nw.IP.To16()
		if ip16 == nil || ones < 0 || ones > 128 {
			return
		}
		loHi := binary.BigEndian.Uint64(ip16[:8])
		loLo := binary.BigEndian.Uint64(ip16[8:])
		var maskHi, maskLo uint64
		switch {
		case ones == 0:
			maskHi, maskLo = math.MaxUint64, math.MaxUint64
		case ones < 64:
			maskHi = math.MaxUint64 >> uint(ones)
			maskLo = math.MaxUint64
		case ones == 64:
			maskLo = math.MaxUint64
		case ones < 128:
			maskLo = math.MaxUint64 >> uint(ones-64)
		}
		loHi &^= maskHi
		loLo &^= maskLo
		hiHi := loHi | maskHi
		hiLo := loLo | maskLo
		t.v6 = append(t.v6, v6Range{loHi: loHi, loLo: loLo, hiHi: hiHi, hiLo: hiLo, val: val})
	}
}

func cmp128(aHi, aLo, bHi, bLo uint64) int {
	if aHi < bHi {
		return -1
	}
	if aHi > bHi {
		return 1
	}
	if aLo < bLo {
		return -1
	}
	if aLo > bLo {
		return 1
	}
	return 0
}

func contiguous128(prevHi, prevLo, nextHi, nextLo uint64) bool {
	if prevHi == math.MaxUint64 && prevLo == math.MaxUint64 {
		return false
	}
	if prevLo == math.MaxUint64 {
		return prevHi+1 == nextHi && nextLo == 0
	}
	return prevHi == nextHi && prevLo+1 == nextLo
}

// finalize sorts (if needed), coalesces adjacent ranges with identical values,
// and trims spare slice capacity so no oversized append backing array lingers.
func (t *mmdbTable) finalize() {
	if len(t.v4) > 0 {
		sorted := true
		for i := 1; i < len(t.v4); i++ {
			if t.v4[i].lo < t.v4[i-1].lo {
				sorted = false
				break
			}
		}
		if !sorted {
			sort.Slice(t.v4, func(i, j int) bool { return t.v4[i].lo < t.v4[j].lo })
		}
		out := t.v4[:0]
		for _, r := range t.v4 {
			if n := len(out); n > 0 {
				prev := &out[n-1]
				if prev.val == r.val && (r.lo <= prev.hi || (prev.hi < math.MaxUint32 && prev.hi+1 == r.lo)) {
					if r.hi > prev.hi {
						prev.hi = r.hi
					}
					continue
				}
			}
			out = append(out, r)
		}
		exact := make([]v4Range, len(out))
		copy(exact, out)
		t.v4 = exact
	}
	if len(t.v6) > 0 {
		sorted := true
		for i := 1; i < len(t.v6); i++ {
			if cmp128(t.v6[i].loHi, t.v6[i].loLo, t.v6[i-1].loHi, t.v6[i-1].loLo) < 0 {
				sorted = false
				break
			}
		}
		if !sorted {
			sort.Slice(t.v6, func(i, j int) bool {
				return cmp128(t.v6[i].loHi, t.v6[i].loLo, t.v6[j].loHi, t.v6[j].loLo) < 0
			})
		}
		out := t.v6[:0]
		for _, r := range t.v6 {
			if n := len(out); n > 0 {
				prev := &out[n-1]
				if prev.val == r.val && (cmp128(r.loHi, r.loLo, prev.hiHi, prev.hiLo) <= 0 || contiguous128(prev.hiHi, prev.hiLo, r.loHi, r.loLo)) {
					if cmp128(r.hiHi, r.hiLo, prev.hiHi, prev.hiLo) > 0 {
						prev.hiHi, prev.hiLo = r.hiHi, r.hiLo
					}
					continue
				}
			}
			out = append(out, r)
		}
		exact := make([]v6Range, len(out))
		copy(exact, out)
		t.v6 = exact
	}
}

func (t *mmdbTable) lookup(ip netip.Addr) uint32 {
	if !ip.IsValid() {
		return 0
	}
	ip = ip.Unmap()
	if ip.Is4() {
		b := ip.As4()
		v := binary.BigEndian.Uint32(b[:])
		lo, hi := 0, len(t.v4)
		for lo < hi {
			mid := int(uint(lo+hi) >> 1)
			r := t.v4[mid]
			if v < r.lo {
				hi = mid
			} else if v > r.hi {
				lo = mid + 1
			} else {
				return r.val
			}
		}
		return 0
	}
	b := ip.As16()
	kHi := binary.BigEndian.Uint64(b[:8])
	kLo := binary.BigEndian.Uint64(b[8:])
	lo, hi := 0, len(t.v6)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		r := t.v6[mid]
		if cmp128(kHi, kLo, r.loHi, r.loLo) < 0 {
			hi = mid
		} else if cmp128(kHi, kLo, r.hiHi, r.hiLo) > 0 {
			lo = mid + 1
		} else {
			return r.val
		}
	}
	return 0
}
