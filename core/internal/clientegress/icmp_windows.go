//go:build windows

package clientegress

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	icmpHlpDLL          = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = icmpHlpDLL.NewProc("IcmpCreateFile")
	procIcmp6CreateFile = icmpHlpDLL.NewProc("Icmp6CreateFile")
	procIcmpCloseHandle = icmpHlpDLL.NewProc("IcmpCloseHandle")
	procIcmpSendEcho2Ex = icmpHlpDLL.NewProc("IcmpSendEcho2Ex")
	procIcmp6SendEcho2  = icmpHlpDLL.NewProc("Icmp6SendEcho2")

	physicalICMPSlots = make(chan struct{}, 32)
)

const (
	ipFlagDF  = 0x02
	ipSuccess = 0
)

// Matches _WIN64 IP_OPTION_INFORMATION (16 bytes, OptionsData at offset 8).
type ipOptionInformation struct {
	Ttl         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	_           [4]byte
	OptionsData uintptr
}

// Matches _WIN64 ICMP_ECHO_REPLY (40 bytes: Data at 16, Options at 24).
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

type pingOutcome struct {
	payload []byte
	ttl     uint8
	err     error
}

func icmpTimeoutMS(ctx context.Context) uint32 {
	d := 3000 * time.Millisecond
	if dl, ok := ctx.Deadline(); ok {
		d = time.Until(dl)
	}
	if d < 100*time.Millisecond {
		d = 100 * time.Millisecond
	}
	if d > 4000*time.Millisecond {
		d = 4000 * time.Millisecond
	}
	return uint32(d / time.Millisecond)
}

func platformPing(ctx context.Context, owner OwnerState, src, dst netip.Addr, ttl, tos uint8, df bool, payload []byte) ([]byte, uint8, error) {
	if len(payload) > 65500 {
		return nil, 0, errors.New("ICMP payload exceeds limit")
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, err
	}
	select {
	case physicalICMPSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
	timeoutMS := icmpTimeoutMS(ctx)
	reqCopy := append([]byte(nil), payload...)
	srcPlain := src.WithZone("").Unmap()
	ch := make(chan pingOutcome, 1)
	go func() {
		defer func() { <-physicalICMPSlots }()
		if dst.Is4() {
			ch <- sendICMPv4(srcPlain, dst, ttl, tos, df, reqCopy, timeoutMS)
		} else {
			ch <- sendICMPv6(owner, srcPlain, dst, ttl, tos, reqCopy, timeoutMS)
		}
	}()
	select {
	case res := <-ch:
		return res.payload, res.ttl, res.err
	case <-ctx.Done():
		return nil, 0, ctx.Err()
	}
}

func sendICMPv4(src, dst netip.Addr, ttl, tos uint8, df bool, req []byte, timeoutMS uint32) pingOutcome {
	h, _, err := procIcmpCreateFile.Call()
	if h == 0 || windows.Handle(h) == windows.InvalidHandle {
		return pingOutcome{err: err}
	}
	defer procIcmpCloseHandle.Call(h)

	if ttl == 0 {
		ttl = 64
	}
	var flags uint8
	if df {
		flags = ipFlagDF
	}
	opt := ipOptionInformation{Ttl: ttl, Tos: tos, Flags: flags}
	s4, d4 := src.As4(), dst.As4()
	srcAddr := binary.LittleEndian.Uint32(s4[:])
	dstAddr := binary.LittleEndian.Uint32(d4[:])

	var reqPtr uintptr
	if len(req) > 0 {
		reqPtr = uintptr(unsafe.Pointer(&req[0]))
	}
	extra := len(req)
	if extra < 8 {
		extra = 8
	}
	replySize := uint32(unsafe.Sizeof(icmpEchoReply{})) + uint32(extra) + 64
	replyBuf := make([]byte, replySize)

	n, _, callErr := procIcmpSendEcho2Ex.Call(
		h,
		0,
		0,
		0,
		uintptr(srcAddr),
		uintptr(dstAddr),
		reqPtr,
		uintptr(uint16(len(req))),
		uintptr(unsafe.Pointer(&opt)),
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(replySize),
		uintptr(timeoutMS),
	)
	runtime.KeepAlive(req)
	runtime.KeepAlive(&opt)
	if n == 0 {
		runtime.KeepAlive(replyBuf)
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return pingOutcome{err: callErr}
		}
		return pingOutcome{err: errors.New("ICMP echo timeout")}
	}
	rep := (*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	if rep.Status != ipSuccess {
		runtime.KeepAlive(replyBuf)
		return pingOutcome{err: errors.New("ICMP echo failed")}
	}
	repTTL := rep.Options.Ttl
	if repTTL == 0 {
		repTTL = 64
	}
	var out []byte
	bufStart := uintptr(unsafe.Pointer(&replyBuf[0]))
	bufEnd := bufStart + uintptr(len(replyBuf))
	if rep.DataSize > 0 && rep.Data >= bufStart && rep.Data+uintptr(rep.DataSize) <= bufEnd {
		off := int(rep.Data - bufStart)
		out = append([]byte(nil), replyBuf[off:off+int(rep.DataSize)]...)
	} else {
		out = append([]byte(nil), req...)
	}
	runtime.KeepAlive(replyBuf)
	return pingOutcome{payload: out, ttl: repTTL}
}

func sendICMPv6(owner OwnerState, src, dst netip.Addr, ttl, tos uint8, req []byte, timeoutMS uint32) pingOutcome {
	h, _, err := procIcmp6CreateFile.Call()
	if h == 0 || windows.Handle(h) == windows.InvalidHandle {
		return pingOutcome{err: err}
	}
	defer procIcmpCloseHandle.Call(h)

	if ttl == 0 {
		ttl = 64
	}
	opt := ipOptionInformation{Ttl: ttl, Tos: tos}
	var scope uint32
	if src.IsLinkLocalUnicast() {
		scope = owner.IfIndex
	}
	srcSA := windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: src.As16(), Scope_id: scope}
	dstSA := windows.RawSockaddrInet6{Family: windows.AF_INET6, Addr: dst.As16()}
	if dst.IsLinkLocalUnicast() {
		dstSA.Scope_id = owner.IfIndex
	}

	var reqPtr uintptr
	if len(req) > 0 {
		reqPtr = uintptr(unsafe.Pointer(&req[0]))
	}
	extra := len(req)
	if extra < 8 {
		extra = 8
	}
	// ICMPV6_ECHO_REPLY_LH is 36 bytes on _WIN64 (Status at 28, RoundTripTime at 32, data at 36).
	const replyHdrLen = 36
	replySize := uint32(replyHdrLen + extra + 64)
	replyBuf := make([]byte, replySize)

	n, _, callErr := procIcmp6SendEcho2.Call(
		h,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&srcSA)),
		uintptr(unsafe.Pointer(&dstSA)),
		reqPtr,
		uintptr(uint16(len(req))),
		uintptr(unsafe.Pointer(&opt)),
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(replySize),
		uintptr(timeoutMS),
	)
	runtime.KeepAlive(req)
	runtime.KeepAlive(&opt)
	runtime.KeepAlive(&srcSA)
	runtime.KeepAlive(&dstSA)
	if n == 0 {
		runtime.KeepAlive(replyBuf)
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return pingOutcome{err: callErr}
		}
		return pingOutcome{err: errors.New("ICMPv6 echo timeout")}
	}
	status := binary.LittleEndian.Uint32(replyBuf[28:32])
	if status != ipSuccess {
		runtime.KeepAlive(replyBuf)
		return pingOutcome{err: errors.New("ICMPv6 echo failed")}
	}
	out := make([]byte, len(req))
	if replyHdrLen+len(req) <= len(replyBuf) {
		copy(out, replyBuf[replyHdrLen:replyHdrLen+len(req)])
	} else {
		copy(out, req)
	}
	runtime.KeepAlive(replyBuf)
	return pingOutcome{payload: out, ttl: 64}
}
