//go:build linux

package procattr

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	udpTupleCacheTTL = 150 * time.Millisecond
	maxProcScanPIDs  = 4096
	maxProcScanFDs   = 4096
)

type udpTupleEntry struct {
	id      Identity
	expires int64
}

var udpTupleCache struct {
	sync.RWMutex
	m map[netip.AddrPort]udpTupleEntry
}

func cachedUDPTuple(q Query) (Identity, bool) {
	if q.Network != "udp" || !q.Source.IsValid() || q.Source.Port() == 0 || q.Source.Addr().IsUnspecified() {
		return Identity{}, false
	}
	now := time.Now().UnixNano()
	udpTupleCache.RLock()
	e, ok := udpTupleCache.m[q.Source]
	udpTupleCache.RUnlock()
	if ok && now < e.expires {
		return e.id, true
	}
	return Identity{}, false
}

func storeUDPTuple(q Query, id Identity) {
	if q.Network != "udp" || !q.Source.IsValid() || q.Source.Port() == 0 || q.Source.Addr().IsUnspecified() {
		return
	}
	udpTupleCache.Lock()
	defer udpTupleCache.Unlock()
	if id.Status != "known" {
		if udpTupleCache.m != nil {
			delete(udpTupleCache.m, q.Source)
		}
		return
	}
	now := time.Now().UnixNano()
	if udpTupleCache.m == nil {
		udpTupleCache.m = make(map[netip.AddrPort]udpTupleEntry, 64)
	} else if len(udpTupleCache.m) >= 1024 {
		for k, v := range udpTupleCache.m {
			if now >= v.expires {
				delete(udpTupleCache.m, k)
			}
		}
		if len(udpTupleCache.m) >= 1024 {
			clear(udpTupleCache.m)
		}
	}
	udpTupleCache.m[q.Source] = udpTupleEntry{id: id, expires: now + int64(udpTupleCacheTTL)}
}

func Lookup(ctx context.Context, q Query) Identity {
	control := Query{Network: "tcp", Source: q.ControlSource, Destination: q.ControlDestination}
	if !control.Source.IsValid() {
		control.Source, control.Destination = q.Source, q.Destination
	}
	ctl := lookupLocal(ctx, control)
	if ctl.Status == "known" && ctl.PID == uint32(os.Getpid()) {
		if id, ok := httpIdentity(ctx, q); ok && q.Network == "tcp" {
			return id
		}
		return unavailableIdentity("unknown")
	}
	if q.Network == "tcp" && control.Source == q.Source && control.Destination == q.Destination {
		return ctl
	}
	return lookupLocal(ctx, Query{Network: q.Network, Source: q.Source, Destination: q.Destination})
}

func lookupLocal(ctx context.Context, q Query) Identity {
	if ctx.Err() != nil {
		return unavailableIdentity("unknown")
	}
	if !q.Source.IsValid() || q.Source.Port() == 0 || q.Source.Addr().IsUnspecified() || q.Source.Addr().Zone() != "" {
		return unavailableIdentity("unsupported")
	}
	if q.Network != "tcp" && q.Network != "udp" {
		return unavailableIdentity("unsupported")
	}
	if q.Network == "tcp" && (!q.Destination.IsValid() || q.Destination.Port() == 0) {
		return unavailableIdentity("unsupported")
	}

	inode, status := findSocketInode(ctx, q)
	if status != "known" {
		return unavailableIdentity(status)
	}

	pid, pidStatus := findPIDByInode(ctx, inode)
	if pidStatus != "known" {
		return unavailableIdentity(pidStatus)
	}

	id, ok := readProcessIdentity(pid)
	if !ok {
		return unavailableIdentity("changed")
	}

	inode2, status2 := findSocketInode(ctx, q)
	if status2 != "known" || inode2 != inode {
		return unavailableIdentity("changed")
	}
	if stamp2, ok := readProcStartTime(pid); !ok || stamp2 != id.Stamp {
		return unavailableIdentity("changed")
	}
	return id
}

func findSocketInode(ctx context.Context, q Query) (uint64, string) {
	src := netip.AddrPortFrom(q.Source.Addr().Unmap(), q.Source.Port())
	dst := q.Destination
	if dst.IsValid() {
		dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	}
	isV4 := src.Addr().Is4()

	var files []string
	if q.Network == "tcp" {
		if isV4 {
			files = []string{"/proc/net/tcp", "/proc/net/tcp6"}
		} else {
			files = []string{"/proc/net/tcp6"}
		}
	} else {
		if isV4 {
			files = []string{"/proc/net/udp", "/proc/net/udp6"}
		} else {
			files = []string{"/proc/net/udp6"}
		}
	}

	var matchedInode uint64
	matches := 0
	wildcard := false

	for _, path := range files {
		if ctx.Err() != nil {
			return 0, "unknown"
		}
		is6File := strings.HasSuffix(path, "6")
		f, err := os.Open(path)
		if err != nil {
			if os.IsPermission(err) {
				return 0, "denied"
			}
			continue
		}
		sc := bufio.NewScanner(f)
		if sc.Scan() {
			for sc.Scan() {
				if ctx.Err() != nil {
					_ = f.Close()
					return 0, "unknown"
				}
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) < 10 {
					continue
				}
				localAP, ok := parseProcNetAddr(fields[1], is6File)
				if !ok || localAP.Port() != src.Port() {
					continue
				}
				localAddr := localAP.Addr().Unmap()
				if q.Network == "tcp" {
					if localAddr != src.Addr() {
						continue
					}
					remoteAP, ok := parseProcNetAddr(fields[2], is6File)
					if !ok || remoteAP.Port() != dst.Port() || remoteAP.Addr().Unmap() != dst.Addr() {
						continue
					}
				} else {
					if localAddr.Is4() != src.Addr().Is4() && !localAddr.IsUnspecified() {
						continue
					}
					if localAddr != src.Addr() && !localAddr.IsUnspecified() {
						continue
					}
				}
				inode, err := strconv.ParseUint(fields[9], 10, 64)
				if err != nil || inode == 0 {
					continue
				}
				if matches == 0 || matchedInode != inode {
					matches++
					matchedInode = inode
					wildcard = localAddr.IsUnspecified()
				}
			}
		}
		_ = f.Close()
	}

	if matches > 1 {
		return 0, "ambiguous"
	}
	if matches == 0 || matchedInode == 0 {
		return 0, "closed"
	}
	if q.Network == "udp" && wildcard {
		return 0, "unknown"
	}
	return matchedInode, "known"
}

func parseProcNetAddr(s string, ipv6 bool) (netip.AddrPort, bool) {
	ipHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.AddrPort{}, false
	}
	p64, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}
	raw, err := hex.DecodeString(ipHex)
	if err != nil {
		return netip.AddrPort{}, false
	}
	if !ipv6 {
		if len(raw) != 4 {
			return netip.AddrPort{}, false
		}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], binary.BigEndian.Uint32(raw))
		return netip.AddrPortFrom(netip.AddrFrom4(b), uint16(p64)), true
	}
	if len(raw) != 16 {
		return netip.AddrPort{}, false
	}
	var b [16]byte
	for i := 0; i < 16; i += 4 {
		binary.LittleEndian.PutUint32(b[i:i+4], binary.BigEndian.Uint32(raw[i:i+4]))
	}
	return netip.AddrPortFrom(netip.AddrFrom16(b), uint16(p64)), true
}

func findPIDByInode(ctx context.Context, inode uint64) (uint32, string) {
	target := "socket:[" + strconv.FormatUint(inode, 10) + "]"

	selfPID := uint32(os.Getpid())
	if found, _ := pidHasSocket("/proc/self/fd", target); found {
		return selfPID, "known"
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		if os.IsPermission(err) {
			return 0, "denied"
		}
		return 0, "unknown"
	}

	var matchedPID uint32
	matches := 0
	sawDenied := false
	scanned := 0

	for _, e := range entries {
		if ctx.Err() != nil {
			return 0, "unknown"
		}
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if len(name) == 0 || name[0] < '0' || name[0] > '9' {
			continue
		}
		pid64, err := strconv.ParseUint(name, 10, 32)
		if err != nil || pid64 == 0 {
			continue
		}
		pid := uint32(pid64)
		if pid == selfPID {
			continue
		}
		scanned++
		if scanned > maxProcScanPIDs {
			break
		}
		found, denied := pidHasSocket("/proc/"+name+"/fd", target)
		if denied {
			sawDenied = true
			continue
		}
		if found {
			matches++
			matchedPID = pid
			if matches > 1 {
				return 0, "ambiguous"
			}
		}
	}

	if matches == 1 {
		return matchedPID, "known"
	}
	if sawDenied {
		return 0, "denied"
	}
	return 0, "closed"
}

func pidHasSocket(fdDir, target string) (found bool, denied bool) {
	f, err := os.Open(fdDir)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return false, true
		}
		return false, false
	}
	names, err := f.Readdirnames(maxProcScanFDs)
	_ = f.Close()
	if err != nil && len(names) == 0 {
		if errors.Is(err, os.ErrPermission) {
			return false, true
		}
		return false, false
	}
	for _, fd := range names {
		link, err := os.Readlink(fdDir + "/" + fd)
		if err == nil && link == target {
			return true, false
		}
	}
	return false, false
}

func readProcessIdentity(pid uint32) (Identity, bool) {
	pidStr := strconv.FormatUint(uint64(pid), 10)
	stamp, ok := readProcStartTime(pid)
	if !ok || stamp == 0 {
		return Identity{}, false
	}
	var path, name string
	if exe, err := os.Readlink("/proc/" + pidStr + "/exe"); err == nil && exe != "" {
		exe = strings.TrimSuffix(exe, " (deleted)")
		if filepath.IsAbs(exe) {
			path = exe
			name = filepath.Base(exe)
		}
	}
	if name == "" || name == "." || strings.ContainsAny(name, `/\`) {
		if b, err := os.ReadFile("/proc/" + pidStr + "/comm"); err == nil {
			name = strings.TrimSpace(string(b))
		}
	}
	if name == "" || name == "." || strings.ContainsAny(name, `/\`) {
		return Identity{}, false
	}
	return Identity{
		Name:   name,
		Path:   path,
		Status: "known",
		PID:    pid,
		Stamp:  stamp,
	}, true
}

func readProcStartTime(pid uint32) (uint64, bool) {
	b, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/stat")
	if err != nil {
		return 0, false
	}
	idx := bytes.LastIndexByte(b, ')')
	if idx < 0 || idx+2 >= len(b) {
		return 0, false
	}
	fields := strings.Fields(string(b[idx+2:]))
	if len(fields) <= 19 {
		return 0, false
	}
	v, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || v == 0 {
		return 0, false
	}
	return v, true
}
