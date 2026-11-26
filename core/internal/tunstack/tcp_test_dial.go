package tunstack

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// DialTestTCP exercises the real admission/epoch gate and System Stack NAT
// acceptLoop using an OS loopback TCP connection without requiring a real TUN NIC.
// Intended for package tests across tunstack and kernel.
func (r *Runtime) DialTestTCP(ctx context.Context, origSrc, origDst netip.AddrPort) (*net.TCPConn, error) {
	if r == nil || r.tcpSys == nil {
		return nil, errors.New("tunstack: tcp stack unavailable")
	}
	v6 := origDst.Addr().Is6()
	if v6 && r.tcpSys.ln6 == nil {
		return nil, errors.New("tunstack: ipv6 listener unavailable")
	}

	// 1. Build a real IPv4/IPv6 TCP SYN packet and run it through dispatchPacket
	//    so admission, epoch, paused/Quiesce and maxHandlers gates execute identically.
	syn := buildTestSYNPacket(origSrc, origDst)
	out := r.dispatchPacket(syn)
	if len(out) == 0 {
		return nil, syscall.ECONNREFUSED
	}
	// If admission rejected the SYN, dispatchPacket returned a TCP RST.
	parsed, _, ok := parseIPPacket(out)
	if !ok || parsed.proto != ipProtoTCP || len(parsed.payload) < 20 || (parsed.payload[13]&0x04) != 0 {
		return nil, syscall.ECONNREFUSED
	}

	// 2. Locate the freshly registered NAT entry and rebind its transport pair to
	//    OS loopback so the real acceptLoop receives a real *net.TCPConn.
	tuple := tcpTuple{src: origSrc, dst: origDst}
	var loopIP netip.Addr
	var network string
	var listenPort uint16
	if v6 {
		loopIP = netip.MustParseAddr("::1")
		network = "tcp6"
		listenPort = r.tcpSys.port6
	} else {
		loopIP = netip.MustParseAddr("127.0.0.1")
		network = "tcp4"
		listenPort = r.tcpSys.port4
	}

	s := r.tcpSys
	var lastErr error
	for attempt := 0; attempt < 16; attempt++ {
		s.mu.Lock()
		entry := s.byTuple[tuple]
		if entry == nil {
			s.mu.Unlock()
			return nil, syscall.ECONNREFUSED
		}
		// Pick a port (on retry allocate a fresh one).
		port := entry.natPort
		if attempt > 0 {
			if v6 {
				if s.byPort6[port] == entry {
					s.byPort6[port] = nil
				}
			} else {
				if s.byPort4[port] == entry {
					s.byPort4[port] = nil
				}
			}
			var okPort bool
			port, okPort = s.allocPortLocked(v6, time.Now().UnixNano())
			if !okPort {
				s.mu.Unlock()
				return nil, syscall.EADDRNOTAVAIL
			}
			entry.natPort = port
			if v6 {
				s.byPort6[port] = entry
			} else {
				s.byPort4[port] = entry
			}
		}
		entry.tunIP = loopIP
		entry.peerIP = loopIP
		s.mu.Unlock()

		d := net.Dialer{
			LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(loopIP, port)),
		}
		conn, err := d.DialContext(ctx, network, netip.AddrPortFrom(loopIP, listenPort).String())
		if err == nil {
			return conn.(*net.TCPConn), nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func buildTestSYNPacket(src, dst netip.AddrPort) []byte {
	if src.Addr().Is4() {
		p := make([]byte, 40)
		p[0] = 0x45
		binary.BigEndian.PutUint16(p[2:4], 40)
		p[6] = 0x40
		p[8] = 64
		p[9] = ipProtoTCP
		a, b := src.Addr().As4(), dst.Addr().As4()
		copy(p[12:16], a[:])
		copy(p[16:20], b[:])
		binary.BigEndian.PutUint16(p[10:12], folded(sum16(p[:20])))
		t := p[20:]
		binary.BigEndian.PutUint16(t[0:2], src.Port())
		binary.BigEndian.PutUint16(t[2:4], dst.Port())
		binary.BigEndian.PutUint32(t[4:8], 1000)
		t[12] = 0x50
		t[13] = 0x02 // SYN
		binary.BigEndian.PutUint16(t[14:16], 65535)
		pseudo := addr4Sum(a) + addr4Sum(b) + ipProtoTCP + 20
		binary.BigEndian.PutUint16(t[16:18], folded(pseudo+sum16(t)))
		return p
	}
	p := make([]byte, 60)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], 20)
	p[6] = ipProtoTCP
	p[7] = 64
	a, b := src.Addr().As16(), dst.Addr().As16()
	copy(p[8:24], a[:])
	copy(p[24:40], b[:])
	t := p[40:]
	binary.BigEndian.PutUint16(t[0:2], src.Port())
	binary.BigEndian.PutUint16(t[2:4], dst.Port())
	binary.BigEndian.PutUint32(t[4:8], 1000)
	t[12] = 0x50
	t[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(t[14:16], 65535)
	pseudo := addr6Sum(a) + addr6Sum(b) + 20 + ipProtoTCP
	binary.BigEndian.PutUint16(t[16:18], folded(pseudo+sum16(t)))
	return p
}

// Keep imports referenced if refactored later.
var _ = sync.Mutex{}
var _ = atomic.Bool{}
