//go:build windows

package clientegress

import (
	"context"
	"encoding/binary"
	"errors"
	"golang.org/x/sys/windows"
	"net"
	"net/netip"
	"syscall"
	"unsafe"
)

const Supported = true

func platformBind(o Options) func(string, syscall.RawConn) error {
	return func(network string, c syscall.RawConn) error {
		var setErr error
		e := c.Control(func(fd uintptr) {
			if network[len(network)-1] == '4' {
				if o.IPv4 == nil {
					setErr = errors.New("IPv4 interface unavailable")
					return
				}
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], *o.IPv4)
				index := binary.NativeEndian.Uint32(b[:])
				setErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31 /* IP_UNICAST_IF, ws2ipdef.h */, int(index))
			} else {
				if o.IPv6 == nil {
					setErr = errors.New("IPv6 interface unavailable")
					return
				}
				setErr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, 31 /* IPV6_UNICAST_IF, ws2ipdef.h */, int(*o.IPv6))
			}
		})
		if e != nil {
			return e
		}
		return setErr
	}
}
func platformValidate(o Options) error {
	size := uint32(16 << 10)
	var buffer []byte
	var first *windows.IpAdapterAddresses
	complete := false
	for attempts := 0; attempts < 3; attempts++ {
		if size > 1<<20 {
			return errors.New("interface list exceeds limit")
		}
		buffer = make([]byte, size)
		first = (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		e := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, first, &size)
		if e == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if e != nil {
			return errors.New("cannot inspect physical interfaces")
		}
		complete = true
		break
	}
	if !complete {
		return errors.New("interface list changed during validation")
	}
	found4, found6 := o.IPv4 == nil, o.IPv6 == nil
	foundDNS := map[DNSEndpoint]bool{}
	count := 0
	for a := first; a != nil; a = a.Next {
		count++
		if count > 1024 {
			return errors.New("adapter list exceeds limit")
		}
		if a.OperStatus != windows.IfOperStatusUp || a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		if o.IPv4 != nil && a.IfIndex == *o.IPv4 && o.LUID4 != nil && a.Luid == *o.LUID4 {
			found4 = true
		}
		if o.IPv6 != nil && a.Ipv6IfIndex == *o.IPv6 && o.LUID6 != nil && a.Luid == *o.LUID6 {
			found6 = true
		}
		if (o.LUID4 != nil && a.Luid == *o.LUID4) || (o.LUID6 != nil && a.Luid == *o.LUID6) {
			n := 0
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				n++
				if n > 64 {
					return errors.New("DNS list exceeds limit")
				}
				if d.Address.Sockaddr == nil {
					continue
				}
				var ip netip.Addr
				var scope, index uint32
				switch d.Address.Sockaddr.Addr.Family {
				case windows.AF_INET:
					if d.Address.SockaddrLength < int32(unsafe.Sizeof(windows.RawSockaddrInet4{})) {
						return errors.New("invalid DNS sockaddr")
					}
					raw := (*windows.RawSockaddrInet4)(unsafe.Pointer(d.Address.Sockaddr))
					ip = netip.AddrFrom4(raw.Addr)
					index = a.IfIndex
				case windows.AF_INET6:
					if d.Address.SockaddrLength < int32(unsafe.Sizeof(windows.RawSockaddrInet6{})) {
						return errors.New("invalid DNS sockaddr")
					}
					raw := (*windows.RawSockaddrInet6)(unsafe.Pointer(d.Address.Sockaddr))
					ip = netip.AddrFrom16(raw.Addr)
					scope = raw.Scope_id
					index = a.Ipv6IfIndex
					if ip.IsLinkLocalUnicast() && scope == 0 {
						scope = index
					}
				default:
					continue
				}
				ep := DNSEndpoint{Address: ip.String(), Owner: a.Luid, IfIndex: index, Scope: scope}
				foundDNS[ep] = true
			}
		}
	}
	_ = foundDNS
	for _, d := range o.DNS {
		ip, err := netip.ParseAddr(d.Address)
		ownerOK := (o.LUID4 != nil && d.Owner == *o.LUID4) || (o.LUID6 != nil && d.Owner == *o.LUID6)
		if err != nil || !ip.IsValid() || !ownerOK {
			return errors.New("registered DNS owner/scope is unavailable")
		}
	}
	if !found4 || !found6 {
		return errors.New("physical interface unavailable")
	}
	// Validate socket options without remote packets. Family absent is accepted
	// only when no index was provided; any later remote use fails closed.
	for _, n := range []string{"udp4", "udp6"} {
		if n == "udp4" && o.IPv4 == nil || n == "udp6" && o.IPv6 == nil {
			continue
		}
		addr := "0.0.0.0:0"
		if n == "udp6" {
			addr = "[::]:0"
		}
		lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error { return platformBind(o)(n, c) }}
		c, e := lc.ListenPacket(context.Background(), n, addr)
		if e != nil {
			return errors.New("physical socket option unavailable")
		}
		c.Close()
	}
	return nil
}

// Recheck the immutable owner at socket creation, so interface-index reuse or
// family removal cannot grant the DNS-only capability to another adapter.
func platformDNSOwner(d DNSEndpoint) error {
	row := windows.MibIfRow2{InterfaceLuid: d.Owner}
	if windows.GetIfEntry2Ex(0, &row) != nil || row.InterfaceLuid != d.Owner || row.OperStatus != windows.IfOperStatusUp {
		return errors.New("system DNS physical owner unavailable")
	}
	ip, _ := netip.ParseAddr(d.Address)
	family := uint16(windows.AF_INET)
	if ip.Is6() {
		family = windows.AF_INET6
	}
	iface := windows.MibIpInterfaceRow{Family: family, InterfaceLuid: d.Owner}
	if windows.GetIpInterfaceEntry(&iface) != nil || iface.InterfaceLuid != d.Owner || iface.InterfaceIndex != d.IfIndex || iface.Connected == 0 {
		return errors.New("system DNS owner family changed")
	}
	return nil
}

// BestRoute2 is restricted to the proven physical LUID/index. This is Microsoft
// netioapi ABI, not wireguard-windows winipcfg. No OS setting is modified.
func platformSelectSource(o OwnerState, dest, configured netip.Addr) (netip.Addr, error) {
	source, e := chooseSnapshotSource(o, dest, configured)
	if e != nil {
		return source, e
	}
	if dest.IsValid() && !dest.IsLoopback() {
		var d windows.RawSockaddrInet
		var input *windows.RawSockaddrInet
		if dest.Is4() {
			v := (*windows.RawSockaddrInet4)(unsafe.Pointer(&d))
			v.Family = windows.AF_INET
			v.Addr = dest.As4()
		} else {
			v := (*windows.RawSockaddrInet6)(unsafe.Pointer(&d))
			v.Family = windows.AF_INET6
			v.Addr = dest.As16()
			if dest.IsLinkLocalUnicast() {
				v.Scope_id = o.IfIndex
			}
		}
		var best windows.RawSockaddrInet
		var row windows.MibIpForwardRow2
		luid := o.LUID
		r, _, _ := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetBestRoute2").Call(uintptr(unsafe.Pointer(&luid)), uintptr(o.IfIndex), uintptr(unsafe.Pointer(input)), uintptr(unsafe.Pointer(&d)), 0, uintptr(unsafe.Pointer(&row)), uintptr(unsafe.Pointer(&best)))
		if r != 0 || row.InterfaceLuid != o.LUID {
			return netip.Addr{}, errors.New("physical source route unavailable")
		}
		var chosen netip.Addr
		switch best.Family {
		case windows.AF_INET:
			chosen = netip.AddrFrom4((*windows.RawSockaddrInet4)(unsafe.Pointer(&best)).Addr)
		case windows.AF_INET6:
			chosen = netip.AddrFrom16((*windows.RawSockaddrInet6)(unsafe.Pointer(&best)).Addr)
		default:
			return netip.Addr{}, errors.New("physical source family")
		}
		source, e = chooseSnapshotSource(o, dest, chosen)
		if e != nil {
			return source, e
		}
	}
	if e = platformConfirmSource(o, source.WithZone("")); e != nil {
		return netip.Addr{}, e
	}
	return source, nil
}
func platformConfirmSource(o OwnerState, source netip.Addr) error {
	if e := platformDNSOwner(DNSEndpoint{Address: source.String(), Owner: o.LUID, IfIndex: o.IfIndex}); e != nil {
		return e
	}
	var row windows.MibUnicastIpAddressRow
	row.InterfaceLuid = o.LUID
	if source.Is4() {
		v := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
		v.Family = windows.AF_INET
		v.Addr = source.As4()
	} else {
		row.Address.Family = windows.AF_INET6
		row.Address.Addr = source.As16()
		if source.IsLinkLocalUnicast() {
			row.Address.Scope_id = o.IfIndex
		}
	}
	if e := windows.GetUnicastIpAddressEntry(&row); e != nil || row.SkipAsSource != 0 || (row.DadState != 4 && row.DadState != 3) || row.ValidLifetime == 0 {
		return errors.New("actual physical source unavailable")
	}
	return nil
}
