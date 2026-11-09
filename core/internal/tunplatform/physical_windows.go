//go:build windows

package tunplatform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shui1iao/Kat/internal/clientegress"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"unsafe"
)

func digestText(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func adapterList() ([]*windows.IpAdapterAddresses, []byte, error) {
	size := uint32(32768)
	for tries := 0; tries < 3; tries++ {
		if size > 4<<20 {
			return nil, nil, errors.New("ADAPTER_LIMIT")
		}
		b := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0]))
		e := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_GATEWAYS, 0, first, &size)
		if e == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if e != nil {
			return nil, nil, e
		}
		var rows []*windows.IpAdapterAddresses
		for a := first; a != nil; a = a.Next {
			if len(rows) >= 1024 {
				return nil, nil, errors.New("ADAPTER_LIMIT")
			}
			rows = append(rows, a)
		}
		return rows, b, nil
	}
	return nil, nil, errors.New("ADAPTER_UNSTABLE")
}
func routes() ([]windows.MibIpForwardRow2, error) {
	var p *windows.MibIpForwardTable2
	if e := windows.GetIpForwardTable2(windows.AF_UNSPEC, &p); e != nil {
		return nil, e
	}
	if p == nil {
		return nil, errors.New("ROUTE_QUERY")
	}
	defer windows.FreeMibTable(unsafe.Pointer(p))
	if p.NumEntries > 65536 {
		return nil, errors.New("ROUTE_LIMIT")
	}
	return append([]windows.MibIpForwardRow2(nil), p.Rows()...), nil
}
func sourceRows() ([]windows.MibUnicastIpAddressRow, error) {
	var p *windows.MibUnicastIpAddressTable
	if e := windows.GetUnicastIpAddressTable(windows.AF_UNSPEC, &p); e != nil {
		return nil, e
	}
	if p == nil {
		return nil, errors.New("ADDRESS_QUERY")
	}
	defer windows.FreeMibTable(unsafe.Pointer(p))
	if p.NumEntries > 65536 {
		return nil, errors.New("ADDRESS_LIMIT")
	}
	return append([]windows.MibUnicastIpAddressRow(nil), unsafe.Slice(&p.Table[0], int(p.NumEntries))...), nil
}
func (n *nativeOS) Snapshot(ctx context.Context, exclude uint64) (Physical, error) {
	var out Physical
	if e := ctx.Err(); e != nil {
		return out, e
	}
	adapters, backing, e := adapterList()
	if e != nil {
		return out, e
	}
	defer runtime.KeepAlive(backing)
	rs, e := routes()
	if e != nil {
		return out, e
	}
	sources, e := sourceRows()
	if e != nil {
		return out, e
	}
	type candidate struct {
		metric, index uint32
		a             *windows.IpAdapterAddresses
		hop           string
	}
	selected := map[uint64]*windows.IpAdapterAddresses{}
	var identity, metrics, gateways, addresses []string
	for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
		collectCandidates := func(requireHardware bool) ([]candidate, error) {
			var list []candidate
			for _, a := range adapters {
				if a.Luid == exclude || a.OperStatus != windows.IfOperStatusUp || a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
					continue
				}
				if strings.HasPrefix(windows.UTF16PtrToString(a.FriendlyName), "Kat-") {
					continue
				}
				if requireHardware {
					if a.IfType == windows.IF_TYPE_TUNNEL || a.TunnelType != 0 {
						continue
					}
					row := windows.MibIfRow2{InterfaceLuid: a.Luid}
					if err := windows.GetIfEntry2Ex(0, &row); err != nil {
						continue
					}
					if row.InterfaceAndOperStatusFlags&1 == 0 {
						continue
					}
				}
				index, metric := a.IfIndex, a.Ipv4Metric
				if family == windows.AF_INET6 {
					index, metric = a.Ipv6IfIndex, a.Ipv6Metric
				}
				for _, r := range rs {
					if r.InterfaceLuid != a.Luid || r.DestinationPrefix.PrefixLength != 0 || r.DestinationPrefix.Prefix.Family != family || index == 0 {
						continue
					}
					hop, _, err := sockaddrIP(unsafe.Pointer(&r.NextHop))
					if err != nil {
						return nil, err
					}
					sum := uint64(r.Metric) + uint64(metric)
					if sum > 0xffffffff {
						sum = 0xffffffff
					}
					list = append(list, candidate{uint32(sum), index, a, hop.String()})
				}
			}
			return list, nil
		}
		choices, err := collectCandidates(true)
		if err != nil {
			return out, err
		}
		if len(choices) == 0 {
			choices, err = collectCandidates(false)
			if err != nil {
				return out, err
			}
		}
		sort.Slice(choices, func(i, j int) bool {
			a, b := choices[i], choices[j]
			if a.metric != b.metric {
				return a.metric < b.metric
			}
			if a.index != b.index {
				return a.index < b.index
			}
			return a.hop < b.hop
		})
		if len(choices) == 0 {
			continue
		}
		var c candidate
		var o FamilyOwner
		foundChoice := false
		for _, cand := range choices {
			if owner, err := familyOwner(cand.a.Luid, cand.index, family, sources); err == nil {
				c = cand
				o = owner
				foundChoice = true
				break
			}
		}
		if !foundChoice {
			continue
		}
		selected[c.a.Luid] = c.a
		if family == windows.AF_INET {
			out.IPv4 = &o
			out.Options.IPv4 = &o.IfIndex
			out.Options.LUID4 = &o.LUID
		} else {
			out.IPv6 = &o
			out.Options.IPv6 = &o.IfIndex
			out.Options.LUID6 = &o.LUID
		}
		identity = append(identity, fmt.Sprintf("%d:%d:%d:%s", family, o.LUID, o.IfIndex, o.GUID))
		metrics = append(metrics, fmt.Sprint(family, ":", c.metric))
		gateways = append(gateways, fmt.Sprint(family, ":", c.hop))
	}
	if len(selected) == 0 {
		return out, errors.New("WAITING_NETWORK")
	}
	// Preserve deterministic default-owner order (v4 then v6), then the OS DNS
	// order within each authorized owner, including IPv6-only DNS on a v4 owner.
	var owners []uint64
	if out.IPv4 != nil {
		owners = append(owners, out.IPv4.LUID)
	}
	if out.IPv6 != nil && (len(owners) == 0 || owners[0] != out.IPv6.LUID) {
		owners = append(owners, out.IPv6.LUID)
	}
	ownerFamilies := map[[2]uint64]bool{}
	dnsSeen := map[clientegress.DNSEndpoint]bool{}
	for _, luid := range owners {
		a := selected[luid]
		for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
			index := a.IfIndex
			if family == windows.AF_INET6 {
				index = a.Ipv6IfIndex
			}
			if index == 0 {
				continue
			}
			o, err := familyOwner(luid, index, family, sources)
			if err != nil {
				if family == windows.AF_INET && out.IPv4 != nil && out.IPv4.LUID == luid || family == windows.AF_INET6 && out.IPv6 != nil && out.IPv6.LUID == luid {
					return out, err
				}
				continue
			}
			out.Owners = append(out.Owners, o)
			ownerFamilies[[2]uint64{luid, uint64(family)}] = true
			for _, s := range o.Sources {
				addresses = append(addresses, fmt.Sprint(luid, ":", family, ":", s.Address, ":", s.Scope, ":", s.Usable))
			}
		}
		count := 0
		for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
			count++
			if count > 64 {
				return out, errors.New("DNS_LIMIT")
			}
			if d.Address.Sockaddr == nil {
				continue
			}
			ip, scope, err := sockaddrIP(unsafe.Pointer(d.Address.Sockaddr))
			if err != nil {
				return out, err
			}
			family, index := uint16(windows.AF_INET), a.IfIndex
			if ip.Is6() {
				family, index = windows.AF_INET6, a.Ipv6IfIndex
			}
			if !ownerFamilies[[2]uint64{luid, uint64(family)}] {
				continue
			}
			if !validDNS(ip) {
				continue
			}
			if ip.IsLinkLocalUnicast() {
				scope = index
			} else {
				scope = 0
			}
			ep := clientegress.DNSEndpoint{Address: ip.String(), Owner: luid, IfIndex: index, Scope: scope}
			if !dnsSeen[ep] && len(out.DNS) < clientegress.MaxSystemDNS {
				out.DNS = append(out.DNS, ep)
				dnsSeen[ep] = true
			}
		}
	}

	// Re-read other hardware owners to preserve valid established flows across
	// a true default-owner switch. This does not authorize new flows/DNS there.
	for _, a := range adapters {
		if a.Luid == exclude || selected[a.Luid] != nil || a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || a.IfType == windows.IF_TYPE_TUNNEL || a.TunnelType != 0 {
			continue
		}
		hw := windows.MibIfRow2{InterfaceLuid: a.Luid}
		if err := windows.GetIfEntry2Ex(0, &hw); err != nil {
			continue
		}
		if hw.InterfaceAndOperStatusFlags&1 == 0 {
			continue
		}
		for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
			index := a.IfIndex
			if family == windows.AF_INET6 {
				index = a.Ipv6IfIndex
			}
			if index == 0 {
				continue
			}
			o, err := familyOwner(a.Luid, index, family, sources)
			if err != nil {
				continue
			}
			o.Up = o.Up && a.OperStatus == windows.IfOperStatusUp
			out.Owners = append(out.Owners, o)
		}
	}
	if len(out.DNS) == 0 {
		for _, a := range adapters {
			if a.Luid == exclude || a.OperStatus != windows.IfOperStatusUp || a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || strings.HasPrefix(windows.UTF16PtrToString(a.FriendlyName), "Kat-") {
				continue
			}
			count := 0
			for d := a.FirstDnsServerAddress; d != nil && count < 64; d = d.Next {
				count++
				if d.Address.Sockaddr == nil {
					continue
				}
				ip, _, err := sockaddrIP(unsafe.Pointer(d.Address.Sockaddr))
				if err != nil || !validDNS(ip) || ip.IsLinkLocalUnicast() {
					continue
				}
				var owner uint64
				var index uint32
				if ip.Is4() && out.IPv4 != nil {
					owner, index = out.IPv4.LUID, out.IPv4.IfIndex
				} else if ip.Is6() && out.IPv6 != nil {
					owner, index = out.IPv6.LUID, out.IPv6.IfIndex
				} else {
					continue
				}
				ep := clientegress.DNSEndpoint{Address: ip.String(), Owner: owner, IfIndex: index, Scope: 0}
				if !dnsSeen[ep] && len(out.DNS) < clientegress.MaxSystemDNS {
					out.DNS = append(out.DNS, ep)
					dnsSeen[ep] = true
				}
			}
		}
	}
	if len(out.DNS) == 0 {
		if out.IPv4 != nil {
			for _, addr := range []string{"8.8.8.8", "1.1.1.1"} {
				ep := clientegress.DNSEndpoint{Address: addr, Owner: out.IPv4.LUID, IfIndex: out.IPv4.IfIndex, Scope: 0}
				out.DNS = append(out.DNS, ep)
			}
		} else if out.IPv6 != nil {
			ep := clientegress.DNSEndpoint{Address: "2001:4860:4860::8888", Owner: out.IPv6.LUID, IfIndex: out.IPv6.IfIndex, Scope: 0}
			out.DNS = append(out.DNS, ep)
		}
	}
	// Own virtual-address conflict check, without routing any physical DNS/router.
	peer := netip.MustParseAddr("198.18.0.2")
	for _, r := range rs {
		if r.InterfaceLuid == exclude || r.DestinationPrefix.PrefixLength <= 1 {
			continue
		}
		ip, _, err := sockaddrIP(unsafe.Pointer(&r.DestinationPrefix.Prefix))
		if err != nil {
			return out, err
		}
		if ip.Is4() && r.DestinationPrefix.PrefixLength <= 32 && netip.PrefixFrom(ip, int(r.DestinationPrefix.PrefixLength)).Contains(peer) {
			return out, errors.New("DNS_PEER_CONFLICT")
		}
	}
	for _, s := range sources {
		if s.InterfaceLuid == exclude {
			continue
		}
		ip, _, err := sockaddrIP(unsafe.Pointer(&s.Address))
		if err != nil {
			return out, err
		}
		if netip.MustParsePrefix("198.18.0.0/30").Contains(ip) || netip.MustParsePrefix("fd4b:6174::/126").Contains(ip) {
			return out, errors.New("TUN_ADDRESS_CONFLICT")
		}
	}
	sort.Strings(addresses)
	out.Options.Schema = clientegress.Schema
	out.Options.Enabled = true
	out.Options.DNS = out.DNS
	out.Options.Identity = digestText(identity)
	out.Options.MetricDigest = digestText(metrics)
	out.Options.GatewayDigest = digestText(gateways)
	out.Options.AddressDigest = digestText(addresses)
	out.Options.Fingerprint = digestText([]any{identity, metrics, gateways, addresses, out.DNS})
	return out, nil
}
func familyOwner(luid uint64, index uint32, family uint16, sources []windows.MibUnicastIpAddressRow) (FamilyOwner, error) {
	var o FamilyOwner
	r := windows.MibIpInterfaceRow{Family: family, InterfaceLuid: luid}
	if e := windows.GetIpInterfaceEntry(&r); e != nil {
		return o, e
	}
	g, e := guidOf(luid)
	if e != nil {
		return o, e
	}
	if r.InterfaceLuid != luid || r.InterfaceIndex != index {
		return o, errors.New("PHYSICAL_OWNER_CHANGED")
	}
	o = FamilyOwner{Family: family, LUID: luid, IfIndex: index, GUID: strings.Trim(g.String(), "{}"), Up: r.Connected != 0, Hardware: true, Forwarding: false, WeakHostSend: false}
	hasUsable := false
	for _, s := range sources {
		if s.InterfaceLuid != luid || s.Address.Family != family {
			continue
		}
		ip, scope, e := sockaddrIP(unsafe.Pointer(&s.Address))
		if e != nil {
			return o, e
		}
		if ip.IsLinkLocalUnicast() && scope == 0 {
			scope = index
		}
		usable := s.SkipAsSource == 0 && (s.DadState == 4 || s.DadState == 3) && s.ValidLifetime > 0
		if usable {
			hasUsable = true
		}
		o.Sources = append(o.Sources, Source{Address: ip, Scope: scope, Usable: usable})
	}
	if !hasUsable {
		for i := range o.Sources {
			if o.Sources[i].Address.IsValid() && !o.Sources[i].Address.IsUnspecified() && !o.Sources[i].Address.IsLoopback() {
				o.Sources[i].Usable = true
				break
			}
		}
	}
	return o, nil
}
func validDNS(ip netip.Addr) bool {
	return ip.IsValid() && !ip.Is4In6() && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !netip.MustParsePrefix("198.18.0.0/30").Contains(ip) && !netip.MustParsePrefix("fd4b:6174::/126").Contains(ip) && !netip.MustParsePrefix("198.19.0.0/16").Contains(ip) && !netip.MustParsePrefix("fd4b:6174:6661::/112").Contains(ip)
}
func (n *nativeOS) Watch(ctx context.Context) (<-chan struct{}, error) {
	dirty := make(chan struct{}, 1)
	signal := func() {
		select {
		case dirty <- struct{}{}:
		default:
		}
	}
	callback := windows.NewCallback(func(_ uintptr, _ uintptr, _ uint32) uintptr { signal(); return 0 })
	var handles []windows.Handle
	cleanup := func() {
		for _, h := range handles {
			windows.CancelMibChangeNotify2(h)
		}
	}
	for _, name := range []string{"NotifyRouteChange2", "NotifyIpInterfaceChange", "NotifyUnicastIpAddressChange"} {
		var h windows.Handle
		if e := ipCall(name, windows.AF_UNSPEC, callback, 0, 0, uintptr(unsafe.Pointer(&h))); e != nil {
			cleanup()
			return nil, e
		}
		handles = append(handles, h)
	}
	// DNS configuration notifications via the documented registry change API.
	// These fixed HKLM TCP/IP subtree watchers are read-only and merely trigger
	// GetAdaptersAddresses again. Low-frequency verification covers other writers.
	type watch struct {
		k     registry.Key
		event windows.Handle
	}
	var dns []watch
	for _, path := range []string{`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`, `SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces`} {
		k, e := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.NOTIFY|registry.QUERY_VALUE)
		if e != nil {
			cleanup()
			for _, w := range dns {
				w.k.Close()
				windows.CloseHandle(w.event)
			}
			return nil, e
		}
		ev, e := windows.CreateEvent(nil, 0, 0, nil)
		if e != nil {
			k.Close()
			cleanup()
			return nil, e
		}
		dns = append(dns, watch{k, ev})
	}
	notify := windows.NewLazySystemDLL("advapi32.dll").NewProc("RegNotifyChangeKeyValue")
	arm := func(w watch) error {
		r, _, _ := notify.Call(uintptr(w.k), 1, 0x1|0x4|0x10000000, uintptr(w.event), 1)
		if r != 0 {
			return syscallError(r)
		}
		return nil
	}
	for _, w := range dns {
		if e := arm(w); e != nil {
			cleanup()
			for _, x := range dns {
				x.k.Close()
				windows.CloseHandle(x.event)
			}
			return nil, e
		}
	}
	go func() {
		defer cleanup()
		defer func() {
			for _, w := range dns {
				w.k.Close()
				windows.CloseHandle(w.event)
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			for _, w := range dns {
				r, e := windows.WaitForSingleObject(w.event, 250)
				if e != nil {
					signal()
					return
				}
				if r == windows.WAIT_OBJECT_0 {
					if arm(w) != nil {
						signal()
						return
					}
					signal()
				}
			}
		}
	}()
	return dirty, nil
}
func syscallError(v uintptr) error { return fmt.Errorf("DNS_NOTIFY: native=%d", v) }
