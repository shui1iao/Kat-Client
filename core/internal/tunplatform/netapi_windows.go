//go:build windows

package tunplatform

// Kat-owned IP Helper ABI glue from Microsoft netioapi/iphlpapi documentation.
// x/sys BSD structs are used where provided; only our adapter may be written.
import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"net/netip"
	"reflect"
	"strings"
	"syscall"
	"unsafe"
)

var ipDLL = windows.NewLazySystemDLL("iphlpapi.dll")
var cfgmgrDLL = windows.NewLazySystemDLL("cfgmgr32.dll")

const (
	cmLocateDevnodePhantom = 1
	crNoSuchDevnode        = 0x0000000D
)

func validGUIDText(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isUninstalledTombstone(r windows.MibIfRow2, guid string) bool {
	if r.OperStatus != windows.IfOperStatusDown || r.InterfaceLuid == 0 || !validGUIDText(guid) {
		return false
	}
	instance, err := windows.UTF16PtrFromString(`SWD\Wintun\{` + guid + `}`)
	if err != nil {
		return false
	}
	var devInst uint32
	cr, _, _ := cfgmgrDLL.NewProc("CM_Locate_DevNodeW").Call(
		uintptr(unsafe.Pointer(&devInst)),
		uintptr(unsafe.Pointer(instance)),
		cmLocateDevnodePhantom,
	)
	if uint32(cr) != crNoSuchDevnode {
		return false
	}
	for _, fam := range []uint16{windows.AF_INET, windows.AF_INET6} {
		ipRow := windows.MibIpInterfaceRow{Family: fam, InterfaceLuid: r.InterfaceLuid}
		if err := windows.GetIpInterfaceEntry(&ipRow); !errors.Is(err, windows.ERROR_NOT_FOUND) {
			return false
		}
	}
	return true
}

func ipCall(name string, args ...uintptr) error {
	r, _, _ := ipDLL.NewProc(name).Call(args...)
	if r != 0 {
		return fmt.Errorf("%s: %w", name, syscall.Errno(r))
	}
	return nil
}
func rawIP(s string) windows.RawSockaddrInet {
	var r windows.RawSockaddrInet
	ip := netip.MustParseAddr(s)
	if ip.Is4() {
		a := (*windows.RawSockaddrInet4)(unsafe.Pointer(&r))
		a.Family = windows.AF_INET
		a.Addr = ip.As4()
	} else {
		a := (*windows.RawSockaddrInet6)(unsafe.Pointer(&r))
		a.Family = windows.AF_INET6
		a.Addr = ip.As16()
	}
	return r
}
func sockaddrIP(p unsafe.Pointer) (netip.Addr, uint32, error) {
	family := *(*uint16)(p)
	switch family {
	case windows.AF_INET:
		r := (*windows.RawSockaddrInet4)(p)
		return netip.AddrFrom4(r.Addr), 0, nil
	case windows.AF_INET6:
		r := (*windows.RawSockaddrInet6)(p)
		return netip.AddrFrom16(r.Addr), r.Scope_id, nil
	}
	return netip.Addr{}, 0, errors.New("ADDRESS_FAMILY")
}
func routeRow(a Adapter, v *RouteValue) windows.MibIpForwardRow2 {
	var r windows.MibIpForwardRow2
	ipDLL.NewProc("InitializeIpForwardEntry").Call(uintptr(unsafe.Pointer(&r))) // void; initialized values below are explicit
	r.InterfaceLuid = a.LUID
	r.DestinationPrefix.Prefix = rawIP(v.Destination)
	r.DestinationPrefix.PrefixLength = v.Prefix
	r.NextHop = rawIP(v.NextHop)
	r.SitePrefixLength = v.SitePrefix
	r.ValidLifetime = v.ValidLifetime
	r.PreferredLifetime = v.PreferredLifetime
	r.Metric = v.Metric
	r.Protocol = v.Protocol
	r.Loopback = flag(v.Loopback)
	r.AutoconfigureAddress = flag(v.Autoconfigure)
	r.Publish = flag(v.Publish)
	r.Immortal = flag(v.Immortal)
	return r
}
func flag(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}
func addressRow(a Adapter, v *AddressValue) windows.MibUnicastIpAddressRow {
	var r windows.MibUnicastIpAddressRow
	ipDLL.NewProc("InitializeUnicastIpAddressEntry").Call(uintptr(unsafe.Pointer(&r)))
	r.InterfaceLuid = a.LUID
	raw := rawIP(v.Address)
	r.Address = *(*windows.RawSockaddrInet6)(unsafe.Pointer(&raw))
	r.OnLinkPrefixLength = v.Prefix
	r.PrefixOrigin = v.PrefixOrigin
	r.SuffixOrigin = v.SuffixOrigin
	r.SkipAsSource = flag(v.SkipAsSource)
	r.DadState = 4
	return r
}

type dnsSettings struct {
	Version                                                                 uint32
	Flags                                                                   uint64
	Domain, NameServer, SearchList                                          *uint16
	RegistrationEnabled, RegisterAdapterName, EnableLLMNR, QueryAdapterName uint32
	ProfileNameServer                                                       *uint16
}

func guidOf(luid uint64) (windows.GUID, error) {
	var g windows.GUID
	e := ipCall("ConvertInterfaceLuidToGuid", uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&g)))
	return g, e
}

type nativeOS struct{ launch Launch }

func platformOS(l Launch) (osBackend, error) {
	if l.Schema != JournalSchema || l.Engine != Engine || l.CorePID != windows.GetCurrentProcessId() {
		return nil, errors.New("CORE_IDENTITY")
	}
	token, e := windows.OpenCurrentProcessToken()
	if e != nil {
		return nil, At("make_token_open", "", e)
	}
	defer token.Close()
	user, e := token.GetTokenUser()
	if e != nil {
		return nil, At("make_token_user", "", e)
	}
	if user.User.Sid.String() != l.OwnerSID || !token.IsElevated() {
		return nil, At("make_token_check", "CORE_TOKEN", errors.New("CORE_TOKEN"))
	}
	var c, x, k, u windows.Filetime
	if e = windows.GetProcessTimes(windows.CurrentProcess(), &c, &x, &k, &u); e != nil {
		return nil, At("make_creation", "", e)
	}
	if uint64(c.HighDateTime)<<32|uint64(c.LowDateTime) != l.CoreCreated {
		return nil, At("make_creation", "CORE_IDENTITY", errors.New("CORE_IDENTITY"))
	}
	return &nativeOS{launch: l}, nil
}
func (n *nativeOS) Device(ctx context.Context, a Adapter) (Device, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	return createNativeDevice(a)
}
func (n *nativeOS) Gone(ctx context.Context, a Adapter) (bool, error) {
	r, e := n.InspectGone(ctx, a)
	return r.Gone, e
}
func (n *nativeOS) InspectGone(ctx context.Context, a Adapter) (GoneRead, error) {
	out := GoneRead{Rows: []GoneRow{}}
	if e := ctx.Err(); e != nil {
		return out, e
	}
	comp, _, _ := ipDLL.NewProc("GetCurrentThreadCompartmentId").Call()
	out.Compartment = uint32(comp)
	if a.Compartment != 1 || out.Compartment != a.Compartment {
		return out, errors.New("RECOVERY_COMPARTMENT")
	}
	rows, rc, e := ifRows()
	out.RC = rc
	if e != nil {
		return out, e
	}
	conflict := false
	for _, r := range rows {
		g := strings.Trim(r.InterfaceGuid.String(), "{}")
		if (a.LUID != 0 && r.InterfaceLuid == a.LUID) || strings.EqualFold(g, a.GUID) {
			if !strings.EqualFold(g, a.GUID) || (a.LUID != 0 && r.InterfaceLuid != a.LUID) {
				out.Rows = append(out.Rows, GoneRow{GUID: strings.ToLower(g), LUID: fmt.Sprint(r.InterfaceLuid), OperStatus: r.OperStatus})
				conflict = true
				continue
			}
			if isUninstalledTombstone(r, g) {
				continue
			}
			out.Rows = append(out.Rows, GoneRow{GUID: strings.ToLower(g), LUID: fmt.Sprint(r.InterfaceLuid), OperStatus: r.OperStatus})
		}
	}
	if conflict {
		return out, errors.New("RECOVERY_CONFLICT")
	}
	out.Gone = len(out.Rows) == 0
	return out, nil
}
func ifRows() ([]windows.MibIfRow2, *uint32, error) {
	var p *windows.MibIfTable2
	// Convert at the annotated native Call boundary, not through a variadic
	// uintptr wrapper: keep the output pointer tracked for the whole syscall.
	rc, _, _ := ipDLL.NewProc("GetIfTable2").Call(uintptr(unsafe.Pointer(&p)))
	result := uint32(rc)
	if rc != 0 {
		return nil, &result, syscall.Errno(rc)
	}
	if p == nil {
		return nil, &result, errors.New("INTERFACE_QUERY")
	}
	defer windows.FreeMibTable(unsafe.Pointer(p))
	if p.NumEntries > 65536 {
		return nil, &result, errors.New("INTERFACE_LIMIT")
	}
	return append([]windows.MibIfRow2(nil), unsafe.Slice(&p.Table[0], int(p.NumEntries))...), &result, nil
}
func (n *nativeOS) Read(ctx context.Context, a Adapter, c Change) (*Value, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	var compartment uint32
	v, _, _ := ipDLL.NewProc("GetCurrentThreadCompartmentId").Call()
	compartment = uint32(v)
	if compartment != 1 || a.Compartment != 1 {
		return nil, errors.New("RECOVERY_COMPARTMENT")
	}
	if c.Installed.Route != nil {
		r := routeRow(a, c.Installed.Route)
		e := windows.GetIpForwardEntry2(&r)
		if errors.Is(e, windows.ERROR_NOT_FOUND) {
			return nil, nil
		}
		if e != nil {
			return nil, e
		}
		if _, e = n.Gone(ctx, a); e != nil {
			return nil, e
		}
		dest, _, e := sockaddrIP(unsafe.Pointer(&r.DestinationPrefix.Prefix))
		if e != nil {
			return nil, e
		}
		hop, scope, e := sockaddrIP(unsafe.Pointer(&r.NextHop))
		if e != nil {
			return nil, e
		}
		return &Value{Route: &RouteValue{Destination: dest.String(), Prefix: r.DestinationPrefix.PrefixLength, NextHop: hop.String(), Scope: scope, Metric: r.Metric, Protocol: r.Protocol, SitePrefix: r.SitePrefixLength, ValidLifetime: r.ValidLifetime, PreferredLifetime: r.PreferredLifetime, Loopback: r.Loopback != 0, Autoconfigure: r.AutoconfigureAddress != 0, Publish: r.Publish != 0, Immortal: r.Immortal != 0, Origin: r.Origin}}, nil
	}
	gone, e := n.Gone(ctx, a)
	if e != nil || gone {
		return nil, e
	}
	if v := c.Installed.Address; v != nil {
		r := addressRow(a, v)
		e := windows.GetUnicastIpAddressEntry(&r)
		if errors.Is(e, windows.ERROR_NOT_FOUND) {
			return nil, nil
		}
		if e != nil {
			return nil, e
		}
		return &Value{Address: &AddressValue{Address: v.Address, Prefix: r.OnLinkPrefixLength, PrefixOrigin: r.PrefixOrigin, SuffixOrigin: r.SuffixOrigin, SkipAsSource: r.SkipAsSource != 0}}, nil
	}
	if v := c.Installed.Interface; v != nil {
		r := windows.MibIpInterfaceRow{Family: v.Family, InterfaceLuid: a.LUID}
		if e := windows.GetIpInterfaceEntry(&r); e != nil {
			return nil, e
		}
		return &Value{Interface: &InterfaceValue{Family: r.Family, MTU: r.NlMtu, Metric: r.Metric, AutomaticMetric: r.UseAutomaticMetric != 0, DADTransmits: r.DadTransmits}}, nil
	}
	if c.Installed.DNS != nil {
		g, e := guidOf(a.LUID)
		if e != nil {
			return nil, e
		}
		s := dnsSettings{Version: 1}
		if e = ipCall("GetInterfaceDnsSettings", uintptr(unsafe.Pointer(&g)), uintptr(unsafe.Pointer(&s))); e != nil {
			return nil, e
		}
		defer ipDLL.NewProc("FreeInterfaceDnsSettings").Call(uintptr(unsafe.Pointer(&s)))
		text := ""
		if s.NameServer != nil {
			b := unsafe.Slice(s.NameServer, 32768)
			end := 0
			for end < len(b) && b[end] != 0 {
				end++
			}
			if end == len(b) {
				return nil, errors.New("DNS_LIMIT")
			}
			text = windows.UTF16ToString(b[:end])
		}
		return &Value{DNS: &DNSValue{Servers: text}}, nil
	}
	return nil, errors.New("JOURNAL_VALUE")
}
func (n *nativeOS) Apply(ctx context.Context, a Adapter, c Change) error {
	current, e := n.Read(ctx, a, c)
	if e != nil {
		return e
	}
	target := c.Before
	if c.Desired {
		target = &c.Installed
	}
	if reflect.DeepEqual(current, target) {
		return nil
	}
	expected := &c.Installed
	if c.Desired {
		expected = c.Before
	}
	if !reflect.DeepEqual(current, expected) {
		return errors.New("RECOVERY_CONFLICT")
	}
	if c.Installed.Route != nil {
		r := routeRow(a, c.Installed.Route)
		name := "DeleteIpForwardEntry2"
		if c.Desired {
			name = "CreateIpForwardEntry2"
		}
		e = ipCall(name, uintptr(unsafe.Pointer(&r)))
	}
	if c.Installed.Address != nil {
		r := addressRow(a, c.Installed.Address)
		name := "DeleteUnicastIpAddressEntry"
		if c.Desired {
			name = "CreateUnicastIpAddressEntry"
		}
		e = ipCall(name, uintptr(unsafe.Pointer(&r)))
	}
	if c.Installed.Interface != nil {
		v := target.Interface
		r := windows.MibIpInterfaceRow{Family: v.Family, InterfaceLuid: a.LUID}
		if e = windows.GetIpInterfaceEntry(&r); e != nil {
			return e
		}
		r.NlMtu = v.MTU
		r.Metric = v.Metric
		r.UseAutomaticMetric = flag(v.AutomaticMetric)
		r.DadTransmits = v.DADTransmits
		r.SitePrefixLength = 0
		e = ipCall("SetIpInterfaceEntry", uintptr(unsafe.Pointer(&r)))
	}
	if c.Installed.DNS != nil {
		g, ge := guidOf(a.LUID)
		if ge != nil {
			return ge
		}
		text, ge := windows.UTF16PtrFromString(target.DNS.Servers)
		if ge != nil {
			return ge
		}
		s := dnsSettings{Version: 1, Flags: 2, NameServer: text}
		e = ipCall("SetInterfaceDnsSettings", uintptr(unsafe.Pointer(&g)), uintptr(unsafe.Pointer(&s)))
	}
	if e != nil {
		return e
	}
	observed, e := n.Read(ctx, a, c)
	if e != nil {
		return e
	}
	if !reflect.DeepEqual(observed, target) {
		return errors.New("OS_READBACK")
	}
	return nil
}
