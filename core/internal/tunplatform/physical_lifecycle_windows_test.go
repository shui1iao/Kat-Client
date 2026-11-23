//go:build windows

package tunplatform

import (
	"errors"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"testing"
	"unsafe"
)

func TestOwnerSourcesNeverPromotesUnusableRow(t *testing.T) {
	row := windows.MibUnicastIpAddressRow{InterfaceLuid: 7, InterfaceIndex: 3, SkipAsSource: 1, DadState: 4, ValidLifetime: 100}
	raw := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
	raw.Family = windows.AF_INET
	raw.Addr = [4]byte{192, 0, 2, 1}
	check := func(want bool) {
		t.Helper()
		sources, err := ownerSources(7, 3, windows.AF_INET, []windows.MibUnicastIpAddressRow{row})
		if err != nil || len(sources) != 1 || sources[0].Usable != want {
			t.Fatal(sources, err)
		}
		o := FamilyOwner{Family: windows.AF_INET, IfIndex: 3, LUID: 7, Up: true, Sources: sources}
		if ok := physicalSafe(Physical{IPv4: &o, Owners: []FamilyOwner{o}}) == nil; ok != want {
			t.Fatal("inconsistent initial admission", sources)
		}
	}
	check(false)
	row.SkipAsSource = 0
	row.DadState = 1
	check(false)
	row.DadState = 4
	row.ValidLifetime = 0
	check(false)
	row.ValidLifetime = 1
	check(true)
}

// Only opens read-only test keys and private events. No network notifications
// or TUN adapter are created. Exercise the partial second-pair acquisition.
func TestRegistryWatchSecondEventFailureClosesAll(t *testing.T) {
	var keys []registry.Key
	var events []windows.Handle
	injected := errors.New("second event failed")
	ws, err := openRegistryWatches(func(string) (registry.Key, error) {
		k, e := registry.OpenKey(registry.CURRENT_USER, `Software`, registry.QUERY_VALUE)
		if e == nil {
			keys = append(keys, k)
		}
		return k, e
	}, func() (windows.Handle, error) {
		if len(events) == 1 {
			return 0, injected
		}
		h, e := windows.CreateEvent(nil, 0, 0, nil)
		if e == nil {
			events = append(events, h)
		}
		return h, e
	})
	if !errors.Is(err, injected) || ws != nil || len(keys) != 2 || len(events) != 1 {
		t.Fatal(ws, err)
	}
	for _, k := range keys {
		if _, err := k.Stat(); !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
			t.Fatal("registry key not closed", err)
		}
	}
	if _, err := windows.WaitForSingleObject(events[0], 0); !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
		t.Fatal("event not closed", err)
	}
}
