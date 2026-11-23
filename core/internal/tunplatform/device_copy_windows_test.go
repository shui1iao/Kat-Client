//go:build windows

package tunplatform

import (
	"bytes"
	"golang.org/x/sys/windows"
	"testing"
)

// Checks the user-mode copy ABI without Wintun, elevation or a network change.
func TestNativeRingCopyABI(t *testing.T) {
	if err := ringMove.Find(); err != nil {
		t.Fatal(err)
	}
	d := nativeDevice{moveMemory: ringMove.Addr()}
	for _, n := range []int{1, MTU, 65535} {
		func() {
			mem, err := windows.LocalAlloc(0, uint32(n+2))
			if err != nil {
				t.Fatal(err)
			}
			defer windows.LocalFree(windows.Handle(mem))
			untouched := bytes.Repeat([]byte{0xaa}, n+2)
			d.copyToRing(mem, untouched)
			data := make([]byte, n)
			for i := range data {
				data[i] = byte(i*7 + 13)
			}
			d.copyToRing(mem+1, data)
			got := bytes.Repeat([]byte{0xff}, n+4)
			d.copyFromRing(got[1:n+3], mem)
			if got[0] != 0xff || got[n+3] != 0xff || got[1] != 0xaa || got[n+2] != 0xaa || !bytes.Equal(got[2:n+2], data) {
				t.Fatal("native copy bounds or contents", n)
			}
		}()
	}
}
