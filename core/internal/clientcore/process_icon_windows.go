//go:build windows

package clientcore

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var (
	modOle32                = syscall.NewLazyDLL("ole32.dll")
	modShell32              = syscall.NewLazyDLL("shell32.dll")
	modUser32               = syscall.NewLazyDLL("user32.dll")
	modGdi32                = syscall.NewLazyDLL("gdi32.dll")
	procCoInitializeEx      = modOle32.NewProc("CoInitializeEx")
	procCoUninitialize      = modOle32.NewProc("CoUninitialize")
	procPrivateExtractIcons = modUser32.NewProc("PrivateExtractIconsW")
	procSHGetFileInfoW      = modShell32.NewProc("SHGetFileInfoW")
	procGetIconInfo         = modUser32.NewProc("GetIconInfo")
	procDestroyIcon         = modUser32.NewProc("DestroyIcon")
	procGetDC               = modUser32.NewProc("GetDC")
	procReleaseDC           = modUser32.NewProc("ReleaseDC")
	procGetObjectW          = modGdi32.NewProc("GetObjectW")
	procGetDIBits           = modGdi32.NewProc("GetDIBits")
	procDeleteObject        = modGdi32.NewProc("DeleteObject")

	procIconCache      sync.Map
	procIconCacheCount atomic.Int32
)

const (
	coinitApartmentThreaded = 0x2
	coinitDisableOle1DDE    = 0x4
	shgfiIcon               = 0x000000100
	shgfiLargeIcon          = 0x000000000
	biRGB                   = 0
	dibRGBColors            = 0
)

type shFileInfoW struct {
	hIcon         uintptr
	iIcon         int32
	dwAttributes  uint32
	szDisplayName [260]uint16
	szTypeName    [80]uint16
}

type winIconInfo struct {
	fIcon    int32
	xHotspot uint32
	yHotspot uint32
	hbmMask  uintptr
	hbmColor uintptr
}

type winBitmap struct {
	bmType       int32
	bmWidth      int32
	bmHeight     int32
	bmWidthBytes int32
	bmPlanes     uint16
	bmBitsPixel  uint16
	bmBits       uintptr
}

type bitmapInfoHeader struct {
	biSize          uint32
	biWidth         int32
	biHeight        int32
	biPlanes        uint16
	biBitCount      uint16
	biCompression   uint32
	biSizeImage     uint32
	biXPelsPerMeter int32
	biYPelsPerMeter int32
}

func extractProcessIconDataURI(exePath string) string {
	p := strings.TrimSpace(exePath)
	// Reject empty, overly long, or UNC/network paths to prevent any SMB traffic.
	if p == "" || len(p) > 1024 || strings.HasPrefix(p, `\`) || strings.HasPrefix(p, "//") {
		return ""
	}
	key := strings.ToLower(p)
	if cached, ok := procIconCache.Load(key); ok {
		return cached.(string)
	}
	wide, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		return ""
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hr, _, _ := procCoInitializeEx.Call(0, coinitApartmentThreaded|coinitDisableOle1DDE)
	if hr == 0 || hr == 1 { // S_OK or S_FALSE
		defer procCoUninitialize.Call()
	}

	var hIcon uintptr
	var iconID uint32
	// 1. Try direct PE 48x48 high-DPI icon resource extraction first.
	extracted, _, _ := procPrivateExtractIcons.Call(
		uintptr(unsafe.Pointer(wide)),
		0,
		48,
		48,
		uintptr(unsafe.Pointer(&hIcon)),
		uintptr(unsafe.Pointer(&iconID)),
		1,
		0,
	)
	if extracted == 0 || extracted == 0xFFFFFFFF || hIcon == 0 {
		hIcon = 0
		// 2. Fallback to Shell SHGetFileInfoW (handles MSIX/Store/WindowsApps aliases).
		var sfi shFileInfoW
		ret, _, _ := procSHGetFileInfoW.Call(
			uintptr(unsafe.Pointer(wide)),
			0,
			uintptr(unsafe.Pointer(&sfi)),
			unsafe.Sizeof(sfi),
			shgfiIcon|shgfiLargeIcon,
		)
		if ret != 0 && sfi.hIcon != 0 {
			hIcon = sfi.hIcon
		}
	}
	if hIcon == 0 {
		return ""
	}
	defer procDestroyIcon.Call(hIcon)

	var ii winIconInfo
	if ok, _, _ := procGetIconInfo.Call(hIcon, uintptr(unsafe.Pointer(&ii))); ok == 0 {
		return ""
	}
	if ii.hbmMask != 0 {
		defer procDeleteObject.Call(ii.hbmMask)
	}
	if ii.hbmColor == 0 {
		return ""
	}
	defer procDeleteObject.Call(ii.hbmColor)

	var bm winBitmap
	if got, _, _ := procGetObjectW.Call(ii.hbmColor, unsafe.Sizeof(bm), uintptr(unsafe.Pointer(&bm))); got == 0 {
		return ""
	}
	w, h := int(bm.bmWidth), int(bm.bmHeight)
	if w <= 0 || h <= 0 || w > 256 || h > 256 {
		return ""
	}

	hdc, _, _ := procGetDC.Call(0)
	if hdc == 0 {
		return ""
	}
	defer procReleaseDC.Call(0, hdc)

	bmi := bitmapInfoHeader{
		biSize:        uint32(unsafe.Sizeof(bitmapInfoHeader{})),
		biWidth:       int32(w),
		biHeight:      -int32(h),
		biPlanes:      1,
		biBitCount:    32,
		biCompression: biRGB,
	}
	pixels := make([]byte, w*h*4)
	lines, _, _ := procGetDIBits.Call(
		hdc,
		ii.hbmColor,
		0,
		uintptr(h),
		uintptr(unsafe.Pointer(&pixels[0])),
		uintptr(unsafe.Pointer(&bmi)),
		dibRGBColors,
	)
	if lines == 0 {
		return ""
	}

	hasAlpha := false
	for i := 3; i < len(pixels); i += 4 {
		if pixels[i] != 0 {
			hasAlpha = true
			break
		}
	}
	var maskPixels []byte
	if !hasAlpha && ii.hbmMask != 0 {
		maskPixels = make([]byte, w*h*4)
		bmiMask := bmi
		procGetDIBits.Call(
			hdc,
			ii.hbmMask,
			0,
			uintptr(h),
			uintptr(unsafe.Pointer(&maskPixels[0])),
			uintptr(unsafe.Pointer(&bmiMask)),
			dibRGBColors,
		)
	}

	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			off := (y*w + x) * 4
			b, g, r, a := pixels[off], pixels[off+1], pixels[off+2], pixels[off+3]
			if !hasAlpha {
				if len(maskPixels) == len(pixels) && maskPixels[off] != 0 {
					a = 0
				} else {
					a = 255
				}
			}
			img.SetNRGBA(x, y, color.NRGBA{R: r, G: g, B: b, A: a})
		}
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil || buf.Len() == 0 || buf.Len() > maxIconBytes {
		return ""
	}
	uri := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
	if procIconCacheCount.Load() < 256 {
		if _, loaded := procIconCache.LoadOrStore(key, uri); !loaded {
			procIconCacheCount.Add(1)
		}
	}
	return uri
}
