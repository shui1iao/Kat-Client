//go:build windows

package clientcore

import (
	"bytes"
	"encoding/base64"
	"golang.org/x/sys/windows/registry"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
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
	procCreateCompatibleDC  = modGdi32.NewProc("CreateCompatibleDC")
	procDeleteDC            = modGdi32.NewProc("DeleteDC")
	procGetObjectW          = modGdi32.NewProc("GetObjectW")
	procGetDIBits           = modGdi32.NewProc("GetDIBits")
	procDeleteObject        = modGdi32.NewProc("DeleteObject")

	procIconCache          sync.Map
	procIconCacheCount     atomic.Int32
	procNamePathCache      sync.Map
	procNamePathCacheCount atomic.Int32
)

const (
	maxProcIconCacheEntries     = 512
	maxProcNamePathCacheEntries = 1024
)

func storeProcNamePath(key, val string) {
	if procNamePathCacheCount.Load() >= maxProcNamePathCacheEntries {
		procNamePathCache.Clear()
		procNamePathCacheCount.Store(0)
	}
	if _, loaded := procNamePathCache.LoadOrStore(key, val); !loaded {
		procNamePathCacheCount.Add(1)
	}
}

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

// Exact 40-byte Microsoft Win32 BITMAPINFOHEADER ABI (wingdi.h)
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
	biClrUsed       uint32
	biClrImportant  uint32
}

type winBitmapInfo struct {
	bmiHeader bitmapInfoHeader
	bmiColors [4]uint32
}

// Compile-time guarantee that bitmapInfoHeader is strictly 40 bytes!
var _ [40]byte = [unsafe.Sizeof(bitmapInfoHeader{})]byte{}

func cleanLocalWindowsFile(p string) string {
	p = strings.Trim(strings.TrimSpace(p), `"`)
	if p == "" || len(p) > 1024 || strings.HasPrefix(p, `\`) || strings.HasPrefix(p, "//") {
		return ""
	}
	if len(p) < 4 || !((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) || p[1] != ':' || (p[2] != '\\' && p[2] != '/') {
		return ""
	}
	st, err := os.Stat(p)
	if err != nil || st.IsDir() {
		return ""
	}
	return p
}

// helperSubprocessParentName maps common iconless helper/webview subprocesses to their main parent app.
var helperSubprocessParentName = map[string]string{
	"wechatappex":            "WeChat.exe",
	"wechatplayer":           "WeChat.exe",
	"wechatutility":          "WeChat.exe",
	"weixinappex":            "Weixin.exe",
	"steamwebhelper":         "steam.exe",
	"steamservice":           "steam.exe",
	"gameoverlayui":          "steam.exe",
	"msedgewebview2":         "msedge.exe",
	"microsoftedgeupdate":    "msedge.exe",
	"googleupdate":           "chrome.exe",
	"software_reporter_tool": "chrome.exe",
	"epicwebhelper":          "EpicGamesLauncher.exe",
	"unrealcefsubprocess":    "EpicGamesLauncher.exe",
	"git-remote-https":       "git-cmd.exe",
	"git-remote-http":        "git-cmd.exe",
	"git-lfs":                "git-cmd.exe",
}

var windowsSystemHostProcs = map[string]bool{
	"system": true, "registry": true, "memory compression": true,
	"svchost": true, "lsass": true, "services": true, "wininit": true,
	"csrss": true, "smss": true, "spoolsv": true, "dwm": true,
	"sihost": true, "taskhostw": true, "runtimebroker": true,
	"backgroundtaskhost": true, "dllhost": true, "rundll32": true,
	"searchhost": true, "searchindexer": true, "smartscreen": true,
}

var windowsDefenderProcs = map[string]bool{
	"msmpeng": true, "nissrv": true, "securityhealthservice": true,
	"securityhealthsystray": true, "mpcmdrun": true,
}

// findSiblingOrParentIconExe climbs up to 3 ancestor directories when a helper subprocess
// itself lacks an icon (e.g. C:\Program Files\App\bin\helper.exe -> C:\Program Files\App\App.exe).
func findSiblingOrParentIconExe(subExePath string, preferredNames ...string) string {
	dir := filepath.Dir(subExePath)
	for depth := 0; depth < 3 && dir != "" && dir != "." && dir != filepath.Dir(dir); depth++ {
		for _, pn := range preferredNames {
			if cp := cleanLocalWindowsFile(filepath.Join(dir, pn)); cp != "" {
				if extractPEIconDataURI(cp) != "" {
					return cp
				}
			}
		}
		entries, err := os.ReadDir(dir)
		if err == nil && len(entries) <= 64 {
			for _, ent := range entries {
				if ent.IsDir() || !strings.HasSuffix(strings.ToLower(ent.Name()), ".exe") {
					continue
				}
				ln := strings.ToLower(ent.Name())
				if strings.Contains(ln, "unins") || strings.Contains(ln, "crash") || strings.Contains(ln, "helper") || strings.Contains(ln, "update") {
					continue
				}
				cand := filepath.Join(dir, ent.Name())
				if !strings.EqualFold(cand, subExePath) && extractPEIconDataURI(cand) != "" {
					return cand
				}
			}
		}
		dir = filepath.Dir(dir)
	}
	return ""
}

func resolveSystemIconCarrier(stemLower string) string {
	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	if windowsDefenderProcs[stemLower] {
		for _, cand := range []string{
			filepath.Join(sysRoot, "System32", "SecurityHealthSystray.exe"),
			filepath.Join(os.Getenv("ProgramFiles"), "Windows Defender", "MSASCuiL.exe"),
		} {
			if cp := cleanLocalWindowsFile(cand); cp != "" {
				return cp
			}
		}
	}
	if windowsSystemHostProcs[stemLower] {
		for _, cand := range []string{
			filepath.Join(sysRoot, "explorer.exe"),
			filepath.Join(sysRoot, "System32", "imageres.dll"),
		} {
			if cp := cleanLocalWindowsFile(cand); cp != "" {
				return cp
			}
		}
	}
	return ""
}

func resolveProcessByName(procName string) string {
	name := strings.TrimSpace(procName)
	if name == "" || strings.ContainsAny(name, `/\:`) || len(name) > 128 {
		return ""
	}
	lower := strings.ToLower(name)
	stem := strings.TrimSuffix(lower, ".exe")
	if v, ok := procNamePathCache.Load(lower); ok {
		return v.(string)
	}

	if sysCarrier := resolveSystemIconCarrier(stem); sysCarrier != "" {
		storeProcNamePath(lower, sysCarrier)
		return sysCarrier
	}

	if parentExe, isHelper := helperSubprocessParentName[stem]; isHelper {
		if resolved := resolveProcessByName(parentExe); resolved != "" {
			storeProcNamePath(lower, resolved)
			return resolved
		}
	}

	if p, ok := lookupObservedPathByName(lower); ok {
		if cp := cleanLocalWindowsFile(p); cp != "" {
			storeProcNamePath(lower, cp)
			return cp
		}
	}

	sysRoot := os.Getenv("SystemRoot")
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	exeName := name
	if !strings.HasSuffix(lower, ".exe") {
		exeName = name + ".exe"
	}

	// 1. Read-only Registry App Paths (HKCU & HKLM)
	subKey := `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\` + exeName
	for _, root := range []registry.Key{registry.CURRENT_USER, registry.LOCAL_MACHINE} {
		if k, err := registry.OpenKey(root, subKey, registry.QUERY_VALUE); err == nil {
			val, _, verr := k.GetStringValue("")
			k.Close()
			if verr == nil {
				if cp := cleanLocalWindowsFile(val); cp != "" {
					storeProcNamePath(lower, cp)
					return cp
				}
			}
		}
	}

	// 2. Standard user/machine application install paths
	appData := os.Getenv("APPDATA")
	localAppData := os.Getenv("LOCALAPPDATA")
	progFiles := os.Getenv("ProgramFiles")
	progFilesX86 := os.Getenv("ProgramFiles(x86)")

	var knownRel []string
	switch stem {
	case "telegram":
		knownRel = []string{
			filepath.Join(appData, "Telegram Desktop", "Telegram.exe"),
			filepath.Join(localAppData, "Telegram Desktop", "Telegram.exe"),
			filepath.Join(progFiles, "Telegram Desktop", "Telegram.exe"),
		}
	case "chrome":
		knownRel = []string{
			filepath.Join(progFiles, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(progFilesX86, "Google", "Chrome", "Application", "chrome.exe"),
			filepath.Join(localAppData, "Google", "Chrome", "Application", "chrome.exe"),
		}
	case "msedge":
		knownRel = []string{
			filepath.Join(progFilesX86, "Microsoft", "Edge", "Application", "msedge.exe"),
			filepath.Join(progFiles, "Microsoft", "Edge", "Application", "msedge.exe"),
		}
	case "firefox":
		knownRel = []string{
			filepath.Join(progFiles, "Mozilla Firefox", "firefox.exe"),
		}
	case "code":
		knownRel = []string{
			filepath.Join(localAppData, "Programs", "Microsoft VS Code", "Code.exe"),
			filepath.Join(progFiles, "Microsoft VS Code", "Code.exe"),
		}
	case "cursor":
		knownRel = []string{
			filepath.Join(localAppData, "Programs", "cursor", "Cursor.exe"),
		}
	case "discord":
		knownRel = []string{
			filepath.Join(localAppData, "Discord", "Update.exe"),
		}
	case "wechat", "weixin":
		knownRel = []string{
			filepath.Join(progFiles, "Tencent", "WeChat", "WeChat.exe"),
			filepath.Join(progFilesX86, "Tencent", "WeChat", "WeChat.exe"),
			filepath.Join(progFiles, "Tencent", "Weixin", "Weixin.exe"),
		}
	case "qq":
		knownRel = []string{
			filepath.Join(progFiles, "Tencent", "QQNT", "QQ.exe"),
			filepath.Join(progFilesX86, "Tencent", "QQ", "Bin", "QQ.exe"),
		}
	case "steam":
		knownRel = []string{
			filepath.Join(progFilesX86, "Steam", "steam.exe"),
			filepath.Join(progFiles, "Steam", "steam.exe"),
		}
	case "git-cmd", "git":
		knownRel = []string{
			filepath.Join(progFiles, "Git", "git-cmd.exe"),
			filepath.Join(progFiles, "Git", "git-bash.exe"),
		}
	}
	for _, cand := range knownRel {
		if cp := cleanLocalWindowsFile(cand); cp != "" {
			storeProcNamePath(lower, cp)
			return cp
		}
	}

	// 3. System32 / WindowsApps alias
	for _, cand := range []string{
		filepath.Join(localAppData, "Microsoft", "WindowsApps", exeName),
		filepath.Join(sysRoot, "System32", exeName),
		filepath.Join(sysRoot, exeName),
	} {
		if cp := cleanLocalWindowsFile(cand); cp != "" {
			storeProcNamePath(lower, cp)
			return cp
		}
	}
	return ""
}

// extractWin32GDIIconDataURI uses PrivateExtractIconsW (exact embedded icon only),
// only allowing SHGetFileInfoW for WindowsApps MSIX reparse aliases so iconless CLI tools
// never receive Windows' ugly Win95 default white-box .exe placeholder.
func extractWin32GDIIconDataURI(p string, allowShellAlias bool) string {
	wide, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		return ""
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hr, _, _ := procCoInitializeEx.Call(0, coinitApartmentThreaded|coinitDisableOle1DDE)
	if hr == 0 || hr == 1 {
		defer procCoUninitialize.Call()
	}

	var hIcon uintptr
	var iconID uint32
	extracted, _, _ := procPrivateExtractIcons.Call(
		uintptr(unsafe.Pointer(wide)),
		0,
		64,
		64,
		uintptr(unsafe.Pointer(&hIcon)),
		uintptr(unsafe.Pointer(&iconID)),
		1,
		0,
	)
	if (extracted == 0 || extracted == 0xFFFFFFFF || hIcon == 0) && allowShellAlias {
		hIcon = 0
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

	hdc, _, _ := procCreateCompatibleDC.Call(0)
	if hdc == 0 {
		return ""
	}
	defer procDeleteDC.Call(hdc)

	bmi := winBitmapInfo{
		bmiHeader: bitmapInfoHeader{
			biSize:        uint32(unsafe.Sizeof(bitmapInfoHeader{})),
			biWidth:       int32(w),
			biHeight:      -int32(h),
			biPlanes:      1,
			biBitCount:    32,
			biCompression: biRGB,
		},
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
	if err := png.Encode(&buf, downscaleImage64(img)); err != nil || buf.Len() == 0 || buf.Len() > maxIconBytes {
		return ""
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())
}

func extractFromSingleCandidate(p string) string {
	if p == "" {
		return ""
	}
	isWinApps := strings.Contains(strings.ToLower(p), `\windowsapps\`)
	var whiteFallback string
	accept := func(uri string) bool {
		if uri == "" {
			return false
		}
		if isPureWhitePNGDataURI(uri) {
			if whiteFallback == "" {
				whiteFallback = uri
			}
			return false
		}
		return true
	}

	// 1. Direct PE .rsrc embedded icon (exact tray/window .ico embedded in Codex.exe / ChatGPT.exe / desktop apps)
	if uri := extractPEIconDataURI(p); accept(uri) {
		return uri
	}
	// 2. MSIX AppxManifest logo (prefers altform-lightunplated / plated scale-200, skips dark-taskbar white unplated)
	if uri := extractMSIXLogoFromPath(p); accept(uri) {
		return uri
	}
	// 3. Win32 PrivateExtractIconsW (plus SHGetFileInfoW for WindowsApps execution aliases)
	if uri := extractWin32GDIIconDataURI(p, isWinApps); accept(uri) {
		return uri
	}
	return whiteFallback
}

func extractProcessIconDataURI(exePath string, procName string) string {
	p := strings.TrimSpace(exePath)
	if p != "" && (len(p) > 1024 || strings.HasPrefix(p, `\`) || strings.HasPrefix(p, "//")) {
		p = ""
	}
	baseName := strings.TrimSpace(procName)
	if baseName == "" && p != "" {
		baseName = filepath.Base(p)
	}
	stem := strings.TrimSuffix(strings.ToLower(baseName), ".exe")

	cacheKey := strings.ToLower(p)
	if cacheKey == "" && stem != "" {
		cacheKey = "name:" + stem
	}
	if cacheKey == "" {
		return ""
	}
	if cached, ok := procIconCache.Load(cacheKey); ok {
		return cached.(string)
	}

	var uri string
	// System / Defender iconless service hosts -> map to clean modern Windows icon carrier
	if sysCarrier := resolveSystemIconCarrier(stem); sysCarrier != "" {
		uri = extractFromSingleCandidate(sysCarrier)
	}
	// Direct executable icon
	if uri == "" && p != "" {
		uri = extractFromSingleCandidate(p)
	}
	// Helper subprocess fallback -> parent / main application executable
	if uri == "" && stem != "" {
		if parentExe, ok := helperSubprocessParentName[stem]; ok {
			if p != "" {
				if sib := findSiblingOrParentIconExe(p, parentExe); sib != "" {
					uri = extractFromSingleCandidate(sib)
				}
			}
			if uri == "" {
				if resolved := resolveProcessByName(parentExe); resolved != "" {
					uri = extractFromSingleCandidate(resolved)
				}
			}
		} else if p != "" && (strings.Contains(stem, "helper") || strings.Contains(stem, "subprocess") || strings.Contains(stem, "webview")) {
			if sib := findSiblingOrParentIconExe(p); sib != "" {
				uri = extractFromSingleCandidate(sib)
			}
		}
	}
	// Name-only resolution fallback
	if uri == "" && baseName != "" {
		if resolved := resolveProcessByName(baseName); resolved != "" && !strings.EqualFold(resolved, p) {
			uri = extractFromSingleCandidate(resolved)
		}
	}

	if uri != "" && procIconCacheCount.Load() < maxProcIconCacheEntries {
		if _, loaded := procIconCache.LoadOrStore(cacheKey, uri); !loaded {
			procIconCacheCount.Add(1)
		}
		if stem != "" && procIconCacheCount.Load() < maxProcIconCacheEntries {
			aliasKey := "name:" + stem + ".exe"
			if aliasKey != cacheKey {
				if _, loaded := procIconCache.LoadOrStore(aliasKey, uri); !loaded {
					procIconCacheCount.Add(1)
				}
			}
		}
	}
	return uri
}

func procIconCacheLen() uint64 {
	if n := procIconCacheCount.Load(); n > 0 {
		return uint64(n)
	}
	return 0
}

func cachedProcessIconsInto(out map[string]string, total *int, limit int) {
	procIconCache.Range(func(k, v any) bool {
		ks, ok1 := k.(string)
		vs, ok2 := v.(string)
		if !ok1 || !ok2 || vs == "" {
			return true
		}
		var uiKey string
		if strings.HasPrefix(ks, "name:") {
			uiKey = "proc:name:" + strings.TrimPrefix(ks, "name:")
		} else {
			uiKey = "proc:path:" + ks
		}
		if *total+len(uiKey)+len(vs) >= limit {
			return false
		}
		out[uiKey] = vs
		*total += len(uiKey) + len(vs)
		return true
	})
}
