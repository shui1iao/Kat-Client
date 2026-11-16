package clientcore

import (
	"net/netip"
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestPEIconExtractionRealWindowsBinaries(t *testing.T) {
	candidates := []string{
		"/opt/kat-release-20261115-v0216/build/bin/kat-desktop.exe",
		"/opt/kat-release-20261115-v0216/build/Kat-Setup-x64.exe",
	}
	tested := 0
	for _, p := range candidates {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		tested++
		uri := extractPEIconDataURI(p)
		if !strings.HasPrefix(uri, "data:image/png;base64,") || len(uri) < 200 {
			t.Fatalf("failed to extract PE icon from %s: got len=%d", p, len(uri))
		}
	}
	if tested == 0 {
		// Deterministic synthetic DIB fallback check so test stays portable in any isolated environment
		dib := make([]byte, 40+4*4*4+4*4)
		dib[0] = 40 // biSize = 40
		dib[4] = 4  // width = 4
		dib[8] = 8  // height = 4*2
		dib[12] = 1 // planes = 1
		dib[14] = 32 // 32bpp
		for i := 0; i < 16; i++ {
			off := 40 + i*4
			dib[off], dib[off+1], dib[off+2], dib[off+3] = 255, 128, 64, 255
		}
		pngBytes, ok := decodeRTIconBlobToPNG(dib)
		if !ok || len(pngBytes) == 0 {
			t.Fatal("synthetic 32bpp DIB decode failed")
		}
	}
}

func TestIconDomainAndRuleCoverage(t *testing.T) {
	cases := map[string]string{
		"raw.githubusercontent.com":          "github.com",
		"collector.github.com":               "github.com",
		"rr3---sn-i3b7kn7d.googlevideo.com":  "youtube.com",
		"cdn4.telesco.pe":                    "telegram.org",
		"upos-sz-mirrorcos.bilivideo.com":    "bilibili.com",
		"i0.hdslb.com":                       "bilibili.com",
		"p3-pc-sign.douyinpic.com":           "douyin.com",
		"api.openai.com":                     "chatgpt.com",
		"generativelanguage.googleapis.com":  "gemini.google.com",
		"api.some-indie-app.io":              "some-indie-app.io",
		"cdn-2.another-site.org":             "another-site.org",
		"ws-gw.chat-service.net":             "chat-service.net",
		"www.example.com":                    "example.com",
		// Distinct product / self-hosted subdomains MUST preserve their own subdomain!
		"se.siaoz.si":                        "se.siaoz.si",
		"duanju.siaoz.si":                    "duanju.siaoz.si",
		"mail.google.com":                    "mail.google.com",
		"live.bilibili.com":                  "live.bilibili.com",
		// Multi-tenant shared CDNs return "" so IP / Rule hints take over instead of wrong company logo
		"e13678.dscb.akamaiedge.net":         "",
		"d111111abcdef8.cloudfront.net":      "",
	}
	for input, want := range cases {
		got := normalizeIconTargetDomain(input)
		if got != want {
			t.Fatalf("normalizeIconTargetDomain(%q) = %q, want %q", input, got, want)
		}
	}

	if got := resolveRuleHintToBrand("rule_set:Telegram->Proxy"); got != "telegram.org" {
		t.Fatalf("rule hint Telegram -> %q", got)
	}
	if got := resolveRuleHintToBrand("rule_set:Apple->direct"); got != "apple.com" {
		t.Fatalf("rule hint Apple -> %q", got)
	}
	if got := resolveRuleHintToBrand("rule_set:OpenAI->AI"); got != "chatgpt.com" {
		t.Fatalf("rule hint OpenAI -> %q", got)
	}

	var h Host
	if got := h.resolveIPToDomain(netip.MustParseAddr("149.154.167.50")); got != "telegram.org" {
		t.Fatalf("Telegram DC IP -> %q", got)
	}
	if got := h.resolveIPToDomain(netip.MustParseAddr("17.253.144.10")); got != "apple.com" {
		t.Fatalf("Apple 17/8 IP -> %q", got)
	}
}

func TestHTMLIconParserBeyond32Links(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("<html><head>")
	// 60 preload/preconnect links before the real favicon link!
	for i := 0; i < 60; i++ {
		sb.WriteString(`<link rel="preload" href="/chunk.js" as="script">`)
	}
	sb.WriteString(`<link rel="icon" href="/static/brand-64.png">`)
	sb.WriteString(`<link rel="apple-touch-icon" href="//cdn.example.com/touch-180.png">`)
	sb.WriteString("</head><body></body></html>")

	base, _ := url.Parse("https://example.com/")
	urls := extractHTMLIconURLs([]byte(sb.String()), base)
	if len(urls) != 2 || urls[0] != "https://cdn.example.com/touch-180.png" || urls[1] != "https://example.com/static/brand-64.png" {
		t.Fatalf("unexpected extracted icon URLs: %+v", urls)
	}
}


func TestMSIXManifestInlineDataAndDoHIPFeedback(t *testing.T) {
	// 1. MSIX AppxManifest.xml high-DPI scale-200 logo extraction
	tmp := t.TempDir()
	assets := tmp + "/Assets"
	if err := os.MkdirAll(assets, 0755); err != nil {
		t.Fatal(err)
	}
	manifest := `<?xml version="1.0" encoding="utf-8"?><Package><Properties><Logo>Assets\StoreLogo.png</Logo></Properties></Package>`
	if err := os.WriteFile(tmp+"/AppxManifest.xml", []byte(manifest), 0644); err != nil {
		t.Fatal(err)
	}
	// Create a valid 2x2 PNG as Assets/StoreLogo.scale-200.png
	dib := make([]byte, 40+2*2*4+2*4)
	dib[0], dib[4], dib[8], dib[12], dib[14] = 40, 2, 4, 1, 32
	for i := 0; i < 4; i++ {
		dib[40+i*4], dib[40+i*4+1], dib[40+i*4+2], dib[40+i*4+3] = 255, 100, 50, 255
	}
	pngBytes, ok := decodeRTIconBlobToPNG(dib)
	if !ok {
		t.Fatal("failed to encode test PNG")
	}
	if err := os.WriteFile(assets+"/StoreLogo.scale-200.png", pngBytes, 0644); err != nil {
		t.Fatal(err)
	}
	msixURI := extractMSIXLogoFromPath(tmp + "/App/MyStoreApp.exe")
	if !strings.HasPrefix(msixURI, "data:image/png;base64,") {
		t.Fatalf("expected MSIX logo data URI, got %q", msixURI)
	}

	// 2. Inline data:image/svg+xml & manifest extraction in <head>
	htmlDoc := `<html><head>
		<link rel="manifest" href="/manifest.webmanifest">
		<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16'%3E%3Crect width='16' height='16' fill='red'/%3E%3C/svg%3E">
	</head></html>`
	base, _ := url.Parse("https://panel.example.com/")
	headAssets := extractHTMLHeadAssets([]byte(htmlDoc), base)
	if len(headAssets.inlineIcons) != 1 || headAssets.manifestURL != "https://panel.example.com/manifest.webmanifest" {
		t.Fatalf("unexpected headAssets: inline=%d manifest=%q", len(headAssets.inlineIcons), headAssets.manifestURL)
	}

	// 3. Browser built-in DoH SNI <-> DestIP live reverse map
	rememberObservedIPHost("203.0.113.88:443", "i.pximg.net")
	rememberObservedIPHost("203.0.113.89:443", "se.siaoz.si")
	var h Host
	if got := h.resolveIPToDomain(netip.MustParseAddr("203.0.113.88")); got != "pixiv.net" {
		t.Fatalf("DoH CDN IP feedback failed: got %q", got)
	}
	if got := h.resolveIPToDomain(netip.MustParseAddr("203.0.113.89")); got != "se.siaoz.si" {
		t.Fatalf("DoH SNI IP feedback failed: got %q, want pixiv.net", got)
	}
}

func TestMSIXSkipsWhiteUnplatedAndPicksBlackLogo(t *testing.T) {
	makeGlyphPNG := func(fg color.NRGBA) []byte {
		img := image.NewNRGBA(image.Rect(0, 0, 16, 16))
		// Transparent background with 8x8 glyph in center
		for y := 4; y < 12; y++ {
			for x := 4; x < 12; x++ {
				img.SetNRGBA(x, y, fg)
			}
		}
		var b bytes.Buffer
		if err := png.Encode(&b, img); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}

	whiteGlyph := makeGlyphPNG(color.NRGBA{R: 255, G: 255, B: 255, A: 255})
	blackGlyph := makeGlyphPNG(color.NRGBA{R: 18, G: 18, B: 18, A: 255})

	// Subcase A: OpenAI Store package with dark-taskbar white `altform-unplated` AND plated/light `scale-200`
	pkgA := t.TempDir()
	assetsA := pkgA + "/Assets"
	if err := os.MkdirAll(assetsA, 0755); err != nil {
		t.Fatal(err)
	}
	manifest := `<?xml version="1.0" encoding="utf-8"?><Package><Applications><Application><uap:VisualElements Square44x44Logo="Assets\Square44x44Logo.png"/></Application></Applications></Package>`
	_ = os.WriteFile(pkgA+"/AppxManifest.xml", []byte(manifest), 0644)
	_ = os.WriteFile(assetsA+"/Square44x44Logo.targetsize-64_altform-unplated.png", whiteGlyph, 0644)
	_ = os.WriteFile(assetsA+"/Square44x44Logo.scale-200.png", blackGlyph, 0644)

	assertDarkCenter := func(label, uri string) {
		t.Helper()
		if !strings.HasPrefix(uri, "data:image/png;base64,") {
			t.Fatalf("%s: unexpected URI %q", label, uri)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, "data:image/png;base64,"))
		if err != nil {
			t.Fatalf("%s: decode base64: %v", label, err)
		}
		decoded, err := png.Decode(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s: decode png: %v", label, err)
		}
		r16, g16, b16, a16 := decoded.At(8, 8).RGBA()
		if a16 < 0xe000 || r16 > 0x3000 || g16 > 0x3000 || b16 > 0x3000 {
			t.Fatalf("%s: center pixel is not dark black glyph: rgba=(%d,%d,%d,%d)", label, r16>>8, g16>>8, b16>>8, a16>>8)
		}
	}

	gotA := extractMSIXLogoFromPath(pkgA + "/app/Codex.exe")
	assertDarkCenter("SubcaseA", gotA)

	// Subcase B: Even if `scale-200.png` itself is pure white, pixel guard skips it and picks black `StoreLogo.png`
	pkgB := t.TempDir()
	assetsB := pkgB + "/Assets"
	_ = os.MkdirAll(assetsB, 0755)
	manifestB := `<?xml version="1.0" encoding="utf-8"?><Package><Properties><Logo>Assets\StoreLogo.png</Logo></Properties><Applications><Application><uap:VisualElements Square44x44Logo="Assets\Square44x44Logo.png"/></Application></Applications></Package>`
	_ = os.WriteFile(pkgB+"/AppxManifest.xml", []byte(manifestB), 0644)
	_ = os.WriteFile(assetsB+"/Square44x44Logo.scale-200.png", whiteGlyph, 0644)
	_ = os.WriteFile(assetsB+"/StoreLogo.png", blackGlyph, 0644)

	gotB := extractMSIXLogoFromPath(pkgB + "/app/ChatGPT.exe")
	assertDarkCenter("SubcaseB", gotB)

	// Subcase C: Low-alpha RGBA16 256x256 PNG (sa > 0 && sa/cnt == 0) never panics; truncated PNG rejected; sibling prefix traversal blocked
	lowAlpha := image.NewNRGBA64(image.Rect(0, 0, 256, 256))
	lowAlpha.SetNRGBA64(0, 0, color.NRGBA64{R: 65535, G: 65535, B: 65535, A: 1})
	var lowBuf bytes.Buffer
	if err := png.Encode(&lowBuf, lowAlpha); err != nil {
		t.Fatal(err)
	}
	if _, ok := decodeRTIconBlobToPNG(lowBuf.Bytes()); !ok {
		t.Fatal("valid RGBA16 PNG downscale failed")
	}
	if _, ok := decodeRTIconBlobToPNG([]byte("\x89PNG\r\n\x1a\n01234567")); ok {
		t.Fatal("truncated 16-byte PNG accepted")
	}
	parentDir := t.TempDir()
	pkgC := parentDir + "/pkg"
	siblingC := parentDir + "/pkg-private"
	_ = os.MkdirAll(pkgC+"/app", 0755)
	_ = os.MkdirAll(siblingC, 0755)
	_ = os.WriteFile(siblingC+"/secret.png", blackGlyph, 0644)
	_ = os.WriteFile(pkgC+"/AppxManifest.xml", []byte(`<?xml version="1.0"?><Package><Properties><Logo>..\pkg-private\secret.png</Logo></Properties></Package>`), 0644)
	if leaked := extractMSIXLogoFromPath(pkgC + "/app/App.exe"); leaked != "" {
		t.Fatalf("sibling directory prefix bypass returned %q", leaked)
	}
}
