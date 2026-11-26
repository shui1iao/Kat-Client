//go:build !windows

package clientcore

import "strings"

func extractProcessIconDataURI(exePath string, _ string) string {
	p := strings.TrimSpace(exePath)
	if p == "" || len(p) > 1024 {
		return ""
	}
	if uri := extractPEIconDataURI(p); uri != "" {
		return uri
	}
	return extractMSIXLogoFromPath(p)
}

func procIconCacheLen() uint64 { return 0 }

func cachedProcessIconsInto(_ map[string]string, _ *int, _ int) {}
