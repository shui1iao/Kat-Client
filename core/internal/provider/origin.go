package provider

import (
	"net/url"
	"strings"
)

// SameOrigin compares request origins, never paths, suffixes or DNS answers.
func SameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil || a.Hostname() == "" || !strings.EqualFold(a.Scheme, b.Scheme) || !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}
	port := func(u *url.URL) string {
		if p := u.Port(); p != "" {
			return p
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return port(a) == port(b)
}
