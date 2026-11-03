// Package logsafe bounds locally displayed diagnostic text. It never persists
// raw errors or changes the structured logs.get allowlist.
package logsafe

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

var urls = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s<>"']+`)
var secrets = regexp.MustCompile(`(?i)(["']?(?:[a-z0-9_-]*(?:token|password|passwd|secret|credential|api[_-]?key|authorization|cookie)[a-z0-9_-]*|username|userinfo|key)["']?\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}&]+)`)
var bearer = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[a-z0-9+/=_\-.]+`)

func Text(s string) string {
	s = urls.ReplaceAllStringFunc(s, func(raw string) string {
		u, e := url.Parse(raw)
		if e != nil {
			return "[invalid URL]"
		}
		u.User = nil
		u.RawQuery = ""
		u.ForceQuery = false
		u.Fragment = ""
		return u.String()
	})
	s = bearer.ReplaceAllString(s, "${1} [redacted]")
	s = secrets.ReplaceAllString(s, "${1}[redacted]")
	s = strings.Map(func(r rune) rune {
		if r < 32 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
	if len(s) > 1024 {
		s = s[:1024]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}
