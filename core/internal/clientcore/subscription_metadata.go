package clientcore

import (
	"context"
	"encoding/base64"
	"mime"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type subscriptionHeadersKey struct{}
type subscriptionHeaders struct {
	captured                 bool
	title, disposition       string
	userinfo, updateInterval string
}

func subscriptionName(ctx context.Context, raw string) string {
	clean := func(s string) string {
		s = strings.TrimSpace(s)
		if s == "" || len(s) > 128 || !utf8.ValidString(s) || strings.ContainsFunc(s, unicode.IsControl) {
			return ""
		}
		return s
	}
	if h, ok := ctx.Value(subscriptionHeadersKey{}).(*subscriptionHeaders); ok {
		title := h.title
		if strings.HasPrefix(strings.ToLower(title), "base64:") {
			v := strings.TrimSpace(title[7:])
			for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
				if b, err := e.DecodeString(v); err == nil {
					title = string(b)
					break
				}
			}
		}
		if !strings.HasPrefix(strings.ToLower(h.title), "base64:") {
			for _, e := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
				if b, err := e.DecodeString(title); err == nil && clean(string(b)) != "" {
					title = string(b)
					break
				}
			}
		}
		if s := clean(title); s != "" {
			return s
		}
		if _, p, e := mime.ParseMediaType(h.disposition); e == nil {
			if s := clean(path.Base(p["filename"])); s != "" && s != "." {
				return s
			}
		}
	}
	u, e := url.Parse(raw)
	if e != nil {
		return ""
	}
	if s := clean(path.Base(strings.TrimRight(u.Path, "/"))); s != "" && s != "." && s != "/" {
		return s
	}
	return clean(u.Hostname())
}

// An absent/invalid field stays absent, never an invented zero allowance/date.
type subscriptionUserInfo struct {
	Upload   uint64  `json:"upload"`
	Download uint64  `json:"download"`
	Total    *uint64 `json:"total,omitempty"`
	Expire   *int64  `json:"expire,omitempty"`
}

func parseSubscriptionUserInfo(s string) *subscriptionUserInfo {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	values := map[string]uint64{}
	for _, part := range strings.Split(s, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			return nil
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		if key != "upload" && key != "download" && key != "total" && key != "expire" {
			continue
		}
		if _, ok := values[key]; ok {
			return nil
		}
		v, e := strconv.ParseUint(strings.TrimSpace(kv[1]), 10, 53)
		if e != nil {
			return nil
		}
		values[key] = v
	}
	up, u := values["upload"]
	down, d := values["download"]
	if !u || !d || up+down > 1<<53-1 {
		return nil
	}
	info := &subscriptionUserInfo{Upload: up, Download: down}
	if v, ok := values["total"]; ok && v > 0 {
		info.Total = &v
	}
	if v, ok := values["expire"]; ok && v > 0 {
		n := int64(v)
		info.Expire = &n
	}
	return info
}
func parseSubscriptionInterval(s string) int {
	hours, e := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
	if e != nil || hours == 0 || hours > 720 {
		return 0
	}
	return int(hours) * 3600
}
func captureSubscriptionHeaders(ctx context.Context, header interface{ Get(string) string }) {
	if h, ok := ctx.Value(subscriptionHeadersKey{}).(*subscriptionHeaders); ok && !h.captured {
		h.captured = true
		h.title = header.Get("profile-title")
		h.disposition = header.Get("Content-Disposition")
		h.userinfo = header.Get("subscription-userinfo")
		h.updateInterval = header.Get("profile-update-interval")
	}
}
