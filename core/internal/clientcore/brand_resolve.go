package clientcore

import (
	"github.com/shui1iao/Kat/internal/kernel"
	"golang.org/x/net/publicsuffix"
	"net"
	"net/netip"
	"strings"
)

// Static alias suffix/domain -> canonical brand root domain for CDN, raw, asset & API domains.
var canonicalBrandSuffixes = []struct {
	suffix string
	brand  string
}{
	// GitHub
	{"githubusercontent.com", "github.com"},
	{"githubassets.com", "github.com"},
	{"github.io", "github.com"},
	{"github.dev", "github.com"},
	{"ghcr.io", "github.com"},
	{"raw.github", "github.com"},
	// Google / YouTube
	{"ytimg.com", "youtube.com"},
	{"googlevideo.com", "youtube.com"},
	{"youtu.be", "youtube.com"},
	{"youtube-nocookie.com", "youtube.com"},
	{"gstatic.com", "google.com"},
	{"googleapis.com", "google.com"},
	{"googleusercontent.com", "google.com"},
	{"1e100.net", "google.com"},
	{"gvt1.com", "google.com"},
	{"gvt2.com", "google.com"},
	{"ggpht.com", "google.com"},
	// Telegram
	{"t.me", "telegram.org"},
	{"tdesktop.com", "telegram.org"},
	{"telesco.pe", "telegram.org"},
	{"telegram-cdn.org", "telegram.org"},
	// OpenAI / ChatGPT / Anthropic
	{"oaistatic.com", "chatgpt.com"},
	{"oaiusercontent.com", "chatgpt.com"},
	{"openai.com", "chatgpt.com"},
	{"claude.ai", "anthropic.com"},
	// X / Twitter
	{"twimg.com", "x.com"},
	{"t.co", "x.com"},
	{"twitter.com", "x.com"},
	// Discord
	{"discordapp.com", "discord.com"},
	{"discordapp.net", "discord.com"},
	{"discord.gg", "discord.com"},
	{"discord.media", "discord.com"},
	// Meta / Facebook / Instagram / WhatsApp
	{"fbcdn.net", "facebook.com"},
	{"fbsbx.com", "facebook.com"},
	{"cdninstagram.com", "instagram.com"},
	{"whatsapp.net", "whatsapp.com"},
	// Apple
	{"mzstatic.com", "apple.com"},
	{"icloud-content.com", "icloud.com"},
	{"aaplimg.com", "apple.com"},
	{"cdn-apple.com", "apple.com"},
	// Microsoft
	{"msftconnecttest.com", "microsoft.com"},
	{"msedge.net", "microsoft.com"},
	{"sfx.ms", "microsoft.com"},
	{"live.com", "microsoft.com"},
	{"office.net", "microsoft.com"},
	{"visualstudio.com", "microsoft.com"},
	// Streaming & Entertainment
	{"nflxvideo.net", "netflix.com"},
	{"nflximg.net", "netflix.com"},
	{"nflxso.net", "netflix.com"},
	{"nflxext.com", "netflix.com"},
	{"scdn.co", "spotify.com"},
	{"spotifycdn.com", "spotify.com"},
	{"ttvnw.net", "twitch.tv"},
	{"jtvnw.net", "twitch.tv"},
	{"steamstatic.com", "steampowered.com"},
	{"steamcontent.com", "steampowered.com"},
	{"steamcommunity.com", "steampowered.com"},
	{"akamaized.net", ""},
	// TikTok / ByteDance
	{"byteoversea.com", "tiktok.com"},
	{"ibytedtos.com", "tiktok.com"},
	{"tiktokcdn.com", "tiktok.com"},
	{"tiktokv.com", "tiktok.com"},
	{"musical.ly", "tiktok.com"},
	{"douyincdn.com", "douyin.com"},
	{"snssdk.com", "douyin.com"},
	{"toutiaoimg.com", "toutiao.com"},
	// Bilibili & Domestic Tech
	{"hdslb.com", "bilibili.com"},
	{"bilivideo.com", "bilibili.com"},
	{"bilivideo.cn", "bilibili.com"},
	{"biliapi.net", "bilibili.com"},
	{"b23.tv", "bilibili.com"},
	{"gtimg.cn", "qq.com"},
	{"gtimg.com", "qq.com"},
	{"qpic.cn", "qq.com"},
	{"qlogo.cn", "qq.com"},
	{"myqcloud.com", "qq.com"},
	{"servicewechat.com", "weixin.qq.com"},
	{"alicdn.com", "taobao.com"},
	{"tbcdn.cn", "taobao.com"},
	{"mmstat.com", "taobao.com"},
	{"360buyimg.com", "jd.com"},
	{"jd.hk", "jd.com"},
	{"bdstatic.com", "baidu.com"},
	{"baidupcs.com", "baidu.com"},
	{"xhscdn.com", "xiaohongshu.com"},
	{"zhimg.com", "zhihu.com"},
	{"sinaimg.cn", "weibo.com"},
	{"126.net", "163.com"},
	{"127.net", "163.com"},
	// Cloudflare & Cloud
	{"cloudflare-dns.com", "cloudflare.com"},
	{"one.one.one.one", "cloudflare.com"},
	{"workers.dev", "cloudflare.com"},
	{"pages.dev", "cloudflare.com"},
	{"redditmedia.com", "reddit.com"},
	{"redd.it", "reddit.com"},
	{"redditstatic.com", "reddit.com"},
	{"pinimg.com", "pinterest.com"},
	{"wikipedia.org", "wikipedia.org"},
	{"wikimedia.org", "wikipedia.org"},
}

// Well-known ASN -> canonical brand domain
var asnBrandMap = map[uint32]string{
	149642: "telegram.org",
	62041:  "telegram.org",
	62014:  "telegram.org",
	59930:  "telegram.org",
	44907:  "telegram.org",
	211157: "telegram.org",
	36459:  "github.com",
	15169:  "google.com",
	396982: "google.com",
	13335:  "cloudflare.com",
	2906:   "netflix.com",
	40027:  "netflix.com",
	32934:  "facebook.com",
	63293:  "facebook.com",
	13414:  "x.com",
	714:    "apple.com",
	6185:   "apple.com",
	8075:   "microsoft.com",
	32590:  "steampowered.com",
	46489:  "twitch.tv",
	16509:  "amazon.com",
	14618:  "amazon.com",
}

var cidrBrandPrefixes []struct {
	prefix netip.Prefix
	brand  string
}

func init() {
	rawCIDRs := []struct {
		cidr  string
		brand string
	}{
		// Telegram Messenger DC IPv4 & IPv6 ranges (connects by raw IP without DNS!)
		{"91.108.4.0/22", "telegram.org"},
		{"91.108.8.0/22", "telegram.org"},
		{"91.108.12.0/22", "telegram.org"},
		{"91.108.16.0/22", "telegram.org"},
		{"91.108.20.0/22", "telegram.org"},
		{"91.108.56.0/22", "telegram.org"},
		{"91.105.192.0/23", "telegram.org"},
		{"149.154.160.0/20", "telegram.org"},
		{"185.76.151.0/24", "telegram.org"},
		{"2001:67c:4e8::/48", "telegram.org"},
		{"2001:b28:f23d::/48", "telegram.org"},
		{"2001:b28:f23f::/48", "telegram.org"},
		{"2001:b28:f23c::/48", "telegram.org"},
		{"2a0a:f280::/32", "telegram.org"},
		// GitHub core blocks
		{"140.82.112.0/20", "github.com"},
		{"192.30.252.0/22", "github.com"},
		{"185.199.108.0/22", "github.com"},
		// Google DNS / Common Anycast
		{"8.8.8.0/24", "google.com"},
		{"8.8.4.0/24", "google.com"},
		{"2001:4860:4860::/48", "google.com"},
		// Cloudflare DNS / Edge
		{"1.1.1.0/24", "cloudflare.com"},
		{"1.0.0.0/24", "cloudflare.com"},
		{"104.16.0.0/12", "cloudflare.com"},
		{"172.64.0.0/13", "cloudflare.com"},
		{"162.158.0.0/15", "cloudflare.com"},
		{"2606:4700::/32", "cloudflare.com"},
		// Domestic Public DNS
		{"223.5.5.0/24", "taobao.com"},
		{"223.6.6.0/24", "taobao.com"},
		{"119.29.29.0/24", "qq.com"},
	}
	for _, item := range rawCIDRs {
		if p, err := netip.ParsePrefix(item.cidr); err == nil {
			cidrBrandPrefixes = append(cidrBrandPrefixes, struct {
				prefix netip.Prefix
				brand  string
			}{p, item.brand})
		}
	}
}

func stripHostPort(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(s, "[]"), "."))
}

func canonicalBrandForDomain(domain string) string {
	d := stripHostPort(domain)
	if d == "" {
		return ""
	}
	for _, entry := range canonicalBrandSuffixes {
		if d == entry.suffix || strings.HasSuffix(d, "."+entry.suffix) {
			if entry.brand != "" {
				return entry.brand
			}
			break
		}
	}
	if strings.Contains(d, "github") && !strings.Contains(d, ".") {
		return "github.com"
	}
	if strings.HasPrefix(d, "raw.github") {
		return "github.com"
	}
	if etld1, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil && etld1 != "" {
		return etld1
	}
	return d
}

// resolveIPToDomain maps a raw IP address to its associated website/service domain:
// 1) Recent observed DNS answers in h.dnsLogs (exact IP resolved for a domain on this machine!)
// 2) Active DNS cache entries in the running kernel
// 3) Known service CIDR blocks (Telegram DCs, GitHub, Cloudflare, Google, etc.)
// 4) Running kernel's MaxMind ASN database (if loaded)
func (h *Host) resolveIPToDomain(ip netip.Addr) string {
	ip = ip.Unmap()
	ipStr := ip.String()

	// 1. Check recent DNS resolution ring (newest first) for an exact real IP match!
	h.dnsLogs.mu.Lock()
	seq, size := h.dnsLogs.seq, h.dnsLogs.size
	var matchedName string
	if size > 0 {
		first := seq - uint64(size) + 1
		for cur := seq; cur >= first; cur-- {
			e := h.dnsLogs.entries[(cur-1)%logCapacity]
			for _, a := range e.Addresses {
				if a == ipStr && e.Name != "" {
					matchedName = e.Name
					break
				}
			}
			if matchedName != "" || cur == first {
				break
			}
		}
	}
	h.dnsLogs.mu.Unlock()
	if matchedName != "" {
		return canonicalBrandForDomain(matchedName)
	}

	// 2. Check live kernel DNS cache & ASN DB
	h.mu.Lock()
	s := h.server
	h.mu.Unlock()
	if s != nil {
		if items, _, err := s.ListDNSCache(); err == nil {
			for _, it := range items {
				for _, a := range it.Addresses {
					if a == ipStr && it.Name != "" {
						return canonicalBrandForDomain(it.Name)
					}
				}
			}
		}
	}

	// 3. Check well-known service CIDR ranges
	for _, item := range cidrBrandPrefixes {
		if item.prefix.Contains(ip) {
			return item.brand
		}
	}

	// 4. Check kernel MaxMind ASN DB if available
	if s != nil {
		if asn := s.LookupIPASN(ip); asn != 0 {
			if brand, ok := asnBrandMap[asn]; ok {
				return brand
			}
		}
	}
	return ""
}

var _ = kernel.Version
