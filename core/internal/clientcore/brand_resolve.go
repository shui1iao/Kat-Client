package clientcore

import (
	"github.com/shui1iao/Kat/internal/kernel"
	"golang.org/x/net/publicsuffix"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
)

// Static alias suffix/domain -> canonical brand root domain for CDN, raw, asset, API & service domains.
// An empty brand ("") marks a shared multi-tenant CDN whose own corporate logo should NOT be used
// for unrelated customer traffic (allowing IP / Rule-Set hints to identify the real service instead).
var canonicalBrandSuffixes = []struct {
	suffix string
	brand  string
}{
	// Multi-tenant shared CDNs (do not display Akamai/CloudFront/Fastly corporate icon for third-party traffic)
	{"akamaiedge.net", ""},
	{"akamaized.net", ""},
	{"akadns.net", ""},
	{"edgekey.net", ""},
	{"edgesuite.net", ""},
	{"akamaitechnologies.com", ""},
	{"cloudfront.net", ""},
	{"fastly.net", ""},
	{"fastlylb.net", ""},
	{"chinacache.net", ""},
	{"kunluncan.com", ""},
	{"alikunlun.com", ""},
	{"cdngslb.com", ""},
	{"qcloudcdn.com", ""},
	{"dnsv1.com", ""},

	// GitHub & Dev Ecosystems
	{"githubusercontent.com", "github.com"},
	{"githubassets.com", "github.com"},
	{"github.io", "github.com"},
	{"github.dev", "github.com"},
	{"githubcopilot.com", "github.com"},
	{"ghcr.io", "github.com"},
	{"raw.github", "github.com"},
	{"gitlab-static.net", "gitlab.com"},
	{"npmjs.org", "npmjs.com"},
	{"yarnpkg.com", "yarnpkg.com"},
	{"pythonhosted.org", "pypi.org"},
	{"crates.io", "crates.io"},
	{"rust-lang.org", "rust-lang.org"},
	{"golang.org", "go.dev"},
	{"docker.io", "docker.com"},

	// AI & LLM Services
	{"oaistatic.com", "chatgpt.com"},
	{"oaiusercontent.com", "chatgpt.com"},
	{"openai.com", "chatgpt.com"},
	{"chatgpt.com", "chatgpt.com"},
	{"claude.ai", "claude.ai"},
	{"claudeusercontent.com", "claude.ai"},
	{"anthropic.com", "claude.ai"},
	{"generativelanguage.googleapis.com", "gemini.google.com"},
	{"aistudio.google.com", "gemini.google.com"},
	{"makersuite.google.com", "gemini.google.com"},
	{"gemini.google.com", "gemini.google.com"},
	{"perplexity.ai", "perplexity.ai"},
	{"pplx.ai", "perplexity.ai"},
	{"cursor.sh", "cursor.com"},
	{"cursor-cdn.com", "cursor.com"},
	{"cursorapi.com", "cursor.com"},
	{"x.ai", "grok.com"},
	{"grok.com", "grok.com"},
	{"deepseek.com", "deepseek.com"},
	{"huggingface.co", "huggingface.co"},
	{"hf.co", "huggingface.co"},
	{"civitai.com", "civitai.com"},
	{"midjourney.com", "midjourney.com"},
	{"poe.com", "poe.com"},
	{"coze.com", "coze.com"},

	// Google / YouTube / Android
	{"ytimg.com", "youtube.com"},
	{"googlevideo.com", "youtube.com"},
	{"youtu.be", "youtube.com"},
	{"youtube-nocookie.com", "youtube.com"},
	{"youtubei.googleapis.com", "youtube.com"},
	{"yt3.ggpht.com", "youtube.com"},
	{"gstatic.com", "google.com"},
	{"googleapis.com", "google.com"},
	{"googleusercontent.com", "google.com"},
	{"1e100.net", "google.com"},
	{"gvt1.com", "google.com"},
	{"gvt2.com", "google.com"},
	{"gvt3.com", "google.com"},
	{"ggpht.com", "google.com"},
	{"googlezip.net", "google.com"},
	{"pki.goog", "google.com"},
	{"dns.google", "google.com"},
	{"appspot.com", "google.com"},
	{"firebaseio.com", "google.com"},
	{"crashlytics.com", "google.com"},
	{"app-measurement.com", "google.com"},
	{"googlesyndication.com", "google.com"},
	{"googletagmanager.com", "google.com"},
	{"google-analytics.com", "google.com"},
	{"doubleclick.net", "google.com"},
	{"widevine.com", "google.com"},
	{"g.co", "google.com"},

	// Telegram
	{"t.me", "telegram.org"},
	{"tdesktop.com", "telegram.org"},
	{"telesco.pe", "telegram.org"},
	{"telegram-cdn.org", "telegram.org"},
	{"cdn-telegram.org", "telegram.org"},
	{"telegra.ph", "telegram.org"},
	{"graph.org", "telegram.org"},

	// X / Twitter
	{"twimg.com", "x.com"},
	{"t.co", "x.com"},
	{"twitter.com", "x.com"},
	{"pscp.tv", "x.com"},

	// Discord
	{"discordapp.com", "discord.com"},
	{"discordapp.net", "discord.com"},
	{"discord.gg", "discord.com"},
	{"discord.media", "discord.com"},
	{"discordcdn.com", "discord.com"},

	// Meta / Facebook / Instagram / WhatsApp / Threads
	{"fbcdn.net", "facebook.com"},
	{"fbsbx.com", "facebook.com"},
	{"facebook.net", "facebook.com"},
	{"tfbnw.net", "facebook.com"},
	{"m.me", "messenger.com"},
	{"cdninstagram.com", "instagram.com"},
	{"ig.me", "instagram.com"},
	{"threads.net", "threads.net"},
	{"whatsapp.net", "whatsapp.com"},
	{"wa.me", "whatsapp.com"},

	// Apple / iCloud
	{"icloud-content.com", "icloud.com"},
	{"apple-cloudkit.com", "icloud.com"},
	{"mzstatic.com", "apple.com"},
	{"aaplimg.com", "apple.com"},
	{"cdn-apple.com", "apple.com"},
	{"apple-dns.net", "apple.com"},
	{"me.com", "apple.com"},

	// Microsoft / Windows / Office / VS Code / Xbox
	{"vsassets.io", "code.visualstudio.com"},
	{"vscode-cdn.net", "code.visualstudio.com"},
	{"visualstudio.com", "code.visualstudio.com"},
	{"xboxlive.com", "xbox.com"},
	{"gamepass.com", "xbox.com"},
	{"office365.com", "office.com"},
	{"office.net", "office.com"},
	{"msocdn.com", "office.com"},
	{"onedrive.com", "onedrive.live.com"},
	{"1drv.com", "onedrive.live.com"},
	{"sharepoint.com", "sharepoint.com"},
	{"bingapis.com", "bing.com"},
	{"bing.net", "bing.com"},
	{"msftconnecttest.com", "microsoft.com"},
	{"msftncsi.com", "microsoft.com"},
	{"windowsupdate.com", "microsoft.com"},
	{"windows.com", "microsoft.com"},
	{"windows.net", "microsoft.com"},
	{"azureedge.net", "microsoft.com"},
	{"trafficmanager.net", "microsoft.com"},
	{"msecnd.net", "microsoft.com"},
	{"msedge.net", "microsoft.com"},
	{"sfx.ms", "microsoft.com"},
	{"aka.ms", "microsoft.com"},
	{"live.com", "microsoft.com"},
	{"live.net", "microsoft.com"},
	{"msn.com", "microsoft.com"},

	// Games & Storefronts
	{"steamstatic.com", "steampowered.com"},
	{"steamcontent.com", "steampowered.com"},
	{"steamcommunity.com", "steampowered.com"},
	{"steamserver.net", "steampowered.com"},
	{"s.team", "steampowered.com"},
	{"valve.net", "steampowered.com"},
	{"epicgames.dev", "epicgames.com"},
	{"unrealengine.com", "epicgames.com"},
	{"riotcdn.net", "riotgames.com"},
	{"pvp.net", "leagueoflegends.com"},
	{"battlenet.com.cn", "battle.net"},
	{"blzstatic.cn", "battle.net"},
	{"playstation.net", "playstation.com"},
	{"sonyentertainmentnetwork.com", "playstation.com"},
	{"nintendo.net", "nintendo.com"},
	{"hoyoverse.com", "hoyoverse.com"},
	{"mihoyo.com", "mihoyo.com"},
	{"yuanshen.com", "mihoyo.com"},
	{"bhsr.com", "mihoyo.com"},
	{"rbxcdn.com", "roblox.com"},
	{"mojang.com", "minecraft.net"},

	// Streaming, Media & Anime/Community
	{"nflxvideo.net", "netflix.com"},
	{"nflximg.net", "netflix.com"},
	{"nflxso.net", "netflix.com"},
	{"nflxext.com", "netflix.com"},
	{"fast.com", "netflix.com"},
	{"bamgrid.com", "disneyplus.com"},
	{"dssott.com", "disneyplus.com"},
	{"hulustream.com", "hulu.com"},
	{"scdn.co", "spotify.com"},
	{"spotifycdn.com", "spotify.com"},
	{"pscdn.co", "spotify.com"},
	{"sndcdn.com", "soundcloud.com"},
	{"ttvnw.net", "twitch.tv"},
	{"jtvnw.net", "twitch.tv"},
	{"pximg.net", "pixiv.net"},
	{"fanbox.cc", "pixiv.net"},
	{"nimg.jp", "nicovideo.jp"},
	{"bahamut.com.tw", "gamer.com.tw"},
	{"hinet.net", "gamer.com.tw"},
	{"abema.io", "abema.tv"},
	{"dmm.co.jp", "dmm.co.jp"},
	{"javdb.com", "javdb.com"},
	{"jable.tv", "jable.tv"},
	{"missav.ws", "missav.ws"},
	{"missav.com", "missav.ws"},
	{"phncdn.com", "pornhub.com"},
	{"xvideos-cdn.com", "xvideos.com"},

	// TikTok / ByteDance / Feishu
	{"byteoversea.com", "tiktok.com"},
	{"ibytedtos.com", "tiktok.com"},
	{"tiktokcdn.com", "tiktok.com"},
	{"tiktokcdn-us.com", "tiktok.com"},
	{"tiktokv.com", "tiktok.com"},
	{"musical.ly", "tiktok.com"},
	{"douyincdn.com", "douyin.com"},
	{"douyinpic.com", "douyin.com"},
	{"douyinvod.com", "douyin.com"},
	{"snssdk.com", "douyin.com"},
	{"amemv.com", "douyin.com"},
	{"byteimg.com", "douyin.com"},
	{"zijieapi.com", "douyin.com"},
	{"toutiaoimg.com", "toutiao.com"},
	{"feishucdn.com", "feishu.cn"},
	{"larksuite.com", "feishu.cn"},
	{"larkoffice.com", "feishu.cn"},
	{"juejin.cn", "juejin.cn"},
	{"byteacctimg.com", "juejin.cn"},

	// Bilibili & Domestic CN Platforms
	{"hdslb.com", "bilibili.com"},
	{"bilivideo.com", "bilibili.com"},
	{"bilivideo.cn", "bilibili.com"},
	{"biliapi.net", "bilibili.com"},
	{"biliapi.com", "bilibili.com"},
	{"biligame.com", "bilibili.com"},
	{"acgvideo.com", "bilibili.com"},
	{"b23.tv", "bilibili.com"},
	{"servicewechat.com", "weixin.qq.com"},
	{"wechat.com", "weixin.qq.com"},
	{"weixinbridge.com", "weixin.qq.com"},
	{"tenpay.com", "weixin.qq.com"},
	{"gtimg.cn", "qq.com"},
	{"gtimg.com", "qq.com"},
	{"qpic.cn", "qq.com"},
	{"qlogo.cn", "qq.com"},
	{"idqqimg.com", "qq.com"},
	{"myqcloud.com", "qq.com"},
	{"smtcdns.net", "qq.com"},
	{"alicdn.com", "taobao.com"},
	{"tbcdn.cn", "taobao.com"},
	{"mmstat.com", "taobao.com"},
	{"aliapp.org", "taobao.com"},
	{"alibabausercontent.com", "taobao.com"},
	{"tmall.com", "tmall.com"},
	{"alipayobjects.com", "alipay.com"},
	{"aliyuncs.com", "aliyun.com"},
	{"elemecdn.com", "ele.me"},
	{"360buyimg.com", "jd.com"},
	{"jd.hk", "jd.com"},
	{"jcloudcs.com", "jd.com"},
	{"bdstatic.com", "baidu.com"},
	{"baidupcs.com", "baidu.com"},
	{"bdimg.com", "baidu.com"},
	{"bcebos.com", "baidu.com"},
	{"iqiyipic.com", "iqiyi.com"},
	{"71.am", "iqiyi.com"},
	{"ykimg.com", "youku.com"},
	{"xhscdn.com", "xiaohongshu.com"},
	{"xhslink.com", "xiaohongshu.com"},
	{"zhimg.com", "zhihu.com"},
	{"sinaimg.cn", "weibo.com"},
	{"weibocdn.com", "weibo.com"},
	{"weibo.cn", "weibo.com"},
	{"126.net", "163.com"},
	{"127.net", "163.com"},
	{"netease.com", "163.com"},
	{"ydstatic.com", "youdao.com"},
	{"meituan.net", "meituan.com"},
	{"dpfile.com", "dianping.com"},
	{"pddpic.com", "pinduoduo.com"},
	{"yangkeduo.com", "pinduoduo.com"},
	{"yximgs.com", "kuaishou.com"},
	{"kwai.net", "kuaishou.com"},
	{"xiaomi.net", "mi.com"},
	{"mi-img.com", "mi.com"},
	{"miui.com", "mi.com"},
	{"dbankcdn.com", "huawei.com"},
	{"hicloud.com", "huawei.com"},
	{"doubanio.com", "douban.com"},
	{"csdnimg.cn", "csdn.net"},
	{"ngabbs.com", "nga.cn"},
	{"coolapkmarket.com", "coolapk.com"},

	// Cloud, Messaging & Productivity SaaS
	{"cloudflare-dns.com", "cloudflare.com"},
	{"cloudflareclient.com", "cloudflare.com"},
	{"cloudflareinsights.com", "cloudflare.com"},
	{"one.one.one.one", "cloudflare.com"},
	{"workers.dev", "cloudflare.com"},
	{"pages.dev", "cloudflare.com"},
	{"r2.dev", "cloudflare.com"},
	{"amazonaws.com", "aws.amazon.com"},
	{"awsstatic.com", "aws.amazon.com"},
	{"vercel.app", "vercel.com"},
	{"vercel-dns.com", "vercel.com"},
	{"netlify.app", "netlify.com"},
	{"supabase.co", "supabase.com"},
	{"notion-static.com", "notion.so"},
	{"slack-edge.com", "slack.com"},
	{"dropboxusercontent.com", "dropbox.com"},
	{"dropboxstatic.com", "dropbox.com"},
	{"paypalobjects.com", "paypal.com"},
	{"stripe.network", "stripe.com"},
	{"line-scdn.net", "line.me"},
	{"line-apps.com", "line.me"},
	{"sc-cdn.net", "snapchat.com"},
	{"redditmedia.com", "reddit.com"},
	{"redd.it", "reddit.com"},
	{"redditstatic.com", "reddit.com"},
	{"pinimg.com", "pinterest.com"},
	{"wikimedia.org", "wikipedia.org"},
	{"tailscale.io", "tailscale.com"},
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
	8068:   "microsoft.com",
	32590:  "steampowered.com",
	46489:  "twitch.tv",
	16509:  "amazon.com",
	14618:  "amazon.com",
	396986: "tiktok.com",
	138699: "bilibili.com",
	45090:  "qq.com",
	132203: "qq.com",
	37963:  "taobao.com",
}

// Rule / Rule-Set keyword -> canonical brand domain (used when target is raw IP or multi-tenant CDN)
var ruleKeywordBrands = []struct {
	kw    string
	brand string
}{
	{"telegram", "telegram.org"},
	{"youtube", "youtube.com"},
	{"openai", "chatgpt.com"},
	{"chatgpt", "chatgpt.com"},
	{"claude", "claude.ai"},
	{"anthropic", "claude.ai"},
	{"gemini", "gemini.google.com"},
	{"copilot", "github.com"},
	{"perplexity", "perplexity.ai"},
	{"github", "github.com"},
	{"google", "google.com"},
	{"netflix", "netflix.com"},
	{"disney", "disneyplus.com"},
	{"spotify", "spotify.com"},
	{"tiktok", "tiktok.com"},
	{"douyin", "douyin.com"},
	{"bilibili", "bilibili.com"},
	{"bahamut", "gamer.com.tw"},
	{"pixiv", "pixiv.net"},
	{"twitter", "x.com"},
	{"discord", "discord.com"},
	{"whatsapp", "whatsapp.com"},
	{"instagram", "instagram.com"},
	{"facebook", "facebook.com"},
	{"onedrive", "onedrive.live.com"},
	{"microsoft", "microsoft.com"},
	{"icloud", "icloud.com"},
	{"apple", "apple.com"},
	{"steam", "steampowered.com"},
	{"epic", "epicgames.com"},
	{"twitch", "twitch.tv"},
	{"reddit", "reddit.com"},
	{"wikipedia", "wikipedia.org"},
	{"paypal", "paypal.com"},
	{"cloudflare", "cloudflare.com"},
	{"wechat", "weixin.qq.com"},
}

var infraSubdomainExact = map[string]bool{
	"api": true, "apis": true, "cdn": true, "static": true, "assets": true, "asset": true,
	"img": true, "imgs": true, "image": true, "images": true, "pic": true, "pics": true,
	"media": true, "video": true, "videos": true, "audio": true, "stream": true, "vod": true,
	"ws": true, "wss": true, "mqtt": true, "gateway": true, "gw": true, "edge": true,
	"collector": true, "telemetry": true, "metrics": true, "log": true, "logs": true,
	"stat": true, "stats": true, "track": true, "tracker": true, "beacon": true, "sentry": true,
	"push": true, "notify": true, "notification": true, "auth": true, "sso": true, "login": true,
	"passport": true, "account": true, "accounts": true, "id": true, "oauth": true,
	"update": true, "updates": true, "dl": true, "download": true, "downloads": true,
	"files": true, "storage": true, "s3": true, "oss": true, "cos": true, "upos": true,
	"dns": true, "doh": true, "dot": true, "ntp": true, "stun": true, "turn": true,
	"ipv4": true, "ipv6": true, "dualstack": true, "prod": true, " rpc": true, "grpc": true,
	"sdk": true, "client": true, "clients": true, "config": true, "conf": true, "ab": true,
}

var infraSubdomainPrefixes = []string{
	"api-", "api.", "cdn-", "cdn0", "cdn1", "cdn2", "cdn3", "cdn4",
	"static-", "img-", "img0", "img1", "img2", "img3", "pic-", "media-",
	"ws-", "gw-", "edge-", "node-", "prod-", "rr1---", "rr2---", "rr3---", "rr4---", "rr5---",
	"p1-", "p2-", "p3-", "p6-", "p9-", "v1-", "v2-", "v3-", "s1.", "s2.", "s3.",
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
		// Apple 17.0.0.0/8
		{"17.0.0.0/8", "apple.com"},
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
		{"180.76.76.0/24", "baidu.com"},
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

func isMultiTenantCDN(domain string) bool {
	d := stripHostPort(domain)
	for _, entry := range canonicalBrandSuffixes {
		if d == entry.suffix || strings.HasSuffix(d, "."+entry.suffix) {
			return entry.brand == ""
		}
	}
	return false
}

// canonicalBrandForDomain returns an explicit brand override if known, or eTLD+1 otherwise.
func canonicalBrandForDomain(domain string) string {
	d := stripHostPort(domain)
	if d == "" {
		return ""
	}
	for _, entry := range canonicalBrandSuffixes {
		if d == entry.suffix || strings.HasSuffix(d, "."+entry.suffix) {
			return entry.brand // "" if multi-tenant CDN!
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

// normalizeIconTargetDomain chooses the ideal domain to cache & query for an icon:
// - Explicit brand aliases (e.g. raw.githubusercontent.com -> github.com, googlevideo.com -> youtube.com) collapse immediately;
// - Technical/API/CDN subdomains (e.g. api.foo.com, cdn2.bar.io, ws-gw.baz.net) collapse to foo.com / bar.io / baz.net;
// - Distinct product/user subdomains (e.g. se.siaoz.si, mail.google.com, live.bilibili.com) keep their own domain first!
func normalizeIconTargetDomain(raw string) string {
	d := stripHostPort(raw)
	if d == "" {
		return ""
	}
	for _, entry := range canonicalBrandSuffixes {
		if d == entry.suffix || strings.HasSuffix(d, "."+entry.suffix) {
			return entry.brand // "" for multi-tenant CDN, or canonical brand domain
		}
	}
	if strings.HasPrefix(d, "raw.github") || (strings.Contains(d, "github") && !strings.Contains(d, ".")) {
		return "github.com"
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil || etld1 == "" || d == etld1 {
		return d
	}
	if d == "www."+etld1 {
		return etld1
	}
	sub := strings.TrimSuffix(d, "."+etld1)
	firstLabel := sub
	if idx := strings.IndexByte(sub, '.'); idx > 0 {
		firstLabel = sub[:idx]
	}
	if infraSubdomainExact[firstLabel] || strings.Contains(sub, ".") {
		// Deep multi-level subdomains (a.b.example.com) or known infra prefixes (api.example.com) -> etld1
		for _, pref := range infraSubdomainPrefixes {
			if strings.HasPrefix(sub, pref) {
				return etld1
			}
		}
		if infraSubdomainExact[firstLabel] {
			return etld1
		}
		// Multi-level subdomains like edge-01.us-east.prod.example.com -> etld1
		if strings.Count(sub, ".") >= 1 {
			return etld1
		}
	}
	for _, pref := range infraSubdomainPrefixes {
		if strings.HasPrefix(firstLabel, pref) {
			return etld1
		}
	}
	return d
}

func resolveRuleHintToBrand(rule string) string {
	r := strings.ToLower(strings.TrimSpace(rule))
	if r == "" || strings.HasPrefix(r, "final") || strings.HasPrefix(r, "match") {
		return ""
	}
	// Strip outbound suffix ("rule_set:Telegram->Proxy" -> "rule_set:telegram")
	if idx := strings.Index(r, "->"); idx > 0 {
		r = r[:idx]
	}
	for _, item := range ruleKeywordBrands {
		if strings.Contains(r, item.kw) {
			return item.brand
		}
	}
	return ""
}

// resolveIPToDomain maps a raw IP address to its associated website/service domain:
// 1) Recent observed DNS answers in h.dnsLogs (exact IP resolved for a domain on this machine)
// 2) Active DNS cache entries in the running kernel
// 3) Known service CIDR blocks (Telegram DCs, Apple, GitHub, Cloudflare, Google, etc.)
// 4) Running kernel's MaxMind ASN database (if loaded)
var (
	observedIPHosts      sync.Map
	observedIPHostsCount atomic.Int32
)

// rememberObservedIPHost records a live mapping from a public DestIP to its sniffed/observed
// domain (supporting Chrome/Edge built-in DoH where DNS bypasses the system resolver).
func rememberObservedIPHost(rawIP, rawHost string) {
	hStr := stripHostPort(rawHost)
	if hStr == "" || !strings.Contains(hStr, ".") {
		return
	}
	if _, err := netip.ParseAddr(hStr); err == nil {
		return
	}
	ip, err := netip.ParseAddr(stripHostPort(rawIP))
	if err != nil {
		return
	}
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return
	}
	norm := normalizeIconTargetDomain(hStr)
	if norm == "" {
		return
	}
	if observedIPHostsCount.Load() >= 4096 {
		observedIPHosts.Clear()
		observedIPHostsCount.Store(0)
	}
	if _, loaded := observedIPHosts.LoadOrStore(ip.String(), norm); !loaded {
		observedIPHostsCount.Add(1)
	} else {
		observedIPHosts.Store(ip.String(), norm)
	}
}

func (h *Host) resolveIPToDomain(ip netip.Addr) string {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return ""
	}
	ipStr := ip.String()

	// 0. Check observed SNI/Host <-> DestIP map (captures browser built-in encrypted DoH!)
	if v, ok := observedIPHosts.Load(ipStr); ok {
		if dom, ok2 := v.(string); ok2 && dom != "" {
			return dom
		}
	}

	// 1. Check recent DNS resolution ring (newest first) for an exact real IP match
	h.dnsLogs.mu.Lock()
	seq, size := h.dnsLogs.seq, h.dnsLogs.size
	var matchedName string
	if size > 0 {
		first := seq - uint64(size) + 1
		for cur := seq; cur >= first; cur-- {
			e := h.dnsLogs.entries[(cur-1)%logCapacity]
			for _, a := range e.Addresses {
				if a == ipStr && e.Name != "" {
					cand := normalizeIconTargetDomain(e.Name)
					if cand != "" {
						matchedName = cand
						break
					}
				}
			}
			if matchedName != "" || cur == first {
				break
			}
		}
	}
	h.dnsLogs.mu.Unlock()
	if matchedName != "" {
		return matchedName
	}

	// 2. Check live kernel DNS cache
	h.mu.Lock()
	s := h.server
	h.mu.Unlock()
	if s != nil {
		if items, _, err := s.ListDNSCache(); err == nil {
			for _, it := range items {
				for _, a := range it.Addresses {
					if a == ipStr && it.Name != "" {
						if cand := normalizeIconTargetDomain(it.Name); cand != "" {
							return cand
						}
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
