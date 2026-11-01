package sub

import (
	"regexp"
	"strings"
)

// 客户端分流规则集（移植自 polarisx 的 myclash 预设）。
//
// 规则在 clash 语法里定义一次，再分别渲染成 clash YAML 和 sing-box JSON——
// 两份规则手工维护迟早会漂移，出现「clash 走了代理但 sing-box 直连」这种
// 谁也查不出来的问题。
//
// 规则源用的是 MetaCubeX/meta-rules-dat 的 .mrs，sing-box 与 mihomo 都认
// 这个格式，所以同一批 URL 两边通用。

// ruleProvider 是一条远程规则源。
type ruleProvider struct {
	Name     string
	Behavior string // domain / ipcidr
	URL      string
	File     string
}

// ruleGroup 是 clash 里的策略组，sing-box 侧渲染成 selector。
type ruleGroup struct {
	Name    string
	Members []string
}

var presetProviders = []ruleProvider{
	{"private", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/private.mrs", "private.mrs"},
	{"geolocation-cn", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/geolocation-cn.mrs", "geolocation-cn.mrs"},
	{"games_cn", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/category-games@cn.mrs", "games_cn.mrs"},
	{"epicgames", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/epicgames.mrs", "epicgames.mrs"},
	{"nvidia_cn", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/nvidia@cn.mrs", "nvidia_cn.mrs"},
	{"apple_cn", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/apple@cn.mrs", "apple_cn.mrs"},
	{"microsoft_cn", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/microsoft@cn.mrs", "microsoft_cn.mrs"},
	{"cn_additional", "domain", "https://static-file-global.353355.xyz/rules/cn-additional-list.mrs", "cn_additional.mrs"},
	{"cn_ip", "ipcidr", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geoip/cn.mrs", "cn_ip.mrs"},
	{"category-ads", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/category-ads.mrs", "category-ads.mrs"},
	{"googlefcm", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/googlefcm.mrs", "googlefcm.mrs"},
	{"youtube", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/youtube.mrs", "youtube.mrs"},
	{"google", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/google.mrs", "google.mrs"},
	{"google_ip", "ipcidr", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geoip/google.mrs", "google_ip.mrs"},
	{"ai", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/category-ai-!cn.mrs", "ai.mrs"},
	{"github", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/github.mrs", "github.mrs"},
	{"microsoft", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/microsoft.mrs", "microsoft.mrs"},
	{"microsoft_ip", "ipcidr", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geoip/microsoft.mrs", "microsoft_ip.mrs"},
	{"apple", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/apple.mrs", "apple.mrs"},
	{"apple_ip", "ipcidr", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geoip/apple.mrs", "apple_ip.mrs"},
	{"telegram", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/telegram.mrs", "telegram.mrs"},
	{"telegram_ip", "ipcidr", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geoip/telegram.mrs", "telegram_ip.mrs"},
	{"steam", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/steam.mrs", "steam.mrs"},
	{"steam_ip", "ipcidr", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geoip/steam.mrs", "steam_ip.mrs"},
	{"tiktok", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/tiktok.mrs", "tiktok.mrs"},
	{"tiktok_ip", "ipcidr", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geoip/tiktok.mrs", "tiktok_ip.mrs"},
	{"twitter", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/twitter.mrs", "twitter.mrs"},
	{"twitter_ip", "ipcidr", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geoip/twitter.mrs", "twitter_ip.mrs"},
	{"meta", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/meta.mrs", "meta.mrs"},
	{"facebook_ip", "ipcidr", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geoip/facebook.mrs", "facebook_ip.mrs"},
	{"line", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/line.mrs", "line.mrs"},
	{"netflix", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/netflix.mrs", "netflix.mrs"},
	{"netflix_ip", "ipcidr", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geoip/netflix.mrs", "netflix_ip.mrs"},
	{"emby", "domain", "https://cdn.jsdmirror.com/gh/666OS/rules@release/mihomo/domain/Emby.mrs", "emby.mrs"},
	{"emos", "domain", "https://cdn.jsdmirror.com/gh/binaryu/emos-proxy-rule@main/rules/emos-mihomo.mrs", "emos.mrs"},
	{"pikpak", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/pikpak.mrs", "pikpak.mrs"},
	{"spotify", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/spotify.mrs", "spotify.mrs"},
	{"spotify_ip", "ipcidr", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geoip/spotify.mrs", "spotify_ip.mrs"},
	{"cryptocurrency", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/category-cryptocurrency.mrs", "cryptocurrency.mrs"},
	{"paypal", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/paypal.mrs", "paypal.mrs"},
	{"patreon", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/patreon.mrs", "patreon.mrs"},
	{"ehentai", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/ehentai.mrs", "ehentai.mrs"},
	{"geolocation-!cn", "domain", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geosite/geolocation-!cn.mrs", "geolocation-_cn.mrs"},
	{"private_ip", "ipcidr", "https://cdn.jsdmirror.com/gh/appshubcc/bett-rules@meta/geo/geoip/private.mrs", "private_ip.mrs"},
}

var presetGroups = []ruleGroup{
	{"AdBlock", []string{"REJECT", "DIRECT", "PROXY"}},
	{"FCM", []string{"PROXY", "DIRECT"}},
	{"YouTube", []string{"PROXY", "DIRECT"}},
	{"Google", []string{"PROXY", "DIRECT"}},
	{"AI", []string{"PROXY", "DIRECT"}},
	{"GitHub", []string{"PROXY", "DIRECT"}},
	{"Microsoft", []string{"PROXY", "DIRECT"}},
	{"Apple", []string{"PROXY", "DIRECT"}},
	{"Telegram", []string{"PROXY", "DIRECT"}},
	{"Steam", []string{"PROXY", "DIRECT"}},
	{"TikTok", []string{"PROXY", "DIRECT"}},
	{"Twitter", []string{"PROXY", "DIRECT"}},
	{"Meta", []string{"PROXY", "DIRECT"}},
	{"Line", []string{"PROXY", "DIRECT"}},
	{"Netflix", []string{"PROXY", "DIRECT"}},
	{"Emby", []string{"PROXY", "DIRECT"}},
	{"PikPak", []string{"PROXY", "DIRECT"}},
	{"Spotify", []string{"PROXY", "DIRECT"}},
	{"Crypto", []string{"PROXY", "DIRECT"}},
	{"PayPal", []string{"PROXY", "DIRECT"}},
	{"Patreon", []string{"PROXY", "DIRECT"}},
	{"EHentai", []string{"PROXY", "DIRECT"}},
}

// presetRules 是分流规则本体，按顺序匹配。
//
// 原预设里这里有一条 RULE-PORT-PLACEHOLDER，展开出来就是
// "DST-PORT,22,DIRECT"（默认 22）。**刻意去掉**：管理流量直连
// 看着省事，但国内到境外的 SSH 经常又慢又断，穿代理反而稳定——
// 这条规则一加上，上传大文件时特别明显。
var presetRules = []string{
	"DOMAIN,cdn.jsdmirror.com,DIRECT",
	"RULE-SET,private,DIRECT",
	"RULE-SET,geolocation-cn,DIRECT",
	"RULE-SET,games_cn,DIRECT",
	"RULE-SET,epicgames,DIRECT",
	"RULE-SET,nvidia_cn,DIRECT",
	"RULE-SET,apple_cn,DIRECT",
	"RULE-SET,microsoft_cn,DIRECT",
	"DOMAIN,fsend.cn,DIRECT",
	"DOMAIN,international-gfe.download.nvidia.com,DIRECT",
	"DOMAIN-SUFFIX,ctaiot.com,DIRECT",
	"AND,((NETWORK,UDP),(DST-PORT,443),(NOT,((OR,((RULE-SET,cn_additional),(RULE-SET,cn_ip,no-resolve)))))),REJECT",
	"RULE-SET,category-ads,AdBlock",
	"RULE-SET,googlefcm,FCM",
	"RULE-SET,youtube,YouTube",
	"RULE-SET,google,Google",
	"RULE-SET,google_ip,Google,no-resolve",
	"RULE-SET,ai,AI",
	"RULE-SET,github,GitHub",
	"RULE-SET,microsoft,Microsoft",
	"RULE-SET,microsoft_ip,Microsoft,no-resolve",
	"RULE-SET,apple,Apple",
	"RULE-SET,apple_ip,Apple,no-resolve",
	"RULE-SET,telegram,Telegram",
	"RULE-SET,telegram_ip,Telegram,no-resolve",
	"RULE-SET,steam,Steam",
	"RULE-SET,steam_ip,Steam,no-resolve",
	"RULE-SET,tiktok,TikTok",
	"RULE-SET,tiktok_ip,TikTok,no-resolve",
	"RULE-SET,twitter,Twitter",
	"RULE-SET,twitter_ip,Twitter,no-resolve",
	"RULE-SET,meta,Meta",
	"RULE-SET,facebook_ip,Meta,no-resolve",
	"RULE-SET,line,Line",
	"RULE-SET,netflix,Netflix",
	"RULE-SET,netflix_ip,Netflix,no-resolve",
	"RULE-SET,emby,Emby",
	"RULE-SET,emos,Emby",
	"DOMAIN-SUFFIX,mb3admin.com,Emby",
	"DOMAIN-SUFFIX,nubebelle.com,Emby",
	"DOMAIN-KEYWORD,emby,Emby",
	"PROCESS-NAME,com.mb.android,Emby",
	"PROCESS-NAME,tv.emby.embyatv,Emby",
	"PROCESS-NAME,com.hush.yamby,Emby",
	"PROCESS-NAME,com.jellycine.app,Emby",
	"PROCESS-NAME,com.mountains.hills,Emby",
	"PROCESS-NAME,RodelPlayer.App.exe,Emby",
	"PROCESS-NAME,com.feifeiduck.capyplayer,Emby",
	"RULE-SET,pikpak,PikPak",
	"RULE-SET,spotify,Spotify",
	"RULE-SET,spotify_ip,Spotify,no-resolve",
	"RULE-SET,cryptocurrency,Crypto",
	"RULE-SET,paypal,PayPal",
	"RULE-SET,patreon,Patreon",
	"RULE-SET,ehentai,EHentai",
	"RULE-SET,geolocation-!cn,PROXY",
	"RULE-SET,cn_ip,DIRECT",
	"RULE-SET,private_ip,DIRECT",
	"MATCH,PROXY",
}

// ---------------------------------------------------------------- 渲染

// outboundTag 把 clash 的出站名映射成 sing-box 的 tag。
//
// DIRECT/PROXY/REJECT 在 clash 里是内置名，sing-box 侧对应 direct/proxy
// 和一个 reject 动作；策略组名两边保持一致，方便对着看。
func outboundTag(clashName string) (tag string, reject bool) {
	switch clashName {
	case "DIRECT":
		return "direct", false
	case "PROXY":
		return "proxy", false
	case "REJECT":
		return "", true
	}
	return clashName, false
}

// splitRule 把一条 clash 规则拆成字段，去掉 no-resolve 这类修饰。
func splitRule(rule string) []string {
	parts := strings.Split(rule, ",")
	out := parts[:0]
	for _, p := range parts {
		switch p {
		case "no-resolve", "src":
			// 修饰词，不是字段
		default:
			out = append(out, p)
		}
	}
	return out
}

// singboxRuleSets 把规则源渲染成 sing-box 的 rule_set。
//
// 用 remote + format binary：和 clash 的 rule-providers 指向同一批 URL，
// 客户端只下载一份。
func singboxRuleSets() []any {
	sets := make([]any, 0, len(presetProviders))
	for _, pr := range presetProviders {
		sets = append(sets, map[string]any{
			"type": "remote", "tag": pr.Name, "format": "binary",
			"url": pr.URL, "update_interval": "1d",
		})
	}
	return sets
}

// singboxRules 把 clash 规则逐条翻译成 sing-box 路由规则，返回规则列表与
// MATCH 落到的最终出站。
func singboxRules() (rules []any, final string) {
	final = "proxy"
	for _, raw := range presetRules {
		// 这条 QUIC 封禁规则是嵌套写法，机械拆字段拆不动，单独处理：
		// 「UDP 443 且目标不在国内规则集里」→ 拒绝。目的是逼 HTTP/3
		// 回落 TCP，否则 QUIC 走不了代理会漏出去（也可能被 QoS）。
		if strings.HasPrefix(raw, "AND,(") {
			if r := quicBlockRule(raw); r != nil {
				rules = append(rules, r)
			}
			continue
		}
		f := splitRule(raw)
		if len(f) < 2 {
			continue
		}
		kind, value := f[0], f[1]
		if kind == "MATCH" {
			if tag, reject := outboundTag(value); !reject {
				final = tag
			}
			continue
		}
		if len(f) < 3 {
			continue
		}
		tag, reject := outboundTag(f[2])
		rule := map[string]any{}
		switch kind {
		case "IP-CIDR", "IP-CIDR6":
			rule["ip_cidr"] = []string{value}
		case "DOMAIN":
			rule["domain"] = []string{value}
		case "DOMAIN-SUFFIX":
			rule["domain_suffix"] = []string{value}
		case "DOMAIN-KEYWORD":
			rule["domain_keyword"] = []string{value}
		case "RULE-SET":
			rule["rule_set"] = []string{value}
		case "GEOIP":
			// clash 的 GEOIP 库在 sing-box 侧用等价的 rule_set
			rule["rule_set"] = []string{"geoip-" + strings.ToLower(value)}
		case "PROCESS-NAME":
			// 按进程名分流（Emby 这类客户端）。sing-box 有对应字段，
			// 不能丢——丢了会让这些 App 悄悄走到别的出站上。
			rule["process_name"] = []string{value}
		default:
			continue
		}
		if reject {
			rule["action"] = "reject"
		} else {
			rule["outbound"] = tag
		}
		rules = append(rules, rule)
	}
	return rules, final
}

// quicBlockRule 把那条嵌套的 QUIC 封禁规则翻译成 sing-box 写法。
func quicBlockRule(raw string) map[string]any {
	// 从原文里抠出规则集名，避免和字符串里的逗号较劲
	var sets []string
	for _, m := range regexp.MustCompile(`RULE-SET,([A-Za-z0-9_\-!]+)`).FindAllStringSubmatch(raw, -1) {
		sets = append(sets, m[1])
	}
	if len(sets) == 0 {
		return nil
	}
	return map[string]any{
		"network":  "udp",
		"port":     []int{443},
		"rule_set": sets,
		// 原文是 NOT(OR(规则集))，即「不在这些规则集里」才命中
		"invert": true,
		"action": "reject",
	}
}

// singboxRouteRules 组装 sing-box 的完整路由规则。
//
// 前三条是固定动作，顺序不能动：必须先嗅探（否则后面的域名规则匹配不到），
// 再劫持 DNS（否则查询会漏到外面），私有地址直连放在分流之前
// （否则内网访问会被规则集里的条目误判成境外流量）。
func singboxRouteRules() []any {
	rules := []any{
		map[string]any{"action": "sniff"},
		map[string]any{"protocol": "dns", "action": "hijack-dns"},
		map[string]any{"ip_is_private": true, "outbound": "direct"},
	}
	converted, _ := singboxRules()
	return append(rules, converted...)
}

// singboxFinal 是 MATCH 那一条落到的出站。
func singboxFinal() string {
	_, final := singboxRules()
	return final
}

// isPlainKey 判断能不能作为 YAML 裸键。
func isPlainKey(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
