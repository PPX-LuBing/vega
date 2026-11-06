package sub

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

// AJSON 生成 Anywhere 的订阅格式。
//
// 为什么需要单独一种格式：Anywhere 是 NodePassProject 官方的 Apple 平台客户端
// （iOS/iPadOS/tvOS/watchOS），它既不认 vector:// 也不认 clash 里的 nowhere。
// vector:// 是**桌面 Vector CLI 的本地运行格式**（带 in=<本地 SOCKS 监听>），
// 手机 App 上没意义，所以之前那份订阅在 Anywhere 里被判「无效」。
//
// 官方文档：https://github.com/NodePassProject/Anywhere/blob/main/Documentations/AJSON.md
// 识别约定：请求带 `X-Anywhere-Format: ajson/1` 时服务端「可以」回 AJSON；
// 客户端则按内容识别——响应体第一个非空白 token 是 `{` 就当 AJSON，
// 这个判断优先于 base64 / Clash / link-list。
//
// 只发 Anywhere 支持的协议（nowhere / vless / hysteria / trojan / anytls /
// shadowsocks）。vmess 和 tuic 它不支持，跳过并如实报出。
//
// 文档里不写 usage：官方约定文档中的 usage 会**逐字段**覆盖响应头
// subscription-userinfo，缺的字段回落到头。不写就完全用头，省得纠结
// expire=0 在两边到底是「不过期」还是「已过期」。
func AJSON(st *store.Store, u store.User) (string, []string, error) {
	eps, skipped, err := Endpoints(st, u)
	if err != nil {
		return "", nil, err
	}
	proxies := make([]any, 0, len(eps))
	seen := map[string]bool{}
	for _, e := range eps {
		proxy, err := ajsonProxy(e)
		if err != nil {
			skipped = append(skipped, fmt.Sprintf("%s: %v", e.Node.Tag, err))
			continue
		}
		id, _ := proxy["id"].(string)
		// id 在文档里必须唯一：重复的 key 会让后面那个代理被静默丢掉。
		// 一个节点配多个接入点（entry_host 逗号分隔）时会走到这里。
		if seen[id] {
			skipped = append(skipped, fmt.Sprintf("%s: 订阅内 id 重复（%s）", e.Node.Tag, id))
			continue
		}
		seen[id] = true
		proxies = append(proxies, proxy)
	}
	if len(proxies) == 0 {
		return "", skipped, fmt.Errorf("该用户没有 Anywhere 支持的节点")
	}
	body, err := json.MarshalIndent(map[string]any{
		"anywhere": 1,
		"name":     st.Setting("sub_title", "Vega"),
		"proxies":  proxies,
	}, "", "  ")
	if err != nil {
		return "", skipped, err
	}
	return string(body) + "\n", skipped, nil
}

// ajsonProxy 把一条节点记录翻译成 AJSON 里的一个代理。
func ajsonProxy(e endpoint) (map[string]any, error) {
	n, u := e.Node, e.User
	if n.EntrySNI != "" {
		n.SNI = n.EntrySNI
	}
	// id 是「稳定身份」的键：同一个 key 每次刷新都得到同一个身份，
	// 服务端改名或调整顺序都不会让客户端丢掉已选中的节点。
	// tag 在机器内唯一，拼上 host 是为了多接入点时也不撞车。
	proxy := map[string]any{
		"id":     n.Tag + "@" + e.Host,
		"name":   e.Name(),
		"server": e.Host,
		"port":   e.Port,
	}

	switch n.Proto {
	case store.ProtoNowhere:
		proxy["protocol"] = "nowhere"
		proxy["key"] = strings.TrimSpace(u.SharedKey)
		// morph 显式写出来：官方默认值是 true，但服务端关掉而客户端默认开着
		// 就会握手失败，靠默认值迟早出事。
		proxy["morph"] = n.Morph
		proxy["network"] = "tcp"
		if n.NowhereClientCarrier() == "quic" {
			proxy["network"] = "udp"
		}
		// AJSON Nowhere uses server for certificate verification. Never replace
		// an entry with its SNI: that could bypass a relay or use the wrong port.
		if n.SNI != "" && !strings.EqualFold(strings.TrimSuffix(n.SNI, "."), strings.TrimSuffix(e.Host, ".")) {
			return nil, fmt.Errorf("Anywhere Nowhere 不支持独立 SNI；接入地址 %s 与 SNI %s 不同，请配置证书匹配的接入域名", e.Host, n.SNI)
		}

	case store.ProtoVLESS:
		proxy["protocol"] = "vless"
		proxy["uuid"] = u.UUID
		if n.TLSMode == "reality" {
			// REALITY 只跑 VLESS over TCP，flow 由服务端用户固定为 vision
			proxy["flow"] = "xtls-rprx-vision"
			proxy["security"] = map[string]any{
				"type": "reality", "sni": n.SNI,
				"publicKey": n.PubKey, "shortId": n.ShortID,
			}
		} else if security := ajsonTLS(n); security != nil {
			proxy["security"] = security
		}
		if transport := ajsonTransport(n); transport != nil {
			proxy["transport"] = transport
		}

	case store.ProtoAnyTLS:
		proxy["protocol"] = "anytls"
		proxy["password"] = u.Password
		if security := ajsonTLS(n); security != nil {
			proxy["security"] = security
		}

	case store.ProtoHysteria2:
		// AJSON 里这个协议叫 hysteria，且 sni 是顶层字段而不是 security
		proxy["protocol"] = "hysteria"
		proxy["password"] = u.Password
		if n.SNI != "" {
			proxy["sni"] = n.SNI
		}
		if n.UpMbps > 0 {
			proxy["upMbps"] = n.UpMbps
		}
		if n.DownMbps > 0 {
			proxy["downMbps"] = n.DownMbps
		}

	case store.ProtoTrojan:
		proxy["protocol"] = "trojan"
		proxy["password"] = u.Password
		if security := ajsonTLS(n); security != nil {
			proxy["security"] = security
		}

	case store.ProtoShadowsocks:
		method := n.SSMethod
		if method == "" {
			method = "2022-blake3-aes-128-gcm"
		}
		password := u.Password
		// SS2022 多用户：客户端密码是「服务端 PSK : 用户 PSK」
		if strings.HasPrefix(method, "2022-") && n.SSPassword != "" {
			password = n.SSPassword + ":" + u.Password
		}
		proxy["protocol"] = "shadowsocks"
		proxy["method"] = method
		proxy["password"] = password

	default:
		// vmess 和 tuic 不在 Anywhere 的协议表里，写进去它只会静默丢掉，
		// 不如在这里明确报出原因。
		return nil, fmt.Errorf("Anywhere 不支持该协议（%s）", n.Proto)
	}
	return proxy, nil
}

// ajsonTLS 生成 tls 安全层；TLSMode 为 none 时返回 nil。
func ajsonTLS(n store.Node) map[string]any {
	if n.TLSMode == "none" {
		return nil
	}
	security := map[string]any{"type": "tls"}
	if n.SNI != "" {
		security["sni"] = n.SNI
	}
	if b64 := echConfigB64(n.ECHConfig); b64 != "" {
		// AJSON 的 security.ech 收裸 base64；写布尔 true 才是「自己去查 DNS 的
		// HTTPS 记录」——我们没有 sslip.io 的 DNS 控制权，所以只能内联。
		security["ech"] = b64
	}
	// AJSON 的 fingerprint 只认 uTLS 的家族名或带版本的名字（chrome_133 等），
	// 面板里存的是 uTLS 原名；只有家族名能直接透传，其余交给默认值，
	// 免得写一个它不认识的值把整个代理判成无效。
	switch family := strings.ToLower(strings.TrimSpace(n.Fingerprint)); family {
	case "chrome", "firefox", "safari", "edge":
		security["fingerprint"] = family
	}
	return security
}

// ajsonTransport 生成 VLESS 的传输层；raw（默认值）返回 nil。
func ajsonTransport(n store.Node) map[string]any {
	transport := map[string]any{}
	switch n.Transport {
	case "ws":
		transport["type"] = "ws"
	case "httpupgrade":
		transport["type"] = "httpupgrade"
	case "grpc":
		transport["type"] = "grpc"
		if n.GRPCService != "" {
			transport["serviceName"] = n.GRPCService
		}
	default:
		return nil
	}
	if n.Path != "" {
		transport["path"] = n.Path
	}
	if n.Host != "" {
		transport["host"] = n.Host
	}
	return transport
}
