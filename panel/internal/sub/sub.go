// Package sub 生成客户端订阅（clash / sing-box）并对外提供 HTTP 服务。
//
// 订阅是「把面板里的节点和用户凭据翻译成客户端能读的配置」。它和内核侧
// 的 buildInbound 是镜像关系：内核往里收，订阅往外发，两边必须对同一份
// 节点数据得出一致的协议参数，否则客户端连不上。
//
// 一个绕不开的约束：**clash/mihomo 内核没有 nowhere 协议**，所以 clash 订阅
// 会跳过它。sing-box 订阅带得动，但需要本仓库的内核（上游没有这个协议，
// 也没有出站实现）。
package sub

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

// endpoint 是一个节点对某个用户呈现出来的连接信息。
type endpoint struct {
	Node store.Node
	User store.User
	// Host 是客户端应当连接的地址（公网），不是内核的 listen。
	Host string
}

// Name 是订阅里这个节点的显示名。
//
// 用「用户可读的中文名」而不是 tag：客户端列表里 tag 看不出是什么，
// 而按国家/机房命名一眼就知道选哪个。备注为空时退回 tag。
func (e endpoint) Name() string {
	if e.Node.Remark != "" {
		return e.Node.Remark
	}
	return e.Node.Tag
}

// SubHost 是订阅里节点地址的来源：优先用节点所在机器的 Host。
//
// 本机节点没有 Host（它就在面板这台机器上），此时必须由 settings 里的
// sub_host 给出公网地址——否则订阅里会写出 0.0.0.0，客户端连不上。
func SubHost(st *store.Store, node store.Node) (string, error) {
	if node.Machine != "" && node.Machine != store.LocalMachine {
		if m, err := st.Machine(node.Machine); err == nil && strings.TrimSpace(m.Host) != "" {
			return strings.TrimSpace(m.Host), nil
		}
	}
	if host := strings.TrimSpace(st.Setting("sub_host", "")); host != "" {
		return host, nil
	}
	return "", fmt.Errorf("节点 %s 在机器 %q 上，但没配 sub_host，订阅里写不出客户端该连的地址",
		node.Tag, node.Machine)
}

// Endpoints 收集某个用户**可用**的节点。
//
// 只发启用的节点、且用户被授权的节点。用户自己被停用/过期/超额时不在这里
// 判断——那是鉴权层的事（见 server.go），因为「订阅拿不到」和「订阅是空的」
// 对客户端是完全不同的信号。
func Endpoints(st *store.Store, u store.User) ([]endpoint, []string, error) {
	tags, err := st.NodesForUser(u.Name)
	if err != nil {
		return nil, nil, err
	}
	granted := make(map[string]bool, len(tags))
	for _, tag := range tags {
		granted[tag] = true
	}

	nodes, err := st.Nodes()
	if err != nil {
		return nil, nil, err
	}
	var (
		out    []endpoint
		skip   []string
		hostOf = map[string]string{}
	)
	for _, n := range nodes {
		if !n.Enabled || !granted[n.Tag] {
			continue
		}
		host, ok := hostOf[n.Machine]
		if !ok {
			host, err = SubHost(st, n)
			if err != nil {
				// 地址缺一个不影响其它节点，但要如实报出来
				skip = append(skip, fmt.Sprintf("%s: %v", n.Tag, err))
				hostOf[n.Machine] = ""
				continue
			}
			hostOf[n.Machine] = host
		}
		if host == "" {
			skip = append(skip, n.Tag+": 该机器的地址解析不到")
			continue
		}
		out = append(out, endpoint{Node: n, User: u, Host: host})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node.Tag < out[j].Node.Tag })
	return out, skip, nil
}

// ---------------------------------------------------------------- clash

// Clash 生成 clash / mihomo 的 YAML 订阅。
//
// nowhere 节点会被跳过：clash 内核没有这个协议，写进去只会让整份订阅
// 解析失败。跳过的节点通过返回值报出，让调用方能提示用户。
func Clash(st *store.Store, u store.User) (string, []string, error) {
	eps, skipped, err := Endpoints(st, u)
	if err != nil {
		return "", nil, err
	}

	var proxies []string
	var names []string
	for _, e := range eps {
		body, ok := clashProxy(e)
		if !ok {
			skipped = append(skipped, e.Node.Tag+"：clash 不支持该协议")
			continue
		}
		proxies = append(proxies, body)
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		return "", skipped, fmt.Errorf("该用户没有任何 clash 能用的节点")
	}

	var b strings.Builder
	b.WriteString("# vega subscription for " + u.Name + "\n")
	b.WriteString("mixed-port: 7890\nallow-lan: false\nmode: rule\nlog-level: info\n")
	b.WriteString("unified-delay: true\ntcp-concurrent: true\n\nproxies:\n")
	for _, p := range proxies {
		b.WriteString(p)
	}
	b.WriteString("\nproxy-groups:\n")
	b.WriteString("  - name: PROXY\n    type: select\n    proxies:\n")
	b.WriteString("      - AUTO\n")
	for _, n := range names {
		b.WriteString("      - " + yamlQuote(n) + "\n")
	}
	b.WriteString("      - DIRECT\n")
	b.WriteString("  - name: AUTO\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n")
	b.WriteString("    interval: 300\n    tolerance: 50\n    proxies:\n")
	for _, n := range names {
		b.WriteString("      - " + yamlQuote(n) + "\n")
	}
	b.WriteString("\nrules:\n")
	b.WriteString("  - GEOIP,private,DIRECT,no-resolve\n")
	b.WriteString("  - GEOIP,cn,DIRECT\n")
	b.WriteString("  - MATCH,PROXY\n")
	return b.String(), skipped, nil
}

// clashProxy 把单个节点渲染成 clash 的 proxy 条目。不支持的协议返回 false。
func clashProxy(e endpoint) (string, bool) {
	n, u := e.Node, e.User
	var b strings.Builder
	line := func(k, v string) {
		b.WriteString("    " + k + ": " + v + "\n")
	}
	head := func(kind string) {
		b.WriteString("  - name: " + yamlQuote(e.Name()) + "\n")
		line("type", kind)
		line("server", e.Host)
		line("port", fmt.Sprint(n.Port))
	}

	switch n.Proto {
	case store.ProtoAnyTLS:
		head("anytls")
		line("password", yamlQuote(u.Password))
		clashForceTLS(&b, n)
		line("udp", "true")

	case store.ProtoHysteria2:
		head("hysteria2")
		line("password", yamlQuote(u.Password))
		clashForceTLS(&b, n)
		if n.UpMbps > 0 {
			line("up", yamlQuote(fmt.Sprintf("%d Mbps", n.UpMbps)))
		}
		if n.DownMbps > 0 {
			line("down", yamlQuote(fmt.Sprintf("%d Mbps", n.DownMbps)))
		}
		line("skip-cert-verify", "false")
		line("udp", "true")

	case store.ProtoVLESS:
		head("vless")
		line("uuid", yamlQuote(u.UUID))
		line("udp", "true")
		if n.TLSMode == "reality" {
			line("tls", "true")
			line("servername", yamlQuote(n.SNI))
			line("client-fingerprint", "chrome")
			b.WriteString("    reality-opts:\n")
			b.WriteString("      public-key: " + yamlQuote(n.PubKey) + "\n")
			b.WriteString("      short-id: " + yamlQuote(n.ShortID) + "\n")
			line("flow", "xtls-rprx-vision")
		} else {
			clashTLS(&b, n)
		}

	case store.ProtoTrojan:
		head("trojan")
		line("password", yamlQuote(u.Password))
		clashTLS(&b, n)
		line("udp", "true")

	case store.ProtoShadowsocks:
		head("ss")
		method := n.SSMethod
		if method == "" {
			method = "2022-blake3-aes-128-gcm"
		}
		line("cipher", yamlQuote(method))
		// SS2022 多用户：客户端口令是「服务端 PSK:用户 PSK」
		pw := u.Password
		if strings.HasPrefix(method, "2022-") && n.SSPassword != "" {
			pw = n.SSPassword + ":" + u.Password
		}
		line("password", yamlQuote(pw))
		line("udp", "true")

	case store.ProtoNowhere:
		return "", false // clash 没有这个协议

	default:
		return "", false
	}
	return b.String(), true
}

// clashForceTLS 给本身就跑 TLS 的协议补字段，不管节点有没有配 tls_mode。
func clashForceTLS(b *strings.Builder, n store.Node) {
	b.WriteString("    tls: true\n")
	if n.SNI != "" {
		b.WriteString("    sni: " + yamlQuote(n.SNI) + "\n")
	}
	b.WriteString("    skip-cert-verify: false\n")
}

// clashTLS 补上 tls / sni / 跳过校验等公共字段。
func clashTLS(b *strings.Builder, n store.Node) {
	if n.TLSMode == "" || n.TLSMode == "none" {
		return
	}
	b.WriteString("    tls: true\n")
	if n.SNI != "" {
		b.WriteString("    sni: " + yamlQuote(n.SNI) + "\n")
	}
	b.WriteString("    skip-cert-verify: false\n")
}

// yamlQuote 给 YAML 标量加双引号。
//
// 节点名里常有中文、emoji、冒号（如 "香港:01"），不加引号 YAML 会解析失败。
func yamlQuote(s string) string {
	encoded, _ := json.Marshal(s)
	return string(encoded)
}

// ---------------------------------------------------------------- sing-box

// Singbox 生成 sing-box 的 JSON 订阅。
//
// 这份订阅**包含 nowhere 节点**，需要本仓库的内核（上游 sing-box 不认识
// 这个协议）。其余节点上游也能用。
func Singbox(st *store.Store, u store.User) (string, []string, error) {
	eps, skipped, err := Endpoints(st, u)
	if err != nil {
		return "", nil, err
	}
	if len(eps) == 0 {
		return "", skipped, fmt.Errorf("该用户没有任何可用节点")
	}

	outbounds := make([]any, 0, len(eps)+2)
	var names []string
	for _, e := range eps {
		ob, ok := singboxOutbound(e)
		if !ok {
			skipped = append(skipped, e.Node.Tag+"：内核暂无该协议的出站实现")
			continue
		}
		outbounds = append(outbounds, ob)
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		return "", skipped, fmt.Errorf("该用户没有任何可用节点")
	}

	selector := map[string]any{
		"type": "selector", "tag": "proxy",
		"outbounds": append(append([]string{}, names...), "direct"),
		"default":   names[0],
	}
	urltest := map[string]any{
		"type": "urltest", "tag": "auto",
		"outbounds":    names,
		"url":          "http://www.gstatic.com/generate_204",
		"interval":     "5m",
		"tolerance":    50,
		"idle_timeout": "30m",
	}
	outbounds = append([]any{selector, urltest}, outbounds...)
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})

	cfg := map[string]any{
		"log":       map[string]any{"level": "info", "timestamp": true},
		"outbounds": outbounds,
		"route": map[string]any{
			"rules": []any{
				map[string]any{"action": "sniff"},
				map[string]any{"protocol": "dns", "action": "hijack-dns"},
				map[string]any{"ip_is_private": true, "outbound": "direct"},
				map[string]any{"rule_set": []string{"geosite-cn", "geoip-cn"}, "outbound": "direct"},
			},
			"final": "proxy",
			// 出站的域名解析走哪个 DNS 必须显式给，否则 1.14 起会告警、
			// 后续版本会直接拒绝加载。
			"default_domain_resolver": "local",
			"rule_set": []any{
				map[string]any{
					"type": "remote", "tag": "geosite-cn", "format": "binary",
					"url":             "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
					"download_detour": "direct", "update_interval": "7d",
				},
				map[string]any{
					"type": "remote", "tag": "geoip-cn", "format": "binary",
					"url":             "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
					"download_detour": "direct", "update_interval": "7d",
				},
			},
		},
		// 国内直连靠规则集。sing-box 不认 clash 的 "geoip:cn" 写法，
		// 必须给出真正的 rule_set 定义，否则加载时报 parse prefix 失败。
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"type": "local", "tag": "local"},
				map[string]any{"type": "udp", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"},
			},
			"rules": []any{
				map[string]any{"ip_is_private": true, "server": "local"},
				map[string]any{"rule_set": []string{"geosite-cn"}, "server": "local"},
			},
			"final": "remote",
		},
		"experimental": map[string]any{
			"cache_file": map[string]any{"enabled": true, "path": "cache.db"},
		},
	}
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", skipped, err
	}
	return string(body), skipped, nil
}

// singboxOutbound 把单个节点渲染成 sing-box 的出站。
func singboxOutbound(e endpoint) (map[string]any, bool) {
	n, u := e.Node, e.User
	ob := map[string]any{
		"tag":         e.Name(),
		"server":      e.Host,
		"server_port": n.Port,
	}

	switch n.Proto {
	case store.ProtoNowhere:
		ob["type"] = "nowhere"
		ob["shared_key"] = u.SharedKey
		ob["morph"] = n.Morph
		// 出站必带 TLS：载体就是 TLS1.3，没给会直接报错
		ob["tls"] = forceTLS(n)

	case store.ProtoAnyTLS:
		ob["type"] = "anytls"
		ob["password"] = u.Password
		// anytls 的名字就来自 "any TLS"，没有 TLS 无从谈起
		ob["tls"] = forceTLS(n)

	case store.ProtoHysteria2:
		ob["type"] = "hysteria2"
		ob["password"] = u.Password
		if n.UpMbps > 0 {
			ob["up_mbps"] = n.UpMbps
		}
		if n.DownMbps > 0 {
			ob["down_mbps"] = n.DownMbps
		}
		// hysteria2 跑在 QUIC 上，TLS 是协议的一部分，不给会报 "TLS required"
		ob["tls"] = forceTLS(n)

	case store.ProtoVLESS:
		ob["type"] = "vless"
		ob["uuid"] = u.UUID
		if n.TLSMode == "reality" {
			ob["tls"] = map[string]any{
				"enabled":     true,
				"server_name": n.SNI,
				"utls":        map[string]any{"enabled": true, "fingerprint": "chrome"},
				"reality":     map[string]any{"enabled": true, "public_key": n.PubKey, "short_id": n.ShortID},
			}
			ob["flow"] = "xtls-rprx-vision"
		} else {
			singboxTLS(ob, n)
		}

	case store.ProtoTrojan:
		ob["type"] = "trojan"
		ob["password"] = u.Password
		singboxTLS(ob, n)

	case store.ProtoShadowsocks:
		ob["type"] = "shadowsocks"
		method := n.SSMethod
		if method == "" {
			method = "2022-blake3-aes-128-gcm"
		}
		ob["method"] = method
		pw := u.Password
		if strings.HasPrefix(method, "2022-") && n.SSPassword != "" {
			pw = n.SSPassword + ":" + u.Password
		}
		ob["password"] = pw

	default:
		return nil, false
	}
	return ob, true
}

// forceTLS 给协议本身就跑在 TLS 上的出站（anytls / hysteria2）生成 tls 块。
// 这类协议不管节点上有没有显式配 tls_mode 都必须给，否则内核直接拒绝加载。
func forceTLS(n store.Node) map[string]any {
	tls := map[string]any{"enabled": true}
	if n.SNI != "" {
		tls["server_name"] = n.SNI
	}
	return tls
}

// singboxTLS 补上 sing-box 的 tls 块。
func singboxTLS(ob map[string]any, n store.Node) {
	if n.TLSMode == "" || n.TLSMode == "none" {
		return
	}
	tls := map[string]any{"enabled": true}
	if n.SNI != "" {
		tls["server_name"] = n.SNI
	}
	ob["tls"] = tls
}
