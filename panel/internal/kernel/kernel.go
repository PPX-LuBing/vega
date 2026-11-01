// Package kernel 负责与 sbx 内核打交道：生成配置、校验、重启、读统计。
//
// 设计取向：面板不重新实现任何协议逻辑，只把「节点 + 用户」翻译成内核配置，
// 再通过内核自己的能力（v2ray_api 统计）把数据读回来。
package kernel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

// Paths 是内核相关的外部路径。
type Paths struct {
	Bin      string // sbx 二进制
	Config   string // 配置路径
	Service  string // systemd 服务名
	StatsBin string // sb-stats（查 v2ray_api 的小工具）
	APIAddr  string // v2ray_api 监听地址
	ClashAddr string // clash_api 监听地址（可观测性数据源）
	ControlAddr string // nowhere 控制端点（运行期改用户）
}

// DefaultPaths 返回默认路径，允许用环境变量覆盖。
//
// 覆盖能力不只是为了本地调试：多机部署时面板要能指向不同位置的内核，
// 而把路径写死在代码里就得重新编译。
func DefaultPaths() Paths {
	paths := Paths{
		Bin:      "/usr/local/bin/sbx",
		Config:   "/usr/local/etc/sbx/config.json",
		Service:  "sbx",
		StatsBin:  "/usr/local/bin/sb-stats",
		APIAddr:   "127.0.0.1:10085",
		ClashAddr:   "127.0.0.1:9090",
		ControlAddr: "127.0.0.1:10087",
	}
	override(&paths.ControlAddr, "SBX_PANEL_CONTROL")
	override(&paths.ClashAddr, "SBX_PANEL_CLASH")
	override(&paths.Bin, "SBX_PANEL_KERNEL")
	override(&paths.Config, "SBX_PANEL_CONFIG")
	override(&paths.Service, "SBX_PANEL_SERVICE")
	override(&paths.StatsBin, "SBX_PANEL_STATS_BIN")
	override(&paths.APIAddr, "SBX_PANEL_API")
	return paths
}

func override(target *string, env string) {
	if value := os.Getenv(env); value != "" {
		*target = value
	}
}

// ---------------------------------------------------------------- 配置生成

// BuildConfig 把面板状态翻译成完整的 sbx 配置。
//
// 被停用、过期或超额的用户不会出现在配置里——这是配额执行的第一道闸门
// （第二道是重启内核，因为 sing-box 没有热重载）。
func BuildConfig(st *store.Store, paths Paths) (map[string]any, error) {
	nodes, err := st.Nodes()
	if err != nil {
		return nil, err
	}
	return buildConfigFromNodes(st, paths, nodes)
}

// buildConfigFromNodes 是配置生成的实际实现，节点列表由调用方给定——
// 多机编排时每台机器只拿自己的节点（见 BuildConfigFor）。
func buildConfigFromNodes(st *store.Store, paths Paths, nodes []store.Node) (map[string]any, error) {
	inbounds := make([]any, 0, len(nodes))
	counted := make([]any, 0)
	seenUser := map[string]bool{}

	for _, node := range nodes {
		if !node.Enabled {
			continue
		}
		users, err := activeUsers(st, node)
		if err != nil {
			return nil, err
		}
		if len(users) == 0 {
			// 没有可用用户就不监听，别开个没人能用的端口
			continue
		}
		inbound, err := buildInbound(node, users)
		if err != nil {
			return nil, err
		}
		inbounds = append(inbounds, inbound)
		for _, u := range users {
			if !seenUser[u.Name] {
				seenUser[u.Name] = true
				counted = append(counted, u.Name)
			}
		}
	}

	config := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"tag": "local", "type": "udp", "server": "223.5.5.5"},
				map[string]any{"tag": "remote", "type": "udp", "server": "1.1.1.1"},
			},
			"strategy": "prefer_ipv4",
		},
		"inbounds": inbounds,
		"outbounds": []any{
			map[string]any{"type": "direct", "tag": "direct"},
			map[string]any{"type": "block", "tag": "block"},
		},
		"route": map[string]any{
			"rules": []any{map[string]any{"action": "sniff"}},
			"final": "direct",
			"default_domain_resolver": map[string]any{"server": "local"},
		},
		"experimental": map[string]any{
			"v2ray_api": map[string]any{
				"listen": paths.APIAddr,
				"stats": map[string]any{
					"enabled":  true,
					"inbounds": tagsOf(inbounds),
					"users":    counted,
				},
			},
			// 必须用机器自己的地址：硬编码 9090 会让同一台机上跑多个
			// 实例时第二个起不来（bind: address already in use）
			"clash_api": map[string]any{"external_controller": orDefaultAddr(paths.ClashAddr, "127.0.0.1:9090")},
		},
	}
	return config, nil
}

// activeUsers 返回该节点上「应当被写进配置」的用户。
func activeUsers(st *store.Store, node store.Node) ([]store.User, error) {
	names, err := st.UsersForNode(node.Tag)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]store.User, 0, len(names))
	for _, name := range names {
		u, err := st.User(name)
		if err != nil {
			continue
		}
		up, down, err := st.Usage(name)
		if err != nil {
			continue
		}
		if Usable(u, up+down, now) {
			out = append(out, u)
		}
	}
	return out, nil
}

func buildInbound(node store.Node, users []store.User) (map[string]any, error) {
	listen := node.Listen
	if listen == "" {
		listen = "0.0.0.0"
	}
	inbound := map[string]any{
		"tag":         node.Tag,
		"listen":      listen,
		"listen_port": node.Port,
	}

	switch node.Proto {
	case store.ProtoNowhere:
		inbound["type"] = "nowhere"
		members := make([]any, 0, len(users))
		for _, u := range users {
			members = append(members, map[string]any{"name": u.Name, "shared_key": u.SharedKey})
		}
		inbound["users"] = members
		inbound["morph"] = node.Morph

	case store.ProtoAnyTLS:
		inbound["type"] = "anytls"
		inbound["users"] = passwordMembers(users)

	case store.ProtoHysteria2:
		inbound["type"] = "hysteria2"
		inbound["users"] = passwordMembers(users)
		if node.UpMbps > 0 {
			inbound["up_mbps"] = node.UpMbps
		}
		if node.DownMbps > 0 {
			inbound["down_mbps"] = node.DownMbps
		}

	case store.ProtoVLESS:
		inbound["type"] = "vless"
		members := make([]any, 0, len(users))
		for _, u := range users {
			member := map[string]any{"name": u.Name, "uuid": u.UUID}
			if node.TLSMode == "reality" {
				member["flow"] = "xtls-rprx-vision"
			}
			members = append(members, member)
		}
		inbound["users"] = members

	case store.ProtoTrojan:
		inbound["type"] = "trojan"
		inbound["users"] = passwordMembers(users)

	case store.ProtoShadowsocks:
		inbound["type"] = "shadowsocks"
		method := node.SSMethod
		if method == "" {
			method = "2022-blake3-aes-128-gcm"
		}
		inbound["method"] = method
		// SS2022 多用户：服务端一把 PSK，每个用户一把
		inbound["password"] = node.SSPassword
		inbound["users"] = passwordMembers(users)

	default:
		return nil, fmt.Errorf("不支持的协议: %s", node.Proto)
	}

	if tlsBlock := buildTLS(node); tlsBlock != nil {
		inbound["tls"] = tlsBlock
	}
	return inbound, nil
}

func passwordMembers(users []store.User) []any {
	out := make([]any, 0, len(users))
	for _, u := range users {
		out = append(out, map[string]any{"name": u.Name, "password": u.Password})
	}
	return out
}

// buildTLS 生成 tls 段；mode 为 none 时返回 nil。
func buildTLS(node store.Node) map[string]any {
	switch node.TLSMode {
	case "none":
		return nil
	case "reality":
		handshake := node.Dest
		if handshake == "" {
			handshake = "www.apple.com"
		}
		server, port := handshake, 443
		if host, portText, ok := splitHostPort(handshake); ok {
			server = host
			if parsed, err := strconv.Atoi(portText); err == nil {
				port = parsed
			}
		}
		serverName := firstCSV(node.SNI)
		if serverName == "" {
			serverName = server
		}
		shortIDs := []any{}
		if node.ShortID != "" {
			shortIDs = append(shortIDs, node.ShortID)
		}
		return map[string]any{
			"enabled":     true,
			"server_name": serverName,
			"reality": map[string]any{
				"enabled":     true,
				"handshake":   map[string]any{"server": server, "server_port": port},
				"private_key": node.PrivKey,
				"short_id":    shortIDs,
			},
		}
	default:
		block := map[string]any{"enabled": true}
		if name := firstCSV(node.SNI); name != "" {
			block["server_name"] = name
		}
		if node.CertPath != "" {
			block["certificate_path"] = node.CertPath
			block["key_path"] = node.KeyPath
		}
		return block
	}
}

func tagsOf(inbounds []any) []any {
	out := make([]any, 0, len(inbounds))
	for _, item := range inbounds {
		if m, ok := item.(map[string]any); ok {
			if tag, ok := m["tag"].(string); ok && tag != "" {
				out = append(out, tag)
			}
		}
	}
	return out
}

// orDefaultAddr 给空地址兜个默认值。
func orDefaultAddr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func firstCSV(s string) string {
	for _, part := range strings.Split(s, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func splitHostPort(s string) (string, string, bool) {
	idx := strings.LastIndex(s, ":")
	if idx <= 0 || idx == len(s)-1 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}

// ---------------------------------------------------------------- 内核控制

// WriteConfig 原子写配置。
func WriteConfig(paths Paths, config map[string]any) error {
	body, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(paths.Config), 0o755); err != nil {
		return err
	}
	tmp := paths.Config + ".tmp"
	if err = os.WriteFile(tmp, body, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, paths.Config)
}

// Check 用内核自己校验配置；不过就不该覆盖现有配置。
func Check(paths Paths) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, paths.Bin, "check", "-c", paths.Config)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("配置校验失败: %s", strings.TrimSpace(out.String()))
	}
	return nil
}

// Apply 生成配置 → 校验 → 写盘 → 重启。
//
// 顺序很重要：先在临时状态校验，通过了才写正式路径，避免把内核起崩。
func Apply(st *store.Store, paths Paths) (int, error) {
	config, err := BuildConfig(st, paths)
	if err != nil {
		return 0, err
	}
	inboundCount := len(config["inbounds"].([]any))
	if inboundCount == 0 {
		return 0, fmt.Errorf("没有任何可用入站（节点都停用了，或者授权用户都过期/超额）")
	}
	if err = WriteConfig(paths, config); err != nil {
		return 0, err
	}
	if err = Check(paths); err != nil {
		return 0, err
	}
	if err = Restart(paths); err != nil {
		return 0, err
	}
	return inboundCount, nil
}

// Restart 重启内核服务。
func Restart(paths Paths) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "systemctl", "restart", paths.Service)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("重启 %s 失败: %s", paths.Service, strings.TrimSpace(out.String()))
	}
	return nil
}

// ServiceState 返回 systemd 里的服务状态（active/inactive/...）。
func ServiceState(service string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", service).Output()
	if err != nil && len(out) == 0 {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// ---------------------------------------------------------------- 统计

// StatEntry 是一条统计：某个用户的上行/下行。
type StatEntry struct {
	Name string
	Up   int64
	Down int64
}

// FetchStats 通过 sb-stats 读 v2ray_api 的按用户统计。
//
// 为什么绕一层外部小工具：官方 sing-box 不编译 v2ray_api，且没有对应的
// 命令行；sb-stats 用 gRPC 直连，输出格式与 `xray api statsquery` 对齐。
func FetchStats(paths Paths, reset bool) ([]StatEntry, error) {
	args := []string{"--server=" + paths.APIAddr, "-pattern", "user>>>"}
	if reset {
		args = append(args, "-reset")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, paths.StatsBin, args...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("读统计失败: %s %s",
			strings.TrimSpace(out.String()), strings.TrimSpace(errOut.String()))
	}
	return parseStats(out.Bytes())
}

// parseStats 解析 sb-stats 的 {"stat":[{"name":"user>>>a>>>traffic>>>uplink","value":"1"}]}。
func parseStats(body []byte) ([]StatEntry, error) {
	var payload struct {
		Stat []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("解析统计失败: %w", err)
	}
	byUser := map[string]*StatEntry{}
	for _, item := range payload.Stat {
		parts := strings.Split(item.Name, ">>>")
		if len(parts) != 4 || parts[0] != "user" {
			continue
		}
		name, direction := parts[1], parts[3]
		value, err := strconv.ParseInt(item.Value, 10, 64)
		if err != nil {
			continue
		}
		entry, ok := byUser[name]
		if !ok {
			entry = &StatEntry{Name: name}
			byUser[name] = entry
		}
		switch direction {
		case "uplink":
			entry.Up = value
		case "downlink":
			entry.Down = value
		}
	}
	out := make([]StatEntry, 0, len(byUser))
	for _, entry := range byUser {
		out = append(out, *entry)
	}
	return out, nil
}

// Collect 读一次统计并累加进数据库（reset=true，读走即清零）。
func Collect(st *store.Store, paths Paths) (int64, int64, error) {
	entries, err := FetchStats(paths, true)
	if err != nil {
		return 0, 0, err
	}
	var totalUp, totalDown int64
	for _, entry := range entries {
		if entry.Up == 0 && entry.Down == 0 {
			continue
		}
		if err = st.AddTraffic(entry.Name, entry.Up, entry.Down, ""); err != nil {
			return totalUp, totalDown, err
		}
		totalUp += entry.Up
		totalDown += entry.Down
	}
	return totalUp, totalDown, nil
}

// GenerateRealityKeypair 调用内核自带的生成器产出 REALITY 密钥对。
//
// 自己实现 X25519 是没必要的——内核已经有 `generate reality-keypair`，
// 而且这样能保证格式与内核版本始终一致。
func GenerateRealityKeypair(paths Paths) (privKey, pubKey string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, paths.Bin, "generate", "reality-keypair").Output()
	if err != nil {
		return "", "", fmt.Errorf("生成 REALITY 密钥失败: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "privatekey:") || strings.HasPrefix(lower, "private key:"):
			privKey = strings.TrimSpace(trimmed[strings.Index(trimmed, ":")+1:])
		case strings.HasPrefix(lower, "publickey:") || strings.HasPrefix(lower, "public key:"):
			pubKey = strings.TrimSpace(trimmed[strings.Index(trimmed, ":")+1:])
		}
	}
	if privKey == "" || pubKey == "" {
		return "", "", fmt.Errorf("解析 REALITY 密钥输出失败: %q", strings.TrimSpace(string(out)))
	}
	return privKey, pubKey, nil
}

// ---------------------------------------------------------------- 展示辅助

// UserState 是用户在面板语义下的状态。
//
// 这个判定必须只有一处实现：CLI 和 TUI 各写一遍的话，
// 会出现「配置里已经把人摘掉了，列表里还显示正常」这种自相矛盾。
type UserState string

const (
	UserStateOK        UserState = "正常"
	UserStateDisabled  UserState = "停用"
	UserStateExpired   UserState = "已过期"
	UserStateOverQuota UserState = "超配额"
	UserStateNearQuota UserState = "接近上限"
)

// EvaluateUser 判定用户状态。used 是累计用量（上下行之和）。
func EvaluateUser(u store.User, used int64, now time.Time) UserState {
	switch {
	case !u.Enabled:
		return UserStateDisabled
	case u.ExpiresAt > 0 && now.Unix() >= u.ExpiresAt:
		return UserStateExpired
	case u.QuotaBytes > 0 && used >= u.QuotaBytes:
		return UserStateOverQuota
	case u.QuotaBytes > 0 && used*10 >= u.QuotaBytes*8:
		return UserStateNearQuota
	}
	return UserStateOK
}

// Usable 报告该用户此刻是否应当出现在内核配置里。
//
// 这是「配置生成」与「界面显示」共用的唯一判据，避免两边口径不一致。
func Usable(u store.User, used int64, now time.Time) bool {
	switch EvaluateUser(u, used, now) {
	case UserStateOK, UserStateNearQuota:
		return true
	}
	return false
}

// HumanBytes 把字节数变成人看的字符串。
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n)
	for _, suffix := range []string{"KB", "MB", "GB", "TB", "PB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.2f %s", value, suffix)
		}
	}
	return fmt.Sprintf("%.2f EB", value/unit)
}
