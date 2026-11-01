package kernel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

// ---------------------------------------------------------------- 可观测性

// Snapshot 是内核的运行时可观测数据。
//
// 数据源是内核自带的 clash_api（不是 v2ray_api）：后者只给按用户的累计字节，
// 而连接数、内存、进程总量这些「当前状态」只有 clash_api 有。
type Snapshot struct {
	Version           string
	Memory            int64
	UploadTotal       int64
	DownloadTotal     int64
	ActiveConnections int
	TopHosts          []HostCount
}

// HostCount 是一个目标主机的连接数。
type HostCount struct {
	Host  string
	Count int
}

// Observe 读一次 clash_api。
func Observe(clashAddr string) (Snapshot, error) {
	var snap Snapshot

	if body, err := httpGetJSON("http://" + clashAddr + "/version"); err == nil {
		var payload struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(body, &payload) == nil {
			snap.Version = payload.Version
		}
	}

	body, err := httpGetJSON("http://" + clashAddr + "/connections")
	if err != nil {
		return snap, fmt.Errorf("读内核状态失败: %w", err)
	}
	var payload struct {
		UploadTotal   int64 `json:"uploadTotal"`
		DownloadTotal int64 `json:"downloadTotal"`
		Memory        int64 `json:"memory"`
		Connections   []struct {
			Metadata struct {
				Host string `json:"host"`
			} `json:"metadata"`
		} `json:"connections"`
	}
	if err = json.Unmarshal(body, &payload); err != nil {
		return snap, fmt.Errorf("解析内核状态失败: %w", err)
	}
	snap.UploadTotal = payload.UploadTotal
	snap.DownloadTotal = payload.DownloadTotal
	snap.Memory = payload.Memory
	snap.ActiveConnections = len(payload.Connections)

	// 按目标主机聚合，方便看出「谁在占着连接」
	counts := map[string]int{}
	for _, conn := range payload.Connections {
		host := conn.Metadata.Host
		if host == "" {
			host = "(无域名)"
		}
		counts[host]++
	}
	for host, count := range counts {
		snap.TopHosts = append(snap.TopHosts, HostCount{Host: host, Count: count})
	}
	sort.Slice(snap.TopHosts, func(i, j int) bool {
		if snap.TopHosts[i].Count != snap.TopHosts[j].Count {
			return snap.TopHosts[i].Count > snap.TopHosts[j].Count
		}
		return snap.TopHosts[i].Host < snap.TopHosts[j].Host
	})
	if len(snap.TopHosts) > 8 {
		snap.TopHosts = snap.TopHosts[:8]
	}
	return snap, nil
}

func httpGetJSON(url string) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// ---------------------------------------------------------------- 多机编排

// MachinePaths 把机器记录翻译成内核路径。
func MachinePaths(m store.Machine) Paths {
	return Paths{
		Bin:       m.KernelPath,
		Config:    m.ConfigPath,
		Service:   m.Service,
		StatsBin:  m.StatsBin,
		APIAddr:     m.APIAddr,
		ClashAddr:   m.ClashAddr,
		ControlAddr: m.ControlAddr,
	}
}

// BuildConfigFor 生成「只含某台机器的节点」的配置。
//
// machine 为空表示不过滤（单机场景或想看全量）。多机时必须过滤：
// 每台机器的配置里只该有它自己的入站。
func BuildConfigFor(st *store.Store, paths Paths, machine string) (map[string]any, error) {
	nodes, err := st.Nodes()
	if err != nil {
		return nil, err
	}
	if machine != "" {
		filtered := nodes[:0:0]
		for _, n := range nodes {
			if orLocalName(n.Machine) == machine {
				filtered = append(filtered, n)
			}
		}
		nodes = filtered
	}
	return buildConfigFromNodes(st, paths, nodes)
}

func orLocalName(name string) string {
	if strings.TrimSpace(name) == "" {
		return store.LocalMachine
	}
	return name
}

// PushResult 是一台机器下发的结果。
type PushResult struct {
	Machine string
	Nodes   int
	Err     error
}

// PushToMachine 把配置推到远端机器：上传 → 校验 → 替换 → 重启。
//
// 用系统的 ssh/scp 而不是引入 agent：SSH 已经在运维手里，
// 多一个常驻进程就多一份攻击面和一份要维护的代码。
//
// 远端命令里的路径全部单引号包裹，避免路径里有空格或特殊字符时被 shell 拆开。
func PushToMachine(ctx context.Context, m store.Machine, config map[string]any) PushResult {
	result := PushResult{Machine: m.Name}
	if inbounds, ok := config["inbounds"].([]any); ok {
		result.Nodes = len(inbounds)
	}

	body, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		result.Err = err
		return result
	}

	if m.Name == store.LocalMachine || m.Host == "" {
		// 本机：直接走 WriteConfig + Restart
		if err = os.MkdirAll(filepath.Dir(m.ConfigPath), 0o755); err != nil {
			result.Err = err
			return result
		}
		tmp := m.ConfigPath + ".tmp"
		if err = os.WriteFile(tmp, body, 0o600); err != nil {
			result.Err = err
			return result
		}
		if err = os.Rename(tmp, m.ConfigPath); err != nil {
			result.Err = err
			return result
		}
		result.Err = restartLocal(m.Service)
		return result
	}

	// 远端：先传到 /tmp，校验通过再原子替换——校验失败时旧配置原样保留
	remote := fmt.Sprintf("/tmp/sbx-config-%d.json", time.Now().UnixNano())
	local, err := os.CreateTemp("", "sbx-config-*.json")
	if err != nil {
		result.Err = err
		return result
	}
	defer os.Remove(local.Name())
	if _, err = local.Write(body); err != nil {
		local.Close()
		result.Err = err
		return result
	}
	local.Close()

	if err = runSSH(ctx, m, "scp", local.Name(), m.SSHUser+"@"+m.Host+":"+remote); err != nil {
		result.Err = fmt.Errorf("上传配置失败: %w", err)
		return result
	}

	script := fmt.Sprintf(
		"set -e; %s check -c %s && mv %s %s && chmod 600 %s && systemctl restart %s",
		shellQuote(m.KernelPath), shellQuote(remote), shellQuote(remote),
		shellQuote(m.ConfigPath), shellQuote(m.ConfigPath), shellQuote(m.Service))
	if err = runSSH(ctx, m, "ssh", m.SSHUser+"@"+m.Host, script); err != nil {
		// 校验失败就把临时文件清掉，别在 /tmp 里堆垃圾
		_ = runSSH(context.Background(), m, "ssh", m.SSHUser+"@"+m.Host, "rm -f "+shellQuote(remote))
		result.Err = fmt.Errorf("远端下发失败: %w", err)
		return result
	}
	return result
}

// runSSH 执行一次 ssh 或 scp。
//
// 统一加上 BatchMode=yes 与连接超时：面板是交互式的，卡在密码提示上
// 会让整个界面失去响应。远端没配好免密就应该快速失败并报出来。
func runSSH(ctx context.Context, m store.Machine, tool string, args ...string) error {
	port := m.SSHPort
	if port == 0 {
		port = 22
	}
	// ssh 用小写 -p 指定端口，scp 用大写 -P。
	// 用错的话 scp 会把端口号当成源文件名，报 "stat local \"22\": No such file or directory"。
	portFlag := "-p"
	if tool == "scp" {
		portFlag = "-P"
	}
	base := []string{
		portFlag, fmt.Sprint(port),
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=accept-new",
	}
	cmd := exec.CommandContext(ctx, tool, append(base, args...)...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}

func restartLocal(service string) error {
	if service == "" {
		service = "sbx"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "systemctl", "restart", service)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("重启 %s 失败: %s", service, strings.TrimSpace(out.String()))
	}
	return nil
}

// shellQuote 把字符串包成单引号形式，用于远端 shell 命令。
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ApplyAll 把配置下发到所有登记的机器。
//
// 返回每台机器的结果，调用方自己决定怎么展示；一台失败不影响其它机器。
func ApplyAll(ctx context.Context, st *store.Store, localPaths Paths) []PushResult {
	machines, err := st.Machines()
	if err != nil {
		return []PushResult{{Machine: "?", Err: err}}
	}
	// 没登记任何机器时，至少把本机当成一台
	if len(machines) == 0 {
		machines = []store.Machine{{Name: store.LocalMachine,
			KernelPath: localPaths.Bin, ConfigPath: localPaths.Config,
			Service: localPaths.Service, APIAddr: localPaths.APIAddr, StatsBin: localPaths.StatsBin}}
	}

	results := make([]PushResult, 0, len(machines))
	for _, m := range machines {
		paths := MachinePaths(m)
		config, err := BuildConfigFor(st, paths, m.Name)
		if err != nil {
			results = append(results, PushResult{Machine: m.Name, Err: err})
			continue
		}
		results = append(results, PushToMachine(ctx, m, config))
	}
	return results
}

// Reachable 探测一台机器是否可达（用于界面上的状态点）。
func Reachable(m store.Machine) bool {
	if m.Name == store.LocalMachine || m.Host == "" {
		return true
	}
	port := m.SSHPort
	if port == 0 {
		port = 22
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", m.Host, port), 3*time.Second)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// ---------------------------------------------------------------- 运行期改用户

// SyncResult 是一次运行期改用户的结果。
type SyncResult struct {
	Inbound string
	Users   int
	Err     error
}

// SyncUsers 把用户名单推给运行中的内核，**不重启**。
//
// 走的是 nowhere 入站的控制端点（POST /users）。只有 nowhere 协议支持：
// 其它协议的认证依赖 sing-box 的入站实现，没有运行期换名单的接口，
// 只能改配置重启——这正是自有协议的价值所在。
func SyncUsers(paths Paths, inbound string, users []store.User) (int, error) {
	type controlUser struct {
		Name      string `json:"name"`
		SharedKey string `json:"shared_key"`
	}
	payload := map[string]any{
		"users": make([]controlUser, 0, len(users)),
	}
	if inbound != "" {
		payload["inbound"] = inbound
	}
	list := make([]controlUser, 0, len(users))
	for _, u := range users {
		list = append(list, controlUser{Name: u.Name, SharedKey: u.SharedKey})
	}
	payload["users"] = list

	body, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post("http://"+paths.ControlAddr+"/users",
		"application/json", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("连不上控制端点 %s（内核是否带 control_addr 启动？）: %w", paths.ControlAddr, err)
	}
	defer resp.Body.Close()

	var result struct {
		OK      bool     `json:"ok"`
		Users   int      `json:"users"`
		Updated []string `json:"updated"`
		Error   string   `json:"error"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return 0, fmt.Errorf("控制端点返回的不是 JSON（HTTP %d）", resp.StatusCode)
	}
	if !result.OK {
		return 0, fmt.Errorf("控制端点拒绝: %s", result.Error)
	}
	return result.Users, nil
}

// SyncNowhereNodes 把所有 nowhere 节点的用户名单推到内核。
//
// 每个节点单独推：不同节点可以授权给不同的人。
func SyncNowhereNodes(st *store.Store, paths Paths) []SyncResult {
	nodes, err := st.Nodes()
	if err != nil {
		return []SyncResult{{Err: err}}
	}
	results := []SyncResult{}
	for _, node := range nodes {
		if node.Proto != store.ProtoNowhere || !node.Enabled {
			continue
		}
		users, err := activeUsers(st, node)
		if err != nil {
			results = append(results, SyncResult{Inbound: node.Tag, Err: err})
			continue
		}
		count, err := SyncUsers(paths, node.Tag, users)
		results = append(results, SyncResult{Inbound: node.Tag, Users: count, Err: err})
	}
	return results
}
