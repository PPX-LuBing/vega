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
	return observeWithGetter(func(path string) ([]byte, error) { return httpGetJSON("http://" + clashAddr + path) })
}

func observeWithGetter(get func(string) ([]byte, error)) (Snapshot, error) {
	var snap Snapshot

	if body, err := get("/version"); err == nil {
		var payload struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(body, &payload) == nil {
			snap.Version = payload.Version
		}
	}

	body, err := get("/connections")
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
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return httpReadJSON(req)
}

func httpReadJSON(req *http.Request) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
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
		Bin:         m.KernelPath,
		Config:      m.ConfigPath,
		Service:     m.Service,
		StatsBin:    m.StatsBin,
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
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	result := PushResult{Machine: m.Name}
	if inbounds, ok := config["inbounds"].([]any); ok {
		result.Nodes = len(inbounds)
	}
	if err := ctx.Err(); err != nil {
		result.Err = err
		return result
	}

	body, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		result.Err = err
		return result
	}

	if m.Name == store.LocalMachine || m.Host == "" {
		if err = os.MkdirAll(filepath.Dir(m.ConfigPath), 0o755); err != nil {
			result.Err = err
			return result
		}
		unlock, lockErr := lockConfig(m.ConfigPath + ".lock")
		if lockErr != nil {
			result.Err = fmt.Errorf("lock config: %w", lockErr)
			return result
		}
		defer unlock()
		file, createErr := os.CreateTemp(filepath.Dir(m.ConfigPath), ".vega-config-*.json")
		if createErr != nil {
			result.Err = createErr
			return result
		}
		tmp := file.Name()
		defer os.Remove(tmp)
		if _, err = file.Write(body); err != nil {
			file.Close()
			result.Err = err
			return result
		}
		if err = file.Close(); err != nil {
			result.Err = err
			return result
		}
		if err = checkContext(ctx, Paths{Bin: m.KernelPath, Config: tmp}); err != nil {
			result.Err = err
			return result
		}
		if err = ctx.Err(); err != nil {
			result.Err = err
			return result
		}
		old, readErr := os.ReadFile(m.ConfigPath)
		if readErr != nil && !os.IsNotExist(readErr) {
			result.Err = readErr
			return result
		}
		if err = os.Rename(tmp, m.ConfigPath); err != nil {
			result.Err = err
			return result
		}
		result.Err = restartLocalContext(ctx, m.Service)
		if result.Err != nil {
			if readErr == nil {
				if restoreErr := WriteConfigBytes(m.ConfigPath, old); restoreErr != nil {
					result.Err = fmt.Errorf("%w; restore config: %v", result.Err, restoreErr)
					return result
				}
				if restartErr := restartLocalContext(context.Background(), m.Service); restartErr != nil {
					result.Err = fmt.Errorf("%w; restart restored config: %v", result.Err, restartErr)
				}
			} else {
				_ = os.Remove(m.ConfigPath)
			}
		}
		return result
	}

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
	// Stage next to the destination so rename stays on the same filesystem.
	remote := m.ConfigPath + "." + filepath.Base(local.Name())

	if err = runSSH(ctx, m, "scp", local.Name(), m.SSHUser+"@"+m.Host+":"+remote); err != nil {
		result.Err = fmt.Errorf("上传配置失败: %w", err)
		return result
	}

	script := fmt.Sprintf(`set -e
tmp=%s; cfg=%s; backup=%s; lock=%s
exec 9>"$lock"
flock -n 9
trap 'rm -f "$tmp"' EXIT
umask 077
chmod 600 "$tmp"
%s check -c "$tmp"
had_old=0
if [ -f "$cfg" ]; then cp -p "$cfg" "$backup"; had_old=1; fi
mv "$tmp" "$cfg"
if ! systemctl restart %s; then
  if [ "$had_old" = 1 ]; then mv "$backup" "$cfg"; systemctl restart %s; else rm -f "$cfg"; fi
  exit 1
fi
rm -f "$backup"`, shellQuote(remote), shellQuote(m.ConfigPath), shellQuote(remote+".previous"), shellQuote(m.ConfigPath+".lock"),
		shellQuote(m.KernelPath), shellQuote(m.Service), shellQuote(m.Service))
	if err = runSSH(ctx, m, "ssh", m.SSHUser+"@"+m.Host, script); err != nil {
		// 校验失败就清理上传的临时文件。
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = runSSH(cleanupCtx, m, "ssh", m.SSHUser+"@"+m.Host, "rm -f "+shellQuote(remote))
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

func restartLocalContext(ctx context.Context, service string) error {
	if service == "" {
		service = "sbx"
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "systemctl", "restart", service)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("重启 %s 失败: %w: %s", service, err, strings.TrimSpace(out.String()))
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
	machines, err := ManagedMachines(st, localPaths)
	if err != nil {
		return []PushResult{{Machine: "?", Err: err}}
	}
	results := make([]PushResult, 0, len(machines))
	for _, m := range machines {
		config, err := BuildConfigFor(st, MachinePaths(m), m.Name)
		if err != nil {
			results = append(results, PushResult{Machine: m.Name, Err: err})
			continue
		}
		results = append(results, PushToMachine(ctx, m, config))
	}
	return results
}

// ManagedMachines uses the same machine set for deployment, accounting and status.
func ManagedMachines(st *store.Store, localPaths Paths) ([]store.Machine, error) {
	machines, err := st.Machines()
	if err != nil {
		return nil, err
	}
	// 没登记任何机器时，至少把本机当成一台
	hasLocal := false
	for _, m := range machines {
		hasLocal = hasLocal || m.Name == store.LocalMachine
	}
	if !hasLocal {
		nodes, err := st.Nodes()
		if err != nil {
			return nil, err
		}
		for _, n := range nodes {
			hasLocal = hasLocal || orLocalName(n.Machine) == store.LocalMachine
		}
		if len(machines) == 0 || hasLocal {
			machines = append([]store.Machine{{Name: store.LocalMachine,
				KernelPath: localPaths.Bin, ConfigPath: localPaths.Config,
				Service: localPaths.Service, APIAddr: localPaths.APIAddr, StatsBin: localPaths.StatsBin,
				ClashAddr: localPaths.ClashAddr, ControlAddr: localPaths.ControlAddr}}, machines...)
		}
	}

	return machines, nil
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
	return syncUsersContext(context.Background(), paths, inbound, users)
}

func syncUsersContext(ctx context.Context, paths Paths, inbound string, users []store.User) (int, error) {
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+paths.ControlAddr+"/users", bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+paths.ControlSecret)
	resp, err := client.Do(req)
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
	if resp.StatusCode != http.StatusOK || !result.OK {
		return 0, fmt.Errorf("控制端点拒绝: %s", result.Error)
	}
	return result.Users, nil
}

// SyncNowhereNodes 把所有 nowhere 节点的用户名单推到内核。
//
// 每个节点单独推：不同节点可以授权给不同的人。
func SyncNowhereNodes(st *store.Store, paths Paths) []SyncResult {
	return SyncNowhereNodesContext(context.Background(), st, paths)
}

func SyncNowhereNodesContext(ctx context.Context, st *store.Store, paths Paths) []SyncResult {
	secret, err := st.ControlSecret()
	if err != nil {
		return []SyncResult{{Err: err}}
	}
	paths.ControlSecret = secret
	nodes, err := st.Nodes()
	if err != nil {
		return []SyncResult{{Err: err}}
	}
	results := []SyncResult{}
	for _, node := range nodes {
		if node.Proto != store.ProtoNowhere {
			continue
		}
		users, err := activeUsers(st, node)
		if err != nil {
			results = append(results, SyncResult{Inbound: node.Tag, Err: err})
			continue
		}
		if !node.Enabled {
			users = nil
		}
		machine, err := st.Machine(node.Machine)
		if err != nil {
			results = append(results, SyncResult{Inbound: node.Tag, Err: err})
			continue
		}
		var count int
		if machine.Name == store.LocalMachine {
			local := paths
			if machines, e := st.Machines(); e == nil {
				for _, m := range machines {
					if m.Name == store.LocalMachine {
						local.ControlAddr = m.ControlAddr
					}
				}
			}
			count, err = syncUsersContext(ctx, local, node.Tag, users)
		} else {
			count, err = syncRemoteUsers(ctx, machine, secret, node.Tag, users)
		}
		results = append(results, SyncResult{Inbound: node.Tag, Users: count, Err: err})
	}
	return results
}

func syncRemoteUsers(ctx context.Context, m store.Machine, secret, inbound string, users []store.User) (int, error) {
	members := make([]map[string]string, 0, len(users))
	for _, u := range users {
		members = append(members, map[string]string{"name": u.Name, "shared_key": u.SharedKey})
	}
	body, err := json.Marshal(map[string]any{"inbound": inbound, "users": members})
	if err != nil {
		return 0, err
	}
	// Send secrets through stdin, not the remote command line or process list.
	input := "header = \"Authorization: Bearer " + secret + "\"\n"
	data, _ := json.Marshal(string(body))
	input += "data = " + string(data) + "\n"
	script := "curl --silent --show-error --fail --max-time 10 --config /dev/stdin -H 'Content-Type: application/json' " + shellQuote("http://"+m.ControlAddr+"/users")
	out, err := sshOutput(ctx, m, script, input)
	if err != nil {
		return 0, err
	}
	var response struct {
		OK    bool   `json:"ok"`
		Users int    `json:"users"`
		Error string `json:"error"`
	}
	if err = json.Unmarshal(out, &response); err != nil {
		return 0, err
	}
	if !response.OK {
		return 0, fmt.Errorf("remote user sync: %s", response.Error)
	}
	return response.Users, nil
}
