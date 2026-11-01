// sbx-panel —— sbx 内核的终端面板。
//
// 用法：
//
//	sbx-panel                          打开 TUI
//	sbx-panel apply                    生成配置并重启内核（可脚本化）
//	sbx-panel collect                  采集一次流量
//	sbx-panel enforce [--watch]        采集并执行配额（变化机器会重启）
//	sbx-panel node add|list|del        节点管理
//	sbx-panel user add|list|del|grant  用户与授权
//	sbx-panel show                     打印生成的配置（排错用）
//	sbx-panel status                   内核运行状态（可观测性）
//	sbx-panel machine add|list|del     多机编排
//	sbx-panel user sync                运行期改用户（不重启，仅 nowhere）
//	sbx-panel serve                    起订阅服务（clash / sing-box）
//	                                   加 --acme-domain 可自动签发证书
//	sbx-panel user sub [name]          打印该用户的订阅地址
//	sbx-panel user rotate-sub [name]   换一把订阅 token（地址泄露时用）
//	sbx-panel user qr [name]           把订阅地址打成二维码（手机扫码导入）
//	sbx-panel setting get|set          读写面板设置（如 sub_host）
//	sbx-panel version
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	qrcode "github.com/skip2/go-qrcode"

	"github.com/PPX-LuBing/vega/panel/internal/kernel"
	"github.com/PPX-LuBing/vega/panel/internal/store"
	"github.com/PPX-LuBing/vega/panel/internal/sub"
	"github.com/PPX-LuBing/vega/panel/internal/tui"
)

const version = "0.1.0"

const defaultDB = "/var/lib/sbx-panel/panel.db"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "错误: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	dbPath := os.Getenv("SBX_PANEL_DB")
	if dbPath == "" {
		dbPath = defaultDB
	}
	paths := kernel.DefaultPaths()

	if len(args) == 0 {
		return runTUI(dbPath, paths)
	}

	switch args[0] {
	case "version":
		fmt.Printf("sbx-panel %s\n", version)
		fmt.Printf("  数据库: %s\n", dbPath)
		fmt.Printf("  内核:   %s\n", paths.Bin)
		fmt.Printf("  配置:   %s\n", paths.Config)
		fmt.Printf("  服务:   %s\n", paths.Service)
		return nil
	case "apply":
		st, err := store.Open(dbPath)
		if err != nil {
			return err
		}
		defer st.Close()
		results := kernel.ApplyAll(context.Background(), st, paths)
		var failed int
		for _, r := range results {
			if r.Err != nil {
				failed++
				fmt.Printf("  ✗ %-12s %v\n", r.Machine, r.Err)
				continue
			}
			fmt.Printf("  ✓ %-12s %d 个入站\n", r.Machine, r.Nodes)
			if r.CollectErr != nil {
				fmt.Printf("    ⚠ 重启前采集失败，这段用量已丢失: %v\n", r.CollectErr)
			}
		}
		if failed > 0 {
			return fmt.Errorf("%d/%d 台机器下发失败", failed, len(results))
		}
		fmt.Printf("已下发 %d 台机器。\n", len(results))
		return nil
	case "status":
		st, err := store.Open(dbPath)
		if err != nil {
			return err
		}
		defer st.Close()
		failed := 0
		for _, r := range kernel.ObserveAll(context.Background(), st, paths) {
			fmt.Printf("%s: 服务 %s (%s)\n", r.Machine.Name, r.Machine.Service, r.State)
			if r.Err != nil {
				failed++
				fmt.Printf("  读取失败: %v\n", r.Err)
				continue
			}
			fmt.Printf("  版本: %s  活动连接: %d  内存: %s\n", r.Version, r.ActiveConnections, kernel.HumanBytes(r.Memory))
			fmt.Printf("  进程流量: ↑ %s / ↓ %s\n", kernel.HumanBytes(r.UploadTotal), kernel.HumanBytes(r.DownloadTotal))
		}
		if failed > 0 {
			return fmt.Errorf("%d 台机器状态读取失败", failed)
		}
		return nil
	case "enforce":
		return runEnforce(dbPath, paths, args[1:])
	case "machine":
		return runMachine(dbPath, args[1:])
	case "collect":
		st, err := store.Open(dbPath)
		if err != nil {
			return err
		}
		defer st.Close()
		var up, down int64
		var failed int
		for _, r := range kernel.CollectAll(context.Background(), st, paths) {
			if r.Err != nil {
				failed++
				fmt.Printf("  ✗ %s: %v\n", r.Machine, r.Err)
				continue
			}
			up += r.Up
			down += r.Down
			fmt.Printf("  %s: ↑ %s / ↓ %s\n", r.Machine, kernel.HumanBytes(r.Up), kernel.HumanBytes(r.Down))
		}
		fmt.Printf("采集: ↑ %s / ↓ %s\n", kernel.HumanBytes(up), kernel.HumanBytes(down))
		if failed > 0 {
			return fmt.Errorf("%d 台机器采集失败，成功机器已入库", failed)
		}
		return nil
	case "show":
		st, err := store.Open(dbPath)
		if err != nil {
			return err
		}
		defer st.Close()
		config, err := kernel.BuildConfig(st, paths)
		if err != nil {
			return err
		}
		body, err := json.MarshalIndent(config, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(body))
		return nil
	case "node":
		return runNode(dbPath, paths, args[1:])
	case "user":
		return runUser(dbPath, paths, args[1:])
	case "serve":
		return runServe(dbPath, args[1:])
	case "setting":
		return runSetting(dbPath, args[1:])
	default:
		return fmt.Errorf("未知命令: %s（试 version / apply / collect / enforce / status / machine / node / user / serve / setting / show）", args[0])
	}
}

func runEnforce(dbPath string, paths kernel.Paths, args []string) error {
	fs := flag.NewFlagSet("enforce", flag.ContinueOnError)
	watch := fs.Bool("watch", false, "持续采集并执行配额/到期，配置变化时重启对应机器")
	interval := fs.Duration("interval", 30*time.Second, "两轮完成之间的间隔，至少 1s")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *interval < time.Second {
		return fmt.Errorf("用法: enforce [--watch] [--interval 30s]，间隔至少 1s")
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	for {
		failed := 0
		for _, r := range kernel.Enforce(ctx, st, paths) {
			if r.Err != nil {
				failed++
				fmt.Printf("%s: 失败: %v\n", r.Machine, r.Err)
			} else if r.Changed {
				fmt.Printf("%s: 配置已更新，已重启以关闭旧会话\n", r.Machine)
			} else if !*watch {
				fmt.Printf("%s: 配置未变，无需重启\n", r.Machine)
			}
		}
		if !*watch {
			if failed > 0 {
				return fmt.Errorf("%d 台机器执行失败", failed)
			}
			return nil
		}
		timer := time.NewTimer(*interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func runTUI(dbPath string, paths kernel.Paths) error {
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	model := tui.New(st, paths)
	defer model.Close()
	program := tea.NewProgram(model, tea.WithAltScreen())
	_, err = program.Run()
	return err
}

// reorderArgs 把位置参数挪到末尾，让 flag 包能正确解析。
//
// 标准库 flag 遇到第一个非 flag 参数就停止解析，所以
// `node add hk-nw --port 8443` 里的 --port 会被当成位置参数吃掉。
// 这里按「该 flag 是否布尔型」判断它后面跟不跟值，把两者分开再拼接。
func reorderArgs(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positional = append(positional, arg)
			continue
		}
		flags = append(flags, arg)
		name := strings.TrimLeft(arg, "-")
		if strings.Contains(name, "=") {
			continue // --key=value 自带值
		}
		f := fs.Lookup(name)
		if f == nil {
			continue // 未知 flag 交给 flag 包去报错
		}
		if boolFlag, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && boolFlag.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positional...)
}

// ---------------------------------------------------------------- machine

func runMachine(dbPath string, args []string) error {
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if len(args) == 0 {
		return fmt.Errorf("用法: machine add|list|del")
	}

	switch args[0] {
	case "list":
		machines, err := st.Machines()
		if err != nil {
			return err
		}
		if len(machines) == 0 {
			fmt.Println("只管理本机。用 `machine add` 登记其它机器。")
			return nil
		}
		fmt.Printf("%-12s %-22s %-6s %-26s %-6s %s\n",
			"NAME", "HOST", "SSH", "内核路径", "节点", "状态")
		for _, m := range machines {
			host, port := m.Host, strconv.Itoa(m.SSHPort)
			if m.Name == store.LocalMachine || host == "" {
				host, port = "(本机)", "-"
			}
			count := 0
			nodes, _ := st.Nodes()
			for _, n := range nodes {
				if n.Machine == m.Name || (n.Machine == "" && m.Name == store.LocalMachine) {
					count++
				}
			}
			state := "在线"
			if !kernel.Reachable(m) {
				state = "不可达"
			}
			fmt.Printf("%-12s %-22s %-6s %-26s %-6d %s\n",
				m.Name, host, port, m.KernelPath, count, state)
		}
		return nil

	case "add":
		fs := flag.NewFlagSet("machine add", flag.ContinueOnError)
		host := fs.String("host", "", "主机地址（本机留空）")
		sshPort := fs.Int("ssh-port", 22, "SSH 端口")
		sshUser := fs.String("ssh-user", "root", "SSH 用户")
		kernelPath := fs.String("kernel-path", "/usr/local/bin/sbx", "内核路径")
		configPath := fs.String("config-path", "/usr/local/etc/sbx/config.json", "配置路径")
		service := fs.String("service", "sbx", "systemd 服务名")
		apiAddr := fs.String("api", "127.0.0.1:10085", "v2ray_api 地址")
		statsBin := fs.String("stats-bin", "/usr/local/bin/sb-stats", "统计工具路径")
		clashAddr := fs.String("clash", "127.0.0.1:9090", "clash_api 地址")
		controlAddr := fs.String("control", "127.0.0.1:10087", "nowhere 控制地址")
		remark := fs.String("remark", "", "备注")
		if err = fs.Parse(reorderArgs(fs, args[1:])); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return fmt.Errorf("用法: machine add <name> --host 1.2.3.4 [--ssh-port 22]")
		}
		name := fs.Arg(0)
		machine := store.Machine{
			Name: name, Host: *host, SSHPort: *sshPort, SSHUser: *sshUser,
			KernelPath: *kernelPath, ConfigPath: *configPath, Service: *service,
			APIAddr: *apiAddr, StatsBin: *statsBin, ClashAddr: *clashAddr, ControlAddr: *controlAddr, Remark: *remark,
		}
		if err = st.SaveMachine(machine); err != nil {
			return err
		}
		fmt.Printf("已登记机器 %s\n", name)
		if name != store.LocalMachine && !kernel.Reachable(machine) {
			fmt.Printf("  注意：%s:%d 当前不可达（面板下发时需要免密 SSH）\n", *host, *sshPort)
		}
		return nil

	case "del":
		if len(args) < 2 {
			return fmt.Errorf("用法: machine del <name>")
		}
		if err = st.DeleteMachine(args[1]); err != nil {
			return err
		}
		fmt.Printf("已删除机器 %s\n", args[1])
		return nil
	}
	return fmt.Errorf("未知子命令: machine %s", args[0])
}

// ---------------------------------------------------------------- node

func runNode(dbPath string, paths kernel.Paths, args []string) error {
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if len(args) == 0 {
		return fmt.Errorf("用法: node add|list|del")
	}

	switch args[0] {
	case "list":
		nodes, err := st.Nodes()
		if err != nil {
			return err
		}
		fmt.Printf("%-18s %-13s %-7s %-9s %-6s %-24s %s\n", "TAG", "协议", "端口", "TLS", "用户", "客户端接入点", "状态")
		for _, n := range nodes {
			users, _ := st.UsersForNode(n.Tag)
			state := "启用"
			if !n.Enabled {
				state = "停用"
			}
			// 接入点为空表示客户端直连，跟内核监听一致
			entry := "直连"
			if n.EntryHost != "" {
				entry = fmt.Sprintf("%s:%d", n.EntryHost, n.EntryPort)
			}
			fmt.Printf("%-18s %-13s %-7d %-9s %-6d %-24s %s\n",
				n.Tag, n.Proto, n.Port, n.TLSMode, len(users), entry, state)
		}
		return nil

	case "add":
		fs := flag.NewFlagSet("node add", flag.ContinueOnError)
		proto := fs.String("proto", store.ProtoNowhere, "协议")
		port := fs.Int("port", 0, "端口")
		tlsMode := fs.String("tls", "tls", "tls/reality/none")
		sni := fs.String("sni", "", "SNI")
		cert := fs.String("cert", "", "证书路径")
		machineName := fs.String("machine", store.LocalMachine, "所在机器名")
		key := fs.String("key", "", "私钥路径")
		remark := fs.String("remark", "", "备注")
		listen := fs.String("listen", "0.0.0.0", "监听地址")
		dest := fs.String("dest", "", "REALITY 伪装目标 host:port")
		privKey := fs.String("priv-key", "", "REALITY 私钥")
		pubKey := fs.String("pub-key", "", "REALITY 公钥")
		shortID := fs.String("short-id", "", "REALITY short id")
		morph := fs.Bool("morph", true, "Nowhere Morph")
		entryHost := fs.String("entry-host", "", "客户端接入地址（有中转时填，留空=直连本机）")
		entryPort := fs.Int("entry-port", 0, "客户端接入端口（有中转时填）")
		if err := fs.Parse(reorderArgs(fs, args[1:])); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return fmt.Errorf("用法: node add <tag> --proto --port")
		}
		tag := fs.Arg(0)
		if (*entryHost == "") != (*entryPort == 0) {
			return fmt.Errorf("--entry-host 与 --entry-port 要么都给，要么都不给（只给一个说明配置漏了）")
		}
		node := store.Node{
			Tag: tag, Proto: *proto, Port: *port, TLSMode: *tlsMode, SNI: *sni,
			Remark: *remark, Listen: *listen, Enabled: true, Morph: *morph,
			Dest: *dest, PrivKey: *privKey, PubKey: *pubKey, ShortID: *shortID,
			CertPath: *cert, KeyPath: *key, Machine: *machineName,
			EntryHost: *entryHost, EntryPort: *entryPort,
		}
		if node.Remark == "" {
			node.Remark = tag
		}
		if *proto == store.ProtoShadowsocks && node.SSPassword == "" {
			node.SSPassword = store.NewSecret()
		}
		// REALITY 密钥对由内核自己生成，避免手填出错格式
		if node.TLSMode == "reality" && node.PrivKey == "" {
			priv, pub, err := kernel.GenerateRealityKeypair(paths)
			if err != nil {
				return err
			}
			node.PrivKey, node.PubKey = priv, pub
		}
		if err := st.SaveNode(node); err != nil {
			return err
		}
		fmt.Printf("已保存节点 %s（%s，端口 %d）\n", tag, *proto, *port)
		if node.PubKey != "" {
			fmt.Printf("  REALITY 公钥: %s\n", node.PubKey)
		}
		if *proto == store.ProtoShadowsocks {
			saved, _ := st.Node(tag)
			fmt.Printf("  SS2022 服务端 PSK: %s\n", saved.SSPassword)
		}
		return nil

	case "del":
		if len(args) < 2 {
			return fmt.Errorf("用法: node del <tag>")
		}
		if err := st.DeleteNode(args[1]); err != nil {
			return err
		}
		fmt.Printf("已删除节点 %s\n", args[1])
		return nil
	}
	return fmt.Errorf("未知子命令: node %s", args[0])
}

// ---------------------------------------------------------------- user

func runUser(dbPath string, paths kernel.Paths, args []string) error {
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if len(args) == 0 {
		return fmt.Errorf("用法: user add|list|del|grant|revoke|reset|sub|rotate-sub")
	}

	switch args[0] {
	case "sub", "rotate-sub":
		return runUserSub(st, args[0] == "rotate-sub", args[1:])

	case "qr":
		return runUserQR(st, args[1:])

	case "list":
		users, err := st.Users()
		if err != nil {
			return err
		}
		usage, _ := st.AllUsage()
		fmt.Printf("%-16s %-11s %-11s %-6s %s\n", "用户", "已用", "配额", "节点", "状态")
		for _, u := range users {
			u2 := usage[u.Name]
			used := u2[0] + u2[1]
			quota := "不限"
			if u.QuotaBytes > 0 {
				quota = kernel.HumanBytes(u.QuotaBytes)
			}
			nodes, _ := st.NodesForUser(u.Name)
			state := kernel.EvaluateUser(u, used, time.Now())
			fmt.Printf("%-16s %-11s %-11s %-6d %s\n",
				u.Name, kernel.HumanBytes(used), quota, len(nodes), state)
		}
		return nil

	case "add":
		fs := flag.NewFlagSet("user add", flag.ContinueOnError)
		quotaGB := fs.String("quota", "0", "配额 GB，0 不限")
		days := fs.String("days", "0", "有效天数，0 永久")
		remark := fs.String("remark", "", "备注")
		if err := fs.Parse(reorderArgs(fs, args[1:])); err != nil {
			return err
		}
		if fs.NArg() < 1 {
			return fmt.Errorf("用法: user add <name> --quota 100 --days 30")
		}
		name := fs.Arg(0)
		quota, err := kernel.ParseQuotaGB(*quotaGB)
		if err != nil {
			return err
		}
		expires, err := kernel.ParseExpiryDays(*days)
		if err != nil {
			return err
		}
		user := store.User{
			Name: name, Remark: *remark, Enabled: true,
			QuotaBytes: quota, ExpiresAt: expires,
		}
		if err := st.SaveUser(user); err != nil {
			return err
		}
		saved, _ := st.User(name)
		fmt.Printf("已创建用户 %s\n", name)
		fmt.Printf("  UUID:       %s\n", saved.UUID)
		fmt.Printf("  口令:       %s\n", saved.Password)
		fmt.Printf("  Nowhere 密钥: %s\n", saved.SharedKey)
		return nil

	case "del":
		if len(args) < 2 {
			return fmt.Errorf("用法: user del <name>")
		}
		if err := st.DeleteUser(args[1]); err != nil {
			return err
		}
		fmt.Printf("已删除用户 %s\n", args[1])
		return nil

	case "grant":
		if len(args) < 3 {
			return fmt.Errorf("用法: user grant <name> <node-tag>")
		}
		if err := st.Grant(args[2], args[1]); err != nil {
			return err
		}
		fmt.Printf("已授权 %s → %s\n", args[1], args[2])
		return nil

	case "revoke":
		if len(args) < 3 {
			return fmt.Errorf("用法: user revoke <name> <node-tag>")
		}
		if err := st.Revoke(args[2], args[1]); err != nil {
			return err
		}
		fmt.Printf("已取消 %s → %s 的授权\n", args[1], args[2])
		return nil

	case "sync":
		// 运行期把用户名单推给内核，不重启。只有 nowhere 协议支持。
		results := kernel.SyncNowhereNodes(st, paths)
		if len(results) == 0 {
			fmt.Println("没有启用的 nowhere 节点，无需同步。")
			return nil
		}
		var failed int
		for _, r := range results {
			if r.Err != nil {
				failed++
				fmt.Printf("  ✗ %-16s %v\n", r.Inbound, r.Err)
				continue
			}
			fmt.Printf("  ✓ %-16s %d 个用户（未重启）\n", r.Inbound, r.Users)
		}
		if failed > 0 {
			return fmt.Errorf("%d/%d 个节点同步失败", failed, len(results))
		}
		return nil

	case "reset":
		if len(args) < 2 {
			return fmt.Errorf("用法: user reset <name>")
		}
		if err := st.ResetTraffic(args[1]); err != nil {
			return err
		}
		fmt.Printf("已重置 %s 的流量计数\n", args[1])
		return nil

	case "show":
		if len(args) < 2 {
			return fmt.Errorf("用法: user show <name>")
		}
		user, err := st.User(args[1])
		if err != nil {
			return err
		}
		up, down, _ := st.Usage(user.Name)
		nodes, _ := st.NodesForUser(user.Name)
		fmt.Printf("用户 %s\n", user.Name)
		fmt.Printf("  UUID:         %s\n", user.UUID)
		fmt.Printf("  口令:         %s\n", user.Password)
		fmt.Printf("  Nowhere 密钥: %s\n", user.SharedKey)
		fmt.Printf("  用量:         ↑ %s / ↓ %s\n", kernel.HumanBytes(up), kernel.HumanBytes(down))
		fmt.Printf("  授权节点:     %s\n", strings.Join(nodes, ", "))
		return nil
	}
	return fmt.Errorf("未知子命令: user %s", args[0])
}

// runServe 起订阅 HTTP 服务。
//
// 订阅地址里的主机名必须显式给（--base），因为面板不知道自己在公网叫什么；
// 猜错的话所有客户端都会拿到连不上的地址。
func runServe(dbPath string, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "监听地址；前面有反代时绑回环")
	base := fs.String("base", "", "订阅地址前缀，如 https://sub.example.com")
	interval := fs.Duration("interval", 12*time.Hour, "客户端多久来拉一次")
	acmeDomain := fs.String("acme-domain", "", "启用 ACME 自动签发时填域名；留空则用明文，TLS 交给反代")
	acmeEmail := fs.String("acme-email", "", "ACME 账号邮箱（Let's Encrypt 到期提醒用）")
	acmeCache := fs.String("acme-cache", "", "ACME 证书缓存目录（启用 ACME 时必填）")
	acmeHTTP := fs.String("acme-http", ":80", "ACME HTTP-01 挑战与跳转的监听地址")
	acmeTLS := fs.String("acme-tls", ":443", "ACME 模式下的 HTTPS 监听地址")
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("用法: serve --listen 127.0.0.1:8080 --base https://sub.example.com")
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	// --base 优先，其次读设置里的 sub_base，都没有就报错而不是猜
	resolved := strings.TrimSpace(*base)
	if resolved == "" {
		resolved = strings.TrimSpace(st.Setting("sub_base", ""))
	}
	if resolved == "" {
		return fmt.Errorf("必须给 --base（或先 setting set sub_base <url>），否则订阅里写不出客户端能用的地址")
	}
	// 本机节点的地址也依赖 sub_host，提前查一次，缺了就早报错
	if strings.TrimSpace(st.Setting("sub_host", "")) == "" {
		fmt.Println("提示：还没设 sub_host，本机上的节点无法生成订阅地址。")
		fmt.Println("      用 setting set sub_host <你的公网 IP 或域名> 补上。")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return sub.Serve(ctx, st, sub.Config{
		Listen:       *listen,
		Base:         strings.TrimRight(resolved, "/"),
		Interval:     *interval,
		ACMEDomain:   strings.TrimSpace(*acmeDomain),
		ACMEEmail:    strings.TrimSpace(*acmeEmail),
		ACMECacheDir: strings.TrimSpace(*acmeCache),
		ACMEHTTPAddr: *acmeHTTP,
		ACMETLSAddr:  *acmeTLS,
	})
}

// runSetting 读写面板设置。
func runSetting(dbPath string, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("用法: setting get <key> | setting set <key> <value>")
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	switch args[0] {
	case "get":
		fmt.Println(st.Setting(args[1], ""))
		return nil
	case "set":
		if len(args) < 3 {
			return fmt.Errorf("用法: setting set <key> <value>")
		}
		// 订阅地址相关的键顺手去掉尾部斜杠，避免拼出 //sub/...
		value := strings.TrimRight(strings.TrimSpace(args[2]), "/")
		if err := st.SetSetting(args[1], value); err != nil {
			return err
		}
		fmt.Printf("已设置 %s = %s\n", args[1], value)
		return nil
	default:
		return fmt.Errorf("用法: setting get <key> | setting set <key> <value>")
	}
}

// runUserSub 打印（或轮换）某个用户的订阅地址。
//
// 不给名字就列出所有用户的，方便一次性导出一批订阅。
func runUserSub(st *store.Store, rotate bool, args []string) error {
	base := strings.TrimRight(strings.TrimSpace(st.Setting("sub_base", "")), "/")
	if base == "" {
		return fmt.Errorf("还没配 sub_base，先执行: setting set sub_base https://你的订阅域名")
	}

	var names []string
	if len(args) > 0 {
		names = args
	} else {
		users, err := st.Users()
		if err != nil {
			return err
		}
		for _, u := range users {
			if u.Enabled {
				names = append(names, u.Name)
			}
		}
		if len(names) == 0 {
			return fmt.Errorf("没有启用的用户")
		}
	}

	for _, name := range names {
		var (
			token string
			err   error
		)
		if rotate {
			token, err = st.RotateSubToken(name)
		} else {
			token, err = st.SubToken(name)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		fmt.Printf("%-12s %s/sub/%s\n", name, base, token)
		fmt.Printf("%-12s %s/sub/%s/clash    (clash/mihomo)\n", "", base, token)
		fmt.Printf("%-12s %s/sub/%s/singbox  (sing-box，含 nowhere)\n", "", base, token)
		fmt.Printf("%-12s %s/sub/%s/nowhere  (nowhere 官方客户端)\n", "", base, token)
	}
	if rotate {
		fmt.Println("\n旧地址已失效。客户端需要重新拉取。")
	}
	return nil
}

// runUserQR 把订阅地址打成二维码，方便手机扫码导入。
//
// 打的是 clash 格式的地址：手机上的客户端绝大多数是 clash 系。
// 用终端半块字符渲染，比用 ASCII 双字符紧凑一半。
func runUserQR(st *store.Store, args []string) error {
	base := strings.TrimRight(strings.TrimSpace(st.Setting("sub_base", "")), "/")
	if base == "" {
		return fmt.Errorf("还没配 sub_base，先执行: setting set sub_base https://你的订阅域名")
	}
	if len(args) != 1 {
		return fmt.Errorf("用法: user qr <name>")
	}
	token, err := st.SubToken(args[0])
	if err != nil {
		return err
	}
	url := base + "/sub/" + token + "/clash"

	qr, err := qrcode.New(url, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("生成二维码失败: %w", err)
	}
	fmt.Printf("%s 的订阅地址：\n%s\n\n", args[0], url)
	fmt.Print(qr.ToSmallString(false))
	fmt.Println()
	return nil
}
