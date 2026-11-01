package kernel

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

func fakeCommand(t *testing.T, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return path
}

func TestPushValidationAndRestartFailurePreserveConfig(t *testing.T) {
	for _, checkFails := range []bool{true, false} {
		t.Run(fmt.Sprint(checkFails), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			if err := os.WriteFile(path, []byte("known-good"), 0o600); err != nil {
				t.Fatal(err)
			}
			body := "exit 0"
			if checkFails {
				body = "exit 1"
			}
			kernel := fakeCommand(t, "kernel", body)
			log := filepath.Join(dir, "restart.log")
			t.Setenv("RESTART_LOG", log)
			fakeSystemctl(t, `echo restart >> "$RESTART_LOG"; exit 1`)
			result := PushToMachine(context.Background(), store.Machine{Name: store.LocalMachine, KernelPath: kernel, ConfigPath: path, Service: "test"}, map[string]any{"inbounds": []any{}})
			if result.Err == nil {
				t.Fatal("failure hidden")
			}
			got, err := os.ReadFile(path)
			if err != nil || string(got) != "known-good" {
				t.Fatalf("old config lost: %q %v", got, err)
			}
			_, err = os.Stat(log)
			if checkFails && !os.IsNotExist(err) {
				t.Fatal("restarted before validation")
			}
		})
	}
}

func TestRemotePushValidatesAndRollsBack(t *testing.T) {
	for _, mode := range []string{"check-fails", "restart-fails", "success"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			if err := os.WriteFile(path, []byte("known-good"), 0o600); err != nil {
				t.Fatal(err)
			}
			check := "exit 0"
			if mode == "check-fails" {
				check = "exit 1"
			}
			kernel := fakeCommand(t, "kernel", check)
			log := filepath.Join(dir, "restart.log")
			t.Setenv("RESTART_LOG", log)
			t.Setenv("RESTART_MODE", mode)
			fakeSystemctl(t, `
echo restart >> "$RESTART_LOG"
if [ "$RESTART_MODE" = restart-fails ] && [ "$(wc -l < "$RESTART_LOG" | tr -d ' ')" = 1 ]; then exit 1; fi`)
			fakeCommand(t, "scp", `
previous=; last=
for arg; do previous=$last; last=$arg; done
cp "$previous" "${last#*:}"`)
			fakeCommand(t, "ssh", `for arg; do script=$arg; done; exec sh -c "$script"`)
			if runtime.GOOS != "linux" {
				fakeCommand(t, "flock", "exit 0") // Linux CI exercises the real remote lock.
			}
			result := PushToMachine(context.Background(), store.Machine{Name: "remote", Host: "example.invalid", SSHUser: "root", KernelPath: kernel, ConfigPath: path, Service: "test"}, map[string]any{"inbounds": []any{}})
			if (result.Err == nil) != (mode == "success") {
				t.Fatalf("unexpected push result: %v", result.Err)
			}
			got, err := os.ReadFile(path)
			if err != nil || (string(got) == "known-good") != (mode != "success") {
				t.Fatalf("unexpected installed config %q: %v", got, err)
			}
			if info, err := os.Stat(path + ".lock"); err != nil || !info.Mode().IsRegular() {
				t.Fatalf("expected persistent flock inode: %v", err)
			}
			if mode == "check-fails" {
				if _, err = os.Stat(log); !os.IsNotExist(err) {
					t.Fatal("remote restarted before validation")
				}
			}
			if mode == "restart-fails" {
				body, err := os.ReadFile(log)
				if err != nil || strings.Count(string(body), "restart") != 2 {
					t.Fatalf("restored service not restarted: %s %v", body, err)
				}
			}
		})
	}
}

func TestApplyAllKeepsImplicitLocalWithRemoteMachines(t *testing.T) {
	st := testStore(t)
	if err := st.SaveMachine(store.Machine{Name: "remote", Host: "example.invalid"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveNode(store.Node{Tag: "local-node", Proto: store.ProtoAnyTLS, Port: 8443, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveUser(store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.Grant("local-node", "alice"); err != nil {
		t.Fatal(err)
	}
	paths := testPaths()
	paths.Bin = fakeCommand(t, "kernel", "exit 0")
	paths.Config = filepath.Join(t.TempDir(), "config.json")
	fakeSystemctl(t, "exit 0")
	fakeCommand(t, "scp", "exit 1")
	results := ApplyAll(context.Background(), st, paths)
	if len(results) != 2 || results[0].Machine != store.LocalMachine || results[0].Err != nil || results[0].Nodes != 1 {
		t.Fatalf("implicit local omitted: %+v", results)
	}
}

func TestNowhereControlSettingsInConfig(t *testing.T) {
	st := testStore(t)
	if err := st.SaveNode(store.Node{Tag: "nw", Proto: store.ProtoNowhere, Port: 8443, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveUser(store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.Grant("nw", "alice"); err != nil {
		t.Fatal(err)
	}
	paths := testPaths()
	paths.ControlAddr = "127.0.0.1:23456"
	cfg, err := BuildConfig(st, paths)
	if err != nil {
		t.Fatal(err)
	}
	node := cfg["inbounds"].([]any)[0].(map[string]any)
	secret, err := st.ControlSecret()
	if err != nil {
		t.Fatal(err)
	}
	if node["control_addr"] != paths.ControlAddr || node["control_secret"] != secret {
		t.Fatal("control settings missing")
	}
	rules := cfg["route"].(map[string]any)["rules"].([]any)
	if rules[0].(map[string]any)["action"] != "resolve" || rules[1].(map[string]any)["action"] != "reject" {
		t.Fatal("management policy must resolve domains before rejecting loopback targets")
	}
}

func TestSyncRemoteDoesNotUseLocalEndpoint(t *testing.T) {
	st := testStore(t)
	if err := st.SaveMachine(store.Machine{Name: "remote", Host: "example.invalid"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveNode(store.Node{Tag: "remote-node", Machine: "remote", Proto: store.ProtoNowhere, Port: 8443, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveUser(store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.Grant("remote-node", "alice"); err != nil {
		t.Fatal(err)
	}
	fakeCommand(t, "ssh", `cat > "$SYNC_STDIN"; printf '{"ok":true,"users":1}'`)
	path := filepath.Join(t.TempDir(), "stdin")
	t.Setenv("SYNC_STDIN", path)
	results := SyncNowhereNodes(st, Paths{ControlAddr: "127.0.0.1:1"})
	if len(results) != 1 || results[0].Err != nil || results[0].Users != 1 {
		t.Fatalf("%+v", results)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := st.ControlSecret()
	if !strings.Contains(string(body), secret) || !strings.Contains(string(body), "remote-node") {
		t.Fatal("missing remote payload")
	}
}

// 多机编排的核心不变量：每台机器的配置里只能有它自己的节点。
// 搞错了就是「香港的配置里出现了台湾的入站」这种事故。
func TestBuildConfigForFiltersByMachine(t *testing.T) {
	st := testStore(t)
	if err := st.SaveMachine(store.Machine{Name: "hk", Host: "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveMachine(store.Machine{Name: "tw", Host: "2.2.2.2"}); err != nil {
		t.Fatal(err)
	}
	st.SaveNode(store.Node{Tag: "hk-1", Machine: "hk", Proto: store.ProtoNowhere,
		Port: 8443, TLSMode: "none", Enabled: true})
	st.SaveNode(store.Node{Tag: "hk-2", Machine: "hk", Proto: store.ProtoAnyTLS,
		Port: 8444, TLSMode: "none", Enabled: true})
	st.SaveNode(store.Node{Tag: "tw-1", Machine: "tw", Proto: store.ProtoAnyTLS,
		Port: 9443, TLSMode: "none", Enabled: true})
	st.SaveNode(store.Node{Tag: "local-1", Machine: store.LocalMachine, Proto: store.ProtoAnyTLS,
		Port: 10443, TLSMode: "none", Enabled: true})

	st.SaveUser(store.User{Name: "alice", Enabled: true})
	for _, tag := range []string{"hk-1", "hk-2", "tw-1", "local-1"} {
		st.Grant(tag, "alice")
	}

	cases := map[string][]string{
		"hk":    {"hk-1", "hk-2"},
		"tw":    {"tw-1"},
		"local": {"local-1"},
	}
	for machine, want := range cases {
		config, err := BuildConfigFor(st, testPaths(), machine)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, item := range config["inbounds"].([]any) {
			got[item.(map[string]any)["tag"].(string)] = true
		}
		if len(got) != len(want) {
			t.Errorf("机器 %s: 期望 %v，实际 %v", machine, want, got)
			continue
		}
		for _, tag := range want {
			if !got[tag] {
				t.Errorf("机器 %s 的配置里缺少 %s", machine, tag)
			}
		}
	}

	// 不过滤时应当拿到全部
	all, err := BuildConfigFor(st, testPaths(), "")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(all["inbounds"].([]any)); n != 4 {
		t.Errorf("不过滤时应有 4 个入站，实际 %d", n)
	}
}

// 机器名留空的节点必须归到 local，否则多机场景下它会从所有配置里消失。
func TestEmptyMachineCountsAsLocal(t *testing.T) {
	st := testStore(t)
	st.SaveNode(store.Node{Tag: "n", Proto: store.ProtoAnyTLS, Port: 8443, TLSMode: "none", Enabled: true})
	st.SaveUser(store.User{Name: "alice", Enabled: true})
	st.Grant("n", "alice")

	config, err := BuildConfigFor(st, testPaths(), store.LocalMachine)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(config["inbounds"].([]any)); n != 1 {
		t.Fatalf("空机器名的节点应当算作 local，实际入站数 %d", n)
	}
}

// 远端命令里的路径必须被安全引用：路径里有空格或引号时不能被 shell 拆开。
func TestShellQuote(t *testing.T) {
	cases := map[string]string{
		"/usr/local/bin/sbx": "'/usr/local/bin/sbx'",
		"/opt/my dir/sbx":    "'/opt/my dir/sbx'",
		"/opt/it's/sbx":      `'/opt/it'\''s/sbx'`,
		"; rm -rf /":         "'; rm -rf /'",
		"$(whoami)":          "'$(whoami)'",
	}
	for input, want := range cases {
		if got := shellQuote(input); got != want {
			t.Errorf("shellQuote(%q) = %q，期望 %q", input, got, want)
		}
	}
}

// 有节点挂在机器上时不允许删机器——否则节点会变成孤儿。
func TestDeleteMachineRefusesWhenNodesExist(t *testing.T) {
	st := testStore(t)
	st.SaveMachine(store.Machine{Name: "hk", Host: "1.1.1.1"})
	st.SaveNode(store.Node{Tag: "n", Machine: "hk", Proto: store.ProtoAnyTLS,
		Port: 8443, TLSMode: "none", Enabled: true})

	if err := st.DeleteMachine("hk"); err == nil {
		t.Fatal("还有节点时不该允许删机器")
	}
	if err := st.DeleteNode("n"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteMachine("hk"); err != nil {
		t.Fatalf("节点清空后应当能删: %v", err)
	}
	if err := st.DeleteMachine(store.LocalMachine); err == nil {
		t.Fatal("本机不该允许删除")
	}
}

// 机器记录缺省值要补全，否则远端命令会拼出空路径。
func TestSaveMachineFillsDefaults(t *testing.T) {
	st := testStore(t)
	if err := st.SaveMachine(store.Machine{Name: "hk", Host: "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	m, err := st.Machine("hk")
	if err != nil {
		t.Fatal(err)
	}
	if m.SSHPort != 22 || m.SSHUser != "root" || m.Service != "sbx" ||
		m.KernelPath == "" || m.ConfigPath == "" || m.APIAddr == "" || m.ClashAddr == "" {
		t.Fatalf("默认值没补全: %+v", m)
	}

	// 没登记的名字，local 要能兜底；其它名字要报错
	if _, err = st.Machine(store.LocalMachine); err != nil {
		t.Fatalf("local 应当能兜底: %v", err)
	}
	if _, err = st.Machine("不存在"); err == nil {
		t.Fatal("未登记的机器应当报错")
	}
}

// 非本机必须填 host。
func TestSaveMachineRequiresHost(t *testing.T) {
	st := testStore(t)
	if err := st.SaveMachine(store.Machine{Name: "hk"}); err == nil {
		t.Fatal("非本机没填 host 应当报错")
	}
	if err := st.SaveMachine(store.Machine{Name: store.LocalMachine}); err != nil {
		t.Fatalf("本机不填 host 应当允许: %v", err)
	}
}

// 本地分支的推送：写盘 + 重启。重启一个不存在的服务应当报错而不是静默成功。
func TestPushToMachineLocalWritesConfig(t *testing.T) {
	st := testStore(t)
	st.SaveNode(store.Node{Tag: "n", Proto: store.ProtoAnyTLS, Port: 8443, TLSMode: "none", Enabled: true})
	st.SaveUser(store.User{Name: "alice", Enabled: true})
	st.Grant("n", "alice")

	config, err := BuildConfigFor(st, testPaths(), store.LocalMachine)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	machine := store.Machine{
		Name: store.LocalMachine, ConfigPath: dir + "/config.json",
		Service: "sbx-panel-nonexistent-service-for-test",
	}
	result := PushToMachine(context.Background(), machine, config)
	// Failed validation must not install a config or restart the service.
	if _, err := os.ReadFile(dir + "/config.json"); !os.IsNotExist(err) {
		t.Fatalf("invalid config was installed: %v", err)
	}
	// 重启不存在的服务必须报错（不能假装成功）
	if result.Err == nil {
		t.Fatal("重启不存在的服务应当报错")
	}
	if !strings.Contains(result.Err.Error(), "校验") {
		t.Fatalf("错误信息不够明确: %v", result.Err)
	}
	if result.Nodes != 1 {
		t.Fatalf("入站数应为 1，实际 %d", result.Nodes)
	}
}

// Observe 对不可达地址要快速失败并给出可读错误，不能挂住。
func TestObserveUnreachable(t *testing.T) {
	start := time.Now()
	_, err := Observe("127.0.0.1:1")
	if err == nil {
		t.Fatal("不可达地址应当报错")
	}
	if elapsed := time.Since(start); elapsed > 8*time.Second {
		t.Fatalf("超时太长: %v", elapsed)
	}
}

// clash_api 与 v2ray_api 的地址必须来自机器记录，不能硬编码——
// 否则同一台机上跑多个实例时第二个会因为端口被占而起不来。
func TestAPIAddressesComeFromPaths(t *testing.T) {
	st := testStore(t)
	st.SaveNode(store.Node{Tag: "n", Proto: store.ProtoAnyTLS, Port: 8443, TLSMode: "none", Enabled: true})
	st.SaveUser(store.User{Name: "alice", Enabled: true})
	st.Grant("n", "alice")

	paths := testPaths()
	paths.APIAddr = "127.0.0.1:20085"
	paths.ClashAddr = "127.0.0.1:29090"

	config, err := BuildConfigFor(st, paths, "")
	if err != nil {
		t.Fatal(err)
	}
	experimental := config["experimental"].(map[string]any)

	v2ray := experimental["v2ray_api"].(map[string]any)["listen"]
	if v2ray != "127.0.0.1:20085" {
		t.Errorf("v2ray_api 地址错误: %v", v2ray)
	}
	clash := experimental["clash_api"].(map[string]any)["external_controller"]
	if clash != "127.0.0.1:29090" {
		t.Errorf("clash_api 地址错误（可能被硬编码了）: %v", clash)
	}
}

// 内核重启会清零内存里的流量计数，所以 ApplyAll 必须先采集再下发。
//
// 采集失败不阻断下发（用户可能正在修故障，下发是显式意图），但必须挂在
// 结果上如实报出——否则这段用量会无声无息地丢掉。
func TestApplyAllCollectsBeforeRestart(t *testing.T) {
	st := testStore(t)
	if err := st.SaveNode(store.Node{Tag: "nw", Proto: store.ProtoNowhere, Port: 8443, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveUser(store.User{Name: "alice", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.Grant("nw", "alice"); err != nil {
		t.Fatal(err)
	}
	paths := testPaths()
	paths.Bin = fakeCommand(t, "kernel", "exit 0")
	paths.Config = filepath.Join(t.TempDir(), "config.json")
	fakeSystemctl(t, "exit 0")

	// 采集必然失败
	paths.StatsBin = fakeCommand(t, "sb-stats", "exit 1")
	results := ApplyAll(context.Background(), st, paths)
	if len(results) != 1 {
		t.Fatalf("期望 1 台机器: %+v", results)
	}
	if results[0].Err != nil {
		t.Fatalf("采集失败不该阻断下发: %v", results[0].Err)
	}
	if results[0].CollectErr == nil {
		t.Fatal("采集失败必须通过 CollectErr 报出，否则重启丢掉的用量不可见")
	}
}

// fakeSystemctl 包一层假 systemctl：restartBody 只用于 restart，show 统一
// 返回「服务健康」。
//
// 之所以要管 show：重启后不能只看 systemctl 的退出码，面板会再观察一段
// 时间确认服务真的活着。假命令不响应 show 的话，所有下发测试都会被判定
// 成「服务没起来」。
func fakeSystemctl(t *testing.T, restartBody string) string {
	t.Helper()
	shortenServiceWaits(t)
	return fakeCommand(t, "systemctl", `
if [ "$1" = show ]; then
  printf 'ActiveState=active\nMainPID=4242\nNRestarts=0\n'
  exit 0
fi
`+restartBody)
}

// fakeSystemctlDead 模拟「进程 fork 出来就死」：systemctl restart 依然
// 返回 0（Type=simple 就是这样），但服务卡在 activating、没有主进程、
// 重启计数每次查询都在涨。真机上端口冲突就是这个样子。
func fakeSystemctlDead(t *testing.T) string {
	t.Helper()
	shortenServiceWaits(t)
	counter := filepath.Join(t.TempDir(), "nrestarts")
	t.Setenv("NRESTARTS_LOG", counter)
	return fakeCommand(t, "systemctl", `
if [ "$1" = show ]; then
  echo x >> "$NRESTARTS_LOG"
  printf 'ActiveState=activating\nMainPID=0\nNRestarts=%s\n' "$(wc -l < "$NRESTARTS_LOG" | tr -d ' ')"
  exit 0
fi
exit 0`)
}

// shortenServiceWaits 把重启后的观察窗口缩短，免得每个用例真等 2.7 秒。
func shortenServiceWaits(t *testing.T) {
	t.Helper()
	first, second := serviceAliveFirstWait, serviceAliveSecondWait
	serviceAliveFirstWait, serviceAliveSecondWait = 5*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { serviceAliveFirstWait, serviceAliveSecondWait = first, second })
}

// 真机实测出来的：内核因端口冲突起不来时，`systemctl restart` 依然返回 0
// （Type=simple 的语义就是进程 fork 出来即算成功），而服务卡在 activating、
// MainPID=0、NRestarts 一路涨。
//
// 只信退出码就会把「服务已死」报成「下发成功」，而且永远不会回滚。
func TestPushRollsBackWhenServiceDiesAfterRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("known-good"), 0o600); err != nil {
		t.Fatal(err)
	}
	kernel := fakeCommand(t, "kernel", "exit 0")
	fakeSystemctlDead(t)

	result := PushToMachine(context.Background(), store.Machine{
		Name: store.LocalMachine, KernelPath: kernel, ConfigPath: path, Service: "test",
	}, map[string]any{"inbounds": []any{}})

	if result.Err == nil {
		t.Fatal("服务重启后没起来必须报错，否则面板会说下发成功而服务是死的")
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "known-good" {
		t.Fatalf("起不来时必须回滚到旧配置，实际 %q %v", got, err)
	}
}
