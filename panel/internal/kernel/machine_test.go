package kernel

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

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
		"/usr/local/bin/sbx":       "'/usr/local/bin/sbx'",
		"/opt/my dir/sbx":          "'/opt/my dir/sbx'",
		"/opt/it's/sbx":            `'/opt/it'\''s/sbx'`,
		"; rm -rf /":               "'; rm -rf /'",
		"$(whoami)":                "'$(whoami)'",
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
	// 配置一定写下去了
	if _, err := os.ReadFile(dir + "/config.json"); err != nil {
		t.Fatalf("配置没有写盘: %v", err)
	}
	// 重启不存在的服务必须报错（不能假装成功）
	if result.Err == nil {
		t.Fatal("重启不存在的服务应当报错")
	}
	if !strings.Contains(result.Err.Error(), "systemctl") &&
		!strings.Contains(result.Err.Error(), "重启") {
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
