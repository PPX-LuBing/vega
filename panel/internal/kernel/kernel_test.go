package kernel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func testPaths() Paths {
	return Paths{
		Bin: "/usr/local/bin/sbx", Config: "/tmp/config.json",
		Service: "sbx", StatsBin: "/usr/local/bin/sb-stats", APIAddr: "127.0.0.1:10085",
	}
}

// 配额/到期/停用三个闸门必须真的把人挡在配置之外——
// 这是面板相对内核原生能力的主要增量，错了就等于配额形同虚设。
func TestActiveUsersFilters(t *testing.T) {
	st := testStore(t)
	if err := st.SaveNode(store.Node{Tag: "n1", Proto: store.ProtoNowhere, Port: 8443, TLSMode: "none", Enabled: true}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		user  store.User
		usage int64 // 预置流量（字节）
		want  bool
	}{
		{"正常", store.User{Name: "ok", Enabled: true}, 0, true},
		{"停用", store.User{Name: "off", Enabled: false}, 0, false},
		{"已过期", store.User{Name: "expired", Enabled: true, ExpiresAt: time.Now().Add(-time.Hour).Unix()}, 0, false},
		{"未到期", store.User{Name: "valid", Enabled: true, ExpiresAt: time.Now().Add(time.Hour).Unix()}, 0, true},
		{"未超额", store.User{Name: "under", Enabled: true, QuotaBytes: 1000}, 999, true},
		{"刚好超额", store.User{Name: "over", Enabled: true, QuotaBytes: 1000}, 1000, false},
		{"远超配额", store.User{Name: "wayover", Enabled: true, QuotaBytes: 1000}, 99999, false},
		{"不限量", store.User{Name: "unlimited", Enabled: true, QuotaBytes: 0}, 1 << 40, true},
	}

	for _, tc := range cases {
		if err := st.SaveUser(tc.user); err != nil {
			t.Fatal(err)
		}
		if err := st.Grant("n1", tc.user.Name); err != nil {
			t.Fatal(err)
		}
		if tc.usage > 0 {
			if err := st.AddTraffic(tc.user.Name, tc.usage, 0, ""); err != nil {
				t.Fatal(err)
			}
		}
	}

	node, _ := st.Node("n1")
	users, err := activeUsers(st, node)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, u := range users {
		got[u.Name] = true
	}
	for _, tc := range cases {
		if got[tc.user.Name] != tc.want {
			t.Errorf("%s(%s): 期望可用=%v 实际=%v", tc.name, tc.user.Name, tc.want, got[tc.user.Name])
		}
	}
}

// 没有任何可用用户的节点不该出现在配置里（别开个没人能用的端口）。
func TestBuildConfigSkipsEmptyNodes(t *testing.T) {
	st := testStore(t)
	st.SaveNode(store.Node{Tag: "used", Proto: store.ProtoNowhere, Port: 8443, TLSMode: "none", Enabled: true, Morph: true})
	st.SaveNode(store.Node{Tag: "unused", Proto: store.ProtoAnyTLS, Port: 8444, TLSMode: "none", Enabled: true})
	st.SaveNode(store.Node{Tag: "disabled", Proto: store.ProtoAnyTLS, Port: 8445, TLSMode: "none", Enabled: false})
	st.SaveUser(store.User{Name: "alice", Enabled: true})
	st.Grant("used", "alice")

	config, err := BuildConfig(st, testPaths())
	if err != nil {
		t.Fatal(err)
	}
	inbounds := config["inbounds"].([]any)
	if len(inbounds) != 1 {
		t.Fatalf("期望 1 个入站，实际 %d", len(inbounds))
	}
	if tag := inbounds[0].(map[string]any)["tag"]; tag != "used" {
		t.Fatalf("入站 tag 错误: %v", tag)
	}

	// 统计范围必须与入站一致，否则统计里会出现不存在的人
	stats := config["experimental"].(map[string]any)["v2ray_api"].(map[string]any)["stats"].(map[string]any)
	if users := stats["users"].([]any); len(users) != 1 || users[0] != "alice" {
		t.Fatalf("统计用户错误: %v", users)
	}
	if tags := stats["inbounds"].([]any); len(tags) != 1 || tags[0] != "used" {
		t.Fatalf("统计入站错误: %v", tags)
	}
}

// Nowhere 入站必须带上每用户的 shared_key（多用户识别的依据）。
func TestNowhereInboundCarriesSharedKeys(t *testing.T) {
	st := testStore(t)
	st.SaveNode(store.Node{Tag: "nw", Proto: store.ProtoNowhere, Port: 8443, TLSMode: "none", Enabled: true, Morph: true})
	st.SaveUser(store.User{Name: "alice", Enabled: true})
	st.SaveUser(store.User{Name: "bob", Enabled: true})
	st.Grant("nw", "alice")
	st.Grant("nw", "bob")

	config, err := BuildConfig(st, testPaths())
	if err != nil {
		t.Fatal(err)
	}
	inbound := config["inbounds"].([]any)[0].(map[string]any)
	if inbound["type"] != "nowhere" {
		t.Fatalf("类型错误: %v", inbound["type"])
	}
	members := inbound["users"].([]any)
	if len(members) != 2 {
		t.Fatalf("期望 2 个用户，实际 %d", len(members))
	}
	for _, item := range members {
		member := item.(map[string]any)
		key, _ := member["shared_key"].(string)
		if len(key) != 32 {
			t.Fatalf("用户 %v 的共享密钥长度应为 32，实际 %d (%q)", member["name"], len(key), key)
		}
		for _, ch := range key {
			if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
				t.Fatalf("共享密钥必须是小写十六进制: %q", key)
			}
		}
	}
}

// parseStats 解析 sb-stats 的输出。
func TestParseStats(t *testing.T) {
	body := []byte(`{"stat":[
      {"name":"user>>>alice>>>traffic>>>uplink","value":"100"},
      {"name":"user>>>alice>>>traffic>>>downlink","value":"200"},
      {"name":"user>>>bob>>>traffic>>>uplink","value":"7"},
      {"name":"inbound>>>nw>>>traffic>>>uplink","value":"999"}
    ]}`)
	entries, err := parseStats(body)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]StatEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	if len(byName) != 2 {
		t.Fatalf("期望 2 个用户，实际 %d（inbound 条目不该算进来）", len(byName))
	}
	if e := byName["alice"]; e.Up != 100 || e.Down != 200 {
		t.Fatalf("alice 统计错误: %+v", e)
	}
	if e := byName["bob"]; e.Up != 7 || e.Down != 0 {
		t.Fatalf("bob 统计错误: %+v", e)
	}

	// 空输入不能报错
	if entries, err := parseStats([]byte(`{"stat":[]}`)); err != nil || len(entries) != 0 {
		t.Fatalf("空统计应当返回空且不报错: %v %v", entries, err)
	}
	// 坏 JSON 必须报错，不能静默当成 0
	if _, err := parseStats([]byte(`not json`)); err == nil {
		t.Fatal("坏 JSON 应当报错")
	}
}

func TestCollectUsesRetrySafeCounters(t *testing.T) {
	st := testStore(t)
	dir := t.TempDir()
	output := filepath.Join(dir, "stats.json")
	args := filepath.Join(dir, "args")
	t.Setenv("STATS_OUTPUT", output)
	t.Setenv("STATS_ARGS", args)
	bin := fakeCommand(t, "sb-stats", `printf '%s\n' "$@" > "$STATS_ARGS"; cat "$STATS_OUTPUT"`)
	paths := testPaths()
	paths.StatsBin = bin
	if err := os.WriteFile(output, []byte(`{"instance":"boot-1","stat":[{"name":"user>>>alice>>>traffic>>>uplink","value":"100"},{"name":"user>>>alice>>>traffic>>>downlink","value":"200"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, want := range [][2]int64{{100, 200}, {0, 0}} {
		up, down, err := Collect(st, paths)
		if err != nil || up != want[0] || down != want[1] {
			t.Fatalf("collect %d/%d, want %v: %v", up, down, want, err)
		}
	}
	body, err := os.ReadFile(args)
	if err != nil || strings.Contains(string(body), "reset") {
		t.Fatalf("destructive collection: %s: %v", body, err)
	}
	if err = os.WriteFile(output, []byte(`{"stat":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = Collect(st, paths); err == nil {
		t.Fatal("old stats binary accepted without instance marker")
	}
}

// 配置要能序列化成内核认的 JSON（键名不能写错）。
func TestConfigJSONShape(t *testing.T) {
	st := testStore(t)
	st.SaveNode(store.Node{Tag: "nw", Proto: store.ProtoNowhere, Port: 8443, TLSMode: "none", Enabled: true, Morph: true})
	st.SaveUser(store.User{Name: "alice", Enabled: true})
	st.Grant("nw", "alice")

	config, err := BuildConfig(st, testPaths())
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err = json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"log", "dns", "inbounds", "outbounds", "route", "experimental"} {
		if _, ok := parsed[key]; !ok {
			t.Errorf("配置缺少顶层字段 %s", key)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[int64]string{
		0:       "0 B",
		512:     "512 B",
		1024:    "1.00 KB",
		1 << 20: "1.00 MB",
		1 << 30: "1.00 GB",
		3 << 29: "1.50 GB",
	}
	for input, want := range cases {
		if got := HumanBytes(input); got != want {
			t.Errorf("HumanBytes(%d) = %q，期望 %q", input, got, want)
		}
	}
}

// 状态判定必须只有一处实现：否则会出现「配置里已经把人摘掉了，
// 列表里还显示正常」这种自相矛盾。这里同时钉住两件事：
//  1. EvaluateUser 的分类正确
//  2. Usable 的结论与 BuildConfig 实际行为一致
func TestEvaluateUserAndUsableAgree(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name   string
		user   store.User
		used   int64
		state  UserState
		usable bool
	}{
		{"正常", store.User{Name: "a", Enabled: true}, 0, UserStateOK, true},
		{"停用", store.User{Name: "b", Enabled: false}, 0, UserStateDisabled, false},
		{"过期", store.User{Name: "c", Enabled: true, ExpiresAt: now.Add(-time.Minute).Unix()},
			0, UserStateExpired, false},
		{"未到期", store.User{Name: "d", Enabled: true, ExpiresAt: now.Add(time.Hour).Unix()},
			0, UserStateOK, true},
		{"超额", store.User{Name: "e", Enabled: true, QuotaBytes: 100}, 100, UserStateOverQuota, false},
		{"接近上限", store.User{Name: "f", Enabled: true, QuotaBytes: 100}, 85, UserStateNearQuota, true},
		{"未接近", store.User{Name: "g", Enabled: true, QuotaBytes: 100}, 10, UserStateOK, true},
	}
	for _, tc := range cases {
		if got := EvaluateUser(tc.user, tc.used, now); got != tc.state {
			t.Errorf("%s: 状态 %q，期望 %q", tc.name, got, tc.state)
		}
		if got := Usable(tc.user, tc.used, now); got != tc.usable {
			t.Errorf("%s: Usable=%v，期望 %v", tc.name, got, tc.usable)
		}
	}
}

// 端到端一致性：EvaluateUser 说不该用的，BuildConfig 就必须真的不放进去。
func TestUsableMatchesBuildConfig(t *testing.T) {
	st := testStore(t)
	st.SaveNode(store.Node{Tag: "n", Proto: store.ProtoNowhere, Port: 8443, TLSMode: "none", Enabled: true})

	// 一个正常、一个超额、一个过期、一个停用
	st.SaveUser(store.User{Name: "ok", Enabled: true})
	st.SaveUser(store.User{Name: "over", Enabled: true, QuotaBytes: 100})
	st.SaveUser(store.User{Name: "expired", Enabled: true, ExpiresAt: time.Now().Add(-time.Hour).Unix()})
	st.SaveUser(store.User{Name: "off", Enabled: false})
	st.AddTraffic("over", 200, 0, "")
	for _, name := range []string{"ok", "over", "expired", "off"} {
		st.Grant("n", name)
	}

	config, err := BuildConfig(st, testPaths())
	if err != nil {
		t.Fatal(err)
	}
	inConfig := map[string]bool{}
	for _, item := range config["inbounds"].([]any)[0].(map[string]any)["users"].([]any) {
		inConfig[item.(map[string]any)["name"].(string)] = true
	}

	users, _ := st.Users()
	now := time.Now()
	for _, u := range users {
		up, down, _ := st.Usage(u.Name)
		want := Usable(u, up+down, now)
		if inConfig[u.Name] != want {
			t.Errorf("用户 %s: Usable=%v 但配置里=%v（口径不一致）", u.Name, want, inConfig[u.Name])
		}
	}
	if !inConfig["ok"] || inConfig["over"] || inConfig["expired"] || inConfig["off"] {
		t.Errorf("配置内容不对: %v", inConfig)
	}
}

// 附加配置必须能真的把额外出站和路由规则并进去，且不破坏面板生成的
// 部分——这是「AI 域名走台湾链路」这类需求不改代码就能落地的唯一口子。
func TestExtraConfigMergesAdditively(t *testing.T) {
	st := testStore(t)
	if err := st.SaveNode(store.Node{Tag: "ss", Proto: store.ProtoShadowsocks, Port: 30002, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveUser(store.User{Name: "hk", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := st.Grant("ss", "hk"); err != nil {
		t.Fatal(err)
	}
	extra := `{
      "outbounds": [{"type":"shadowsocks","tag":"chain","server":"tw.example.com","server_port":50360,
                     "method":"2022-blake3-aes-128-gcm","password":"AAAAAAAAAAAAAAAAAAAAAA==:BBBBBBBBBBBBBBBBBBBBBB=="}],
      "route": {"rules": [{"domain_suffix":["openai.com"],"outbound":"chain"}]}
    }`
	if err := st.SetSetting("extra_config", extra); err != nil {
		t.Fatal(err)
	}
	paths := testPaths()
	config, err := BuildConfigFor(st, paths, store.LocalMachine)
	if err != nil {
		t.Fatal(err)
	}

	// 额外出站要并进去，面板自己的 direct 也要还在
	outbounds, _ := config["outbounds"].([]any)
	var sawChain, sawDirect bool
	for _, raw := range outbounds {
		ob, _ := raw.(map[string]any)
		switch ob["tag"] {
		case "chain":
			sawChain = true
		case "direct":
			sawDirect = true
		}
	}
	if !sawChain {
		t.Fatal("附加出站没并进去")
	}
	if !sawDirect {
		t.Fatal("合并把面板自己的出站覆盖掉了，应当是追加")
	}

	// 额外路由规则要追加，且不能吃掉面板的管理地址拒绝规则
	route, _ := config["route"].(map[string]any)
	rules, _ := route["rules"].([]any)
	var sawAI, sawReject bool
	for _, raw := range rules {
		rule, _ := raw.(map[string]any)
		if _, ok := rule["domain_suffix"]; ok {
			sawAI = true
		}
		if _, ok := rule["ip_cidr"]; ok {
			sawReject = true
		}
	}
	if !sawAI {
		t.Fatal("附加路由规则没并进去")
	}
	if !sawReject {
		t.Fatal("合并把管理地址拒绝规则覆盖掉了")
	}
}

// 附加配置写错必须报错，不能静默忽略——否则运维以为链路生效了，
// 实际流量还在直连。
func TestExtraConfigRejectsBadJSON(t *testing.T) {
	st := testStore(t)
	if err := st.SetSetting("extra_config", "{不是 JSON"); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildConfigFor(st, testPaths(), store.LocalMachine); err == nil {
		t.Fatal("非法 extra_config 应当报错")
	}
}
