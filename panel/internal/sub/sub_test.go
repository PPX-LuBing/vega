package sub

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.SetSetting("sub_host", "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting("sub_base", "https://sub.example.com"); err != nil {
		t.Fatal(err)
	}
	return st
}

// seed 造一份覆盖各协议的节点 + 一个用户。
func seed(t *testing.T, st *store.Store) store.User {
	t.Helper()
	nodes := []store.Node{
		{Tag: "hk-nw", Proto: store.ProtoNowhere, Port: 8443, Enabled: true, Remark: "香港 nowhere",
			Morph: true, TLSMode: "tls", SNI: "a.example.com"},
		{Tag: "hk-any", Proto: store.ProtoAnyTLS, Port: 8444, Enabled: true, Remark: "香港 anytls",
			TLSMode: "tls", SNI: "b.example.com"},
		{Tag: "hk-vless", Proto: store.ProtoVLESS, Port: 8445, Enabled: true,
			TLSMode: "reality", SNI: "c.example.com", PubKey: "CjT73Kg28b267-w2RpFaZPmcOsLt9gpQmEySRgtmAyU", ShortID: "0123456789abcdef"},
		{Tag: "hk-hy2", Proto: store.ProtoHysteria2, Port: 8446, Enabled: true, UpMbps: 50, DownMbps: 100},
		{Tag: "hk-ss", Proto: store.ProtoShadowsocks, Port: 30002, Enabled: true,
			SSMethod: "2022-blake3-aes-128-gcm", SSPassword: "U1NTU1NTU1NTU1NTU1NTUw=="},
		{Tag: "hk-off", Proto: store.ProtoAnyTLS, Port: 8447, Enabled: false, Remark: "停用的"},
	}
	for _, n := range nodes {
		if err := st.SaveNode(n); err != nil {
			t.Fatal(err)
		}
	}
	u := store.User{
		Name: "alice", UUID: "11111111-2222-3333-4444-555555555555",
		Password: "VVVVVVVVVVVVVVVVVVVVVQ==", SharedKey: "0123456789abcdef0123456789abcdef",
		Enabled: true, QuotaBytes: 0,
	}
	if err := st.SaveUser(u); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"hk-nw", "hk-any", "hk-vless", "hk-hy2", "hk-ss", "hk-off"} {
		if err := st.Grant(tag, "alice"); err != nil {
			t.Fatal(err)
		}
	}
	return u
}

// clash 内核不认识 nowhere，写进去整份订阅会解析失败——所以必须跳过，
// 而且要如实报出跳了哪个，不能静默丢节点。
func TestClashSkipsNowhereAndReportsIt(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)

	body, skipped, err := Clash(st, u)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "nowhere") {
		t.Fatal("clash 订阅里不该出现 nowhere")
	}
	if !strings.Contains(strings.Join(skipped, " "), "hk-nw") {
		t.Fatalf("跳过的 nowhere 节点必须报出来，实际: %v", skipped)
	}
	// 停用的节点不该出现
	if strings.Contains(body, "停用的") {
		t.Fatal("停用的节点不该进订阅")
	}
	for _, want := range []string{"香港 anytls", "香港", "203.0.113.9", "RULE-SET,cn_ip,DIRECT", "MATCH,PROXY"} {
		if !strings.Contains(body, want) {
			t.Errorf("clash 订阅缺少 %q", want)
		}
	}
	// 节点名带中文，YAML 必须加引号，否则解析失败
	if !strings.Contains(body, `name: "香港 anytls"`) {
		t.Error("中文节点名没有加引号，YAML 会解析失败")
	}
}

// SS2022 多用户：客户端口令必须是「服务端 PSK:用户 PSK」。
// 只发用户 PSK 的话客户端能连上但认证失败，且报错很难查。
func TestClashShadowsocksUsesServerAndUserPSK(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)

	body, _, err := Clash(st, u)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "U1NTU1NTU1NTU1NTU1NTUw==:VVVVVVVVVVVVVVVVVVVVVQ==") {
		t.Fatalf("SS2022 口令格式不对:\n%s", body)
	}
}

// sing-box 订阅必须带 nowhere——这是本仓库内核相对上游的独有价值，
// 也是客户端能用上自有协议的唯一途径。
func TestSingboxIncludesNowhereAndParses(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)

	body, _, err := Singbox(st, u)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("生成的 JSON 不合法: %v", err)
	}
	outbounds, _ := cfg["outbounds"].([]any)
	var sawNowhere, sawSelector bool
	for _, raw := range outbounds {
		ob, _ := raw.(map[string]any)
		switch ob["type"] {
		case "nowhere":
			sawNowhere = true
			if ob["shared_key"] != u.SharedKey {
				t.Errorf("nowhere 出站的 shared_key 不对: %v", ob["shared_key"])
			}
			// 出站载体就是 TLS1.3，没给 tls 块内核会拒绝加载
			if _, ok := ob["tls"].(map[string]any); !ok {
				t.Error("nowhere 出站必须带 tls 块")
			}
		case "selector":
			sawSelector = true
		}
	}
	if !sawNowhere {
		t.Fatal("sing-box 订阅里必须有 nowhere 出站")
	}
	if !sawSelector {
		t.Fatal("缺少 selector 出站，客户端没法切节点")
	}
}

// reality 节点的 public_key 必须来自节点而不是空值——空值会让客户端
// 静默连不上，而且日志里看不出原因。
func TestSingboxRealityCarriesPublicKey(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)
	body, _, err := Singbox(st, u)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"public_key": "CjT73Kg28b267-w2RpFaZPmcOsLt9gpQmEySRgtmAyU"`) {
		t.Fatalf("reality 出站没带上 public_key:\n%s", body)
	}
}

// 机器没 Host、也没配 sub_host 时，订阅里会写出 0.0.0.0 这种连不上的地址。
// 必须报错而不是发出去。
func TestMissingHostIsReportedNotSilentlyZero(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)
	if err := st.SetSetting("sub_host", ""); err != nil {
		t.Fatal(err)
	}
	body, skipped, err := Clash(st, u)
	if err == nil {
		t.Fatalf("地址解析不到时应当报错，却返回了:\n%s", body)
	}
	if len(skipped) == 0 {
		t.Fatal("应当说明是哪些节点缺地址")
	}
}

// ---------------------------------------------------------------- 服务

func serveTest(t *testing.T, st *store.Store) *httptest.Server {
	t.Helper()
	h := &handler{st: st, cfg: Config{Base: "https://sub.example.com"}}
	mux := http.NewServeMux()
	mux.HandleFunc("/sub/", h.subscription)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func get(t *testing.T, srv *httptest.Server, path, ua string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp.StatusCode, b.String(), resp.Header
}

// token 是订阅的唯一凭据，不能靠猜。无效 token 必须 404，且回显里
// 不能带上 token 本身（否则它会被写进别人的日志）。
func TestServerRejectsUnknownToken(t *testing.T) {
	st := testStore(t)
	seed(t, st)
	srv := serveTest(t, st)

	code, body, _ := get(t, srv, "/sub/deadbeefdeadbeefdeadbeefdeadbeef", "")
	if code != http.StatusNotFound {
		t.Fatalf("无效 token 应当 404，实际 %d", code)
	}
	if strings.Contains(body, "deadbeef") {
		t.Fatal("回显里不该出现 token")
	}
}

// 停用 / 过期 / 超额的用户不能在订阅层放行——那是客户端拿到节点的唯一途径。
func TestServerBlocksDisabledExpiredOverQuota(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)
	token, err := st.SubToken(u.Name)
	if err != nil {
		t.Fatal(err)
	}
	srv := serveTest(t, st)

	if code, _, _ := get(t, srv, "/sub/"+token+"/clash", ""); code != http.StatusOK {
		t.Fatalf("正常用户应当 200，实际 %d", code)
	}

	disabled := u
	disabled.Enabled = false
	if err = st.SaveUser(disabled); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := get(t, srv, "/sub/"+token+"/clash", ""); code != http.StatusForbidden {
		t.Fatalf("停用用户应当 403，实际 %d", code)
	}

	// 超额
	over := u
	over.Enabled = true
	over.QuotaBytes = 100
	if err = st.SaveUser(over); err != nil {
		t.Fatal(err)
	}
	if err = st.AddTraffic(u.Name, 1000, 0, "2026-01-01"); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := get(t, srv, "/sub/"+token+"/clash", ""); code != http.StatusForbidden {
		t.Fatalf("超额用户应当 403，实际 %d", code)
	}
}

// 不带格式后缀时按 User-Agent 猜：sing-box 客户端要 JSON，其余按 clash 处理。
func TestServerPicksFormatFromUserAgent(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)
	token, err := st.SubToken(u.Name)
	if err != nil {
		t.Fatal(err)
	}
	srv := serveTest(t, st)

	code, body, hdr := get(t, srv, "/sub/"+token, "sing-box 1.14.4")
	if code != http.StatusOK {
		t.Fatalf("应当 200，实际 %d", code)
	}
	if !strings.Contains(hdr.Get("Content-Type"), "json") {
		t.Errorf("sing-box UA 应返回 JSON，实际 %s", hdr.Get("Content-Type"))
	}
	if !json.Valid([]byte(body)) {
		t.Error("返回的不是合法 JSON")
	}

	code, body, hdr = get(t, srv, "/sub/"+token, "clash-verge/v2.0")
	if code != http.StatusOK {
		t.Fatalf("应当 200，实际 %d", code)
	}
	if !strings.Contains(hdr.Get("Content-Type"), "yaml") {
		t.Errorf("clash UA 应返回 YAML，实际 %s", hdr.Get("Content-Type"))
	}
	if !strings.Contains(body, "proxies:") {
		t.Error("返回的不是 clash 配置")
	}
	// clash 客户端靠这个头显示用量
	if hdr.Get("Subscription-Userinfo") == "" {
		t.Error("缺少 Subscription-Userinfo 头，clash 里看不到用量")
	}
	if hdr.Get("Cache-Control") != "no-store" {
		t.Error("订阅不能缓存，否则改了节点客户端拉不到")
	}
}

// ---------------------------------------------------------------- token

// token 必须能轮换，且轮换只影响订阅、不动代理凭据——
// 否则订阅地址泄露就得把所有客户端重配一遍。
func TestSubTokenLifecycle(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)

	first, err := st.SubToken(u.Name)
	if err != nil {
		t.Fatal(err)
	}
	again, err := st.SubToken(u.Name)
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatal("同一用户重复取 token 应当稳定，否则每次拉订阅都会换地址")
	}

	rotated, err := st.RotateSubToken(u.Name)
	if err != nil {
		t.Fatal(err)
	}
	if rotated == first {
		t.Fatal("轮换后 token 应当变化")
	}
	if _, err = st.UserBySubToken(first); err == nil {
		t.Fatal("旧 token 应当立即失效")
	}
	got, err := st.UserBySubToken(rotated)
	if err != nil {
		t.Fatal(err)
	}
	// 代理凭据不受影响
	if got.Password != u.Password || got.SharedKey != u.SharedKey || got.UUID != u.UUID {
		t.Fatal("轮换订阅 token 不该动代理凭据")
	}
}

// ---------------------------------------------------------------- ACME

// 启用 ACME 却不给缓存目录必须直接报错。
//
// 没有缓存的话每次重启都会重新签发，很快撞上 Let's Encrypt 的
// 每周同域名签发次数限制，之后连正常续期都会被拒。
func TestACMERequiresCacheDir(t *testing.T) {
	st := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := Serve(ctx, st, Config{
		Listen:     "127.0.0.1:0",
		Base:       "https://sub.example.com",
		ACMEDomain: "sub.example.com",
		// 故意不给 ACMECacheDir
	})
	if err == nil {
		t.Fatal("启用 ACME 却没给缓存目录，应当报错")
	}
	if !strings.Contains(err.Error(), "acme_cache") {
		t.Fatalf("错误信息应当点明缺的是缓存目录，实际: %v", err)
	}
}

// 没配 ACME 时不该碰 80/443，也不该要求缓存目录——反代场景要能用。
func TestPlainServeDoesNotRequireACME(t *testing.T) {
	st := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, st, Config{Listen: "127.0.0.1:0", Base: "https://sub.example.com"})
	}()
	time.Sleep(150 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("明文模式应当正常关闭，实际: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("取消后没有及时退出")
	}
}

// ---------------------------------------------------------------- nowhere

// nowhere 客户端只认 URI，不读 clash YAML 也不读 sing-box JSON。
// 没有这个格式的话，用 nowhere 的人得手拼 URI——服务端地址、共享密钥、
// morph 开关、SNI 一个都不能错，拼错了还查不出原因。
func TestNowhereSubscriptionEmitsURIs(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)

	body, skipped, err := Nowhere(st, u)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "vector://"+u.SharedKey+"@203.0.113.9:8443?") {
		t.Fatalf("URI 主体不对:\n%s", body)
	}
	// morph 必须显式写出来：两代协议的默认值不同，靠默认值迟早出错
	if !strings.Contains(body, "morph=1") {
		t.Error("morph 没有显式写出来")
	}
	// 非 nowhere 节点不该出现在这份订阅里
	for _, tag := range []string{"hk-any", "hk-vless", "hk-hy2", "hk-ss"} {
		if strings.Contains(body, tag) {
			t.Errorf("非 nowhere 节点 %s 不该出现在 nowhere 订阅里", tag)
		}
	}
	_ = skipped
}

// 共享密钥长度不对必须报错而不是拼出一条连不上的 URI。
func TestNowhereSubscriptionRejectsBadKey(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)
	bad := u
	bad.SharedKey = "tooshort"
	if err := st.SaveUser(bad); err != nil {
		t.Fatal(err)
	}
	_, skipped, err := Nowhere(st, bad)
	if err == nil {
		t.Fatal("密钥长度不对应当报错")
	}
	if len(skipped) == 0 {
		t.Fatal("应当说明是哪个节点的问题")
	}
}

// 没有 nowhere 节点时要明确报错，而不是发一份空订阅让客户端干瞪眼。
func TestNowhereSubscriptionWithoutNowhereNodes(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)
	// 只授权非 nowhere 节点
	if err := st.Revoke("hk-nw", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Nowhere(st, u); err == nil {
		t.Fatal("没有 nowhere 节点时应当报错")
	}
}

// ---------------------------------------------------------------- 分流规则

// SSH 默认必须走代理。
//
// 这条是踩过坑的：管理流量直连看着省事，但国内到境外的 SSH 经常又慢又断，
// 穿代理反而稳定。之前 polarisx 的预设里有 DST-PORT,22,DIRECT，上传大文件
// 时慢到不能用，去掉之后才正常。谁要是「顺手」把它加回来，这条测试会拦住。
func TestSSHIsNotForcedDirect(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)

	cl, _, err := Clash(st, u)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"DST-PORT,22", "DST-PORT, 22"} {
		if strings.Contains(cl, bad) {
			t.Fatalf("clash 规则里不该有 %q——SSH 必须走代理", bad)
		}
	}

	sb, _, err := Singbox(st, u)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sb, `"port"`) && strings.Contains(sb, "22") {
		var cfg map[string]any
		if err := json.Unmarshal([]byte(sb), &cfg); err == nil {
			route, _ := cfg["route"].(map[string]any)
			rules, _ := route["rules"].([]any)
			for _, raw := range rules {
				rule, _ := raw.(map[string]any)
				if ports, ok := rule["port"].([]any); ok {
					for _, p := range ports {
						if p == float64(22) && rule["outbound"] == "direct" {
							t.Fatal("sing-box 规则里不该把 22 端口强制直连")
						}
					}
				}
			}
		}
	}
}

// clash 与 sing-box 的分流规则必须来自同一份定义。
//
// 两份规则手工维护迟早会漂移，出现「clash 走了代理但 sing-box 直连」
// 这种谁也查不出来的问题。这里用条数做粗校验。
func TestBothFormatsShareRuleSet(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)

	cl, _, err := Clash(st, u)
	if err != nil {
		t.Fatal(err)
	}
	clashRules := 0
	inRules := false
	for _, line := range strings.Split(cl, "\n") {
		if line == "rules:" {
			inRules = true
			continue
		}
		if inRules && strings.HasPrefix(line, "  - ") {
			clashRules++
		}
	}
	if clashRules != len(presetRules) {
		t.Fatalf("clash 规则数 %d 与定义 %d 不一致", clashRules, len(presetRules))
	}

	sb, _, err := Singbox(st, u)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(sb), &cfg); err != nil {
		t.Fatal(err)
	}
	route, _ := cfg["route"].(map[string]any)
	rules, _ := route["rules"].([]any)
	// 前 3 条是固定动作（嗅探/DNS 劫持/私有地址），其余来自同一份定义；
	// MATCH 变成了 route.final 不算规则。
	if len(rules)-3 != len(presetRules)-1 {
		t.Fatalf("sing-box 规则数 %d（减固定 3 条）与 clash 的 %d 条对不上——"+
			"说明有规则在转换时被静默丢掉了，那会让两种客户端分流不一致",
			len(rules)-3, len(presetRules)-1)
	}
}

// 每条 clash 规则类型都必须有 sing-box 对应写法。
//
// 这是上一条测试的补充：上一条查总数，这条查类型。之前 PROCESS-NAME
// 就没有映射，7 条 Emby 规则被静默丢掉，总数测试才发现。
func TestEveryRuleTypeIsConvertible(t *testing.T) {
	supported := map[string]bool{
		"IP-CIDR": true, "IP-CIDR6": true, "DOMAIN": true,
		"DOMAIN-SUFFIX": true, "DOMAIN-KEYWORD": true,
		"RULE-SET": true, "GEOIP": true, "PROCESS-NAME": true,
	}
	for _, raw := range presetRules {
		if raw == "MATCH,PROXY" || strings.HasPrefix(raw, "AND,(") {
			continue // 分别由 final 和 quicBlockRule 处理
		}
		f := splitRule(raw)
		if len(f) < 3 {
			t.Errorf("规则字段不足: %s", raw)
			continue
		}
		if !supported[f[0]] {
			t.Errorf("规则类型 %q 没有 sing-box 对应写法，会被静默丢掉: %s", f[0], raw)
		}
	}
}

// 规则里引用到的策略组必须有对应的出站，否则客户端加载时报 outbound not found。
func TestGroupOutboundsExist(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)
	sb, _, err := Singbox(st, u)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(sb), &cfg); err != nil {
		t.Fatal(err)
	}
	tags := map[string]bool{}
	for _, raw := range cfg["outbounds"].([]any) {
		ob, _ := raw.(map[string]any)
		if tag, ok := ob["tag"].(string); ok {
			tags[tag] = true
		}
	}
	route, _ := cfg["route"].(map[string]any)
	for _, raw := range route["rules"].([]any) {
		rule, _ := raw.(map[string]any)
		tag, ok := rule["outbound"].(string)
		if !ok {
			continue
		}
		if !tags[tag] {
			t.Fatalf("规则引用了不存在的出站 %q", tag)
		}
	}
}

// ---------------------------------------------------------------- 接入点

// 有中转时订阅必须发接入点，而不是节点自己的直连地址。
//
// 这是踩过的坑：内核在香港监听 30002，客户端要连的是前置 123.207.1.101:23334，
// 由前置转到中转再落到香港。订阅发了直连地址，客户端就绕开了中转，
// 延迟从几十毫秒涨到三百多毫秒——而且表面上「能连上」，很难发现。
func TestSubscriptionUsesEntryPoint(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)

	// 先确认默认发的是直连地址
	before, _, err := Clash(st, u)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(before, "server: 203.0.113.9") {
		t.Fatalf("没有接入点时应当发直连地址:\n%s", before)
	}

	// 给节点配上接入点
	n, err := st.Node("hk-ss")
	if err != nil {
		t.Fatal(err)
	}
	n.EntryHost = "123.207.1.101"
	n.EntryPort = 23334
	if err := st.SaveNode(n); err != nil {
		t.Fatal(err)
	}

	after, _, err := Clash(st, u)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(after, "server: 123.207.1.101") {
		t.Fatalf("配了接入点后应当发接入点地址:\n%s", after)
	}
	if !strings.Contains(after, "port: 23334") {
		t.Fatalf("端口也应当是接入点端口:\n%s", after)
	}
	// 只看 hk-ss 那一条：夹具里其它节点共用同一台机器，没配接入点，
	// 它们照旧发直连地址是对的
	if !strings.Contains(proxyBlock(after, "hk-ss"), "server: 123.207.1.101") {
		t.Fatal("hk-ss 这一条应当发接入点地址")
	}

	// sing-box 侧同样
	sb, _, err := Singbox(st, u)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sb, `"server":"123.207.1.101"`) && !strings.Contains(sb, `"server": "123.207.1.101"`) {
		t.Fatalf("sing-box 订阅也应当发接入点:\n%s", sb)
	}
}

// 只给 host 不给 port（或反过来）是配置漏了，必须拒绝而不是猜一个。
func TestEntryPointRequiresBothFields(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)
	n, err := st.Node("hk-ss")
	if err != nil {
		t.Fatal(err)
	}
	// CLI 层的校验在 main.go，这里只确认 store 不会因为只有一个字段而崩溃
	n.EntryHost = "1.2.3.4"
	n.EntryPort = 0
	if err := st.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	body, _, err := Clash(st, u)
	if err != nil {
		t.Fatal(err)
	}
	// 只有 host 没有 port 时退回直连，不能发出一个端口为 0 的节点
	if strings.Contains(body, "port: 0") {
		t.Fatal("不能发出端口为 0 的节点")
	}
}

// proxyBlock 从 clash 订阅里抠出某个 proxy 的 YAML 片段，方便按节点断言。
func proxyBlock(doc, name string) string {
	lines := strings.Split(doc, "\n")
	start := -1
	for i, l := range lines {
		if strings.Contains(l, "name:") && strings.Contains(l, name) {
			start = i
			continue
		}
		if start >= 0 && i > start && strings.HasPrefix(l, "  - name:") {
			return strings.Join(lines[start:i], "\n")
		}
	}
	if start >= 0 {
		return strings.Join(lines[start:], "\n")
	}
	return ""
}
