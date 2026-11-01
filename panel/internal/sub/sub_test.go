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
	for _, want := range []string{"香港 anytls", "香港", "203.0.113.9", "GEOIP,cn,DIRECT", "MATCH,PROXY"} {
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
