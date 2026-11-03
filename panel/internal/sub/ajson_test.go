package sub

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

func decodeAJSON(t *testing.T, body string) (string, []map[string]any) {
	t.Helper()
	var doc struct {
		Anywhere int              `json:"anywhere"`
		Name     string           `json:"name"`
		Proxies  []map[string]any `json:"proxies"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("AJSON 不是合法 JSON: %v\n%s", err, body)
	}
	if doc.Anywhere != 1 {
		t.Fatalf("anywhere 版本 = %d，想要 1", doc.Anywhere)
	}
	return doc.Name, doc.Proxies
}

func proxyByTag(t *testing.T, proxies []map[string]any, tag string) map[string]any {
	t.Helper()
	for _, p := range proxies {
		if id, _ := p["id"].(string); strings.HasPrefix(id, tag+"@") {
			return p
		}
	}
	t.Fatalf("找不到 %s 的代理", tag)
	return nil
}

func securityOf(t *testing.T, proxy map[string]any) map[string]any {
	t.Helper()
	security, ok := proxy["security"].(map[string]any)
	if !ok {
		t.Fatalf("代理缺 security: %#v", proxy)
	}
	return security
}

func TestAJSONCoversEverySupportedProtocol(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)
	n, err := st.Node("hk-nw")
	if err != nil {
		t.Fatal(err)
	}
	n.EntryHost = n.SNI
	if err := st.SaveNode(n); err != nil {
		t.Fatal(err)
	}

	body, skipped, err := AJSON(st, u)
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 0 {
		t.Fatalf("不该跳过任何节点，实际跳过: %v", skipped)
	}
	_, proxies := decodeAJSON(t, body)
	// seed 里有 nowhere / anytls / vless / hysteria2 / shadowsocks 五个可用节点，
	// Anywhere 这五种都支持，一个都不该丢
	if len(proxies) != 5 {
		t.Fatalf("代理数 = %d，想要 5\n%s", len(proxies), body)
	}

	// id 必须唯一：重复的 key 会让客户端静默丢掉后面的代理
	seen := map[string]bool{}
	for _, p := range proxies {
		id, _ := p["id"].(string)
		if id == "" {
			t.Fatalf("代理缺 id: %#v", p)
		}
		if seen[id] {
			t.Fatalf("id 重复: %s", id)
		}
		seen[id] = true
		if p["name"] == "" || p["server"] == "" || p["protocol"] == "" {
			t.Fatalf("代理缺必填字段: %#v", p)
		}
		if _, ok := p["port"].(float64); !ok {
			t.Fatalf("port 必须是 JSON 数字: %#v", p["port"])
		}
	}

	// nowhere：key + morph，server 必须是证书域名（它没有 sni 字段）
	nw := proxyByTag(t, proxies, "hk-nw")
	if nw["protocol"] != "nowhere" || nw["key"] != u.SharedKey || nw["morph"] != true {
		t.Fatalf("nowhere 代理不对: %#v", nw)
	}
	if nw["server"] != "a.example.com" {
		t.Fatalf("nowhere 的 server 应当是证书域名，实际 %v", nw["server"])
	}

	// anytls：password + tls 安全层
	any := proxyByTag(t, proxies, "hk-any")
	if any["protocol"] != "anytls" || any["password"] != u.Password {
		t.Fatalf("anytls 代理不对: %#v", any)
	}
	if securityOf(t, any)["sni"] != "b.example.com" {
		t.Fatalf("anytls 的 sni 不对: %#v", any)
	}

	// vless + reality：公钥 / shortId / flow
	vless := proxyByTag(t, proxies, "hk-vless")
	if vless["protocol"] != "vless" || vless["uuid"] != u.UUID || vless["flow"] != "xtls-rprx-vision" {
		t.Fatalf("vless 代理不对: %#v", vless)
	}
	reality := securityOf(t, vless)
	if reality["type"] != "reality" || reality["sni"] != "c.example.com" ||
		reality["publicKey"] != "CjT73Kg28b267-w2RpFaZPmcOsLt9gpQmEySRgtmAyU" || reality["shortId"] != "0123456789abcdef" {
		t.Fatalf("reality 安全层不对: %#v", reality)
	}

	// hysteria2 在 AJSON 里叫 hysteria，sni 是顶层字段
	hy := proxyByTag(t, proxies, "hk-hy2")
	if hy["protocol"] != "hysteria" || hy["password"] != u.Password {
		t.Fatalf("hysteria 代理不对: %#v", hy)
	}
	if hy["upMbps"] != float64(50) || hy["downMbps"] != float64(100) {
		t.Fatalf("hysteria 限速不对: %#v", hy)
	}

	// shadowsocks 2022：客户端密码是「服务端 PSK : 用户 PSK」
	ss := proxyByTag(t, proxies, "hk-ss")
	if ss["protocol"] != "shadowsocks" || ss["method"] != "2022-blake3-aes-128-gcm" {
		t.Fatalf("shadowsocks 代理不对: %#v", ss)
	}
	if ss["password"] != "U1NTU1NTU1NTU1NTU1NTUw==:"+u.Password {
		t.Fatalf("shadowsocks 密码应当拼上服务端 PSK，实际 %v", ss["password"])
	}
}

// Anywhere 的协议表里没有 vmess 和 tuic，写进去它只会静默丢掉——
// 所以要跳过并如实报出原因。
func TestAJSONSkipsUnsupportedProtocols(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)
	n, err := st.Node("hk-nw")
	if err != nil {
		t.Fatal(err)
	}
	n.EntryHost = n.SNI
	if err := st.SaveNode(n); err != nil {
		t.Fatal(err)
	}

	for _, n := range []store.Node{
		{Tag: "hk-vmess", Proto: store.ProtoVMess, Port: 8448, Enabled: true, TLSMode: "tls", SNI: "d.example.com"},
		{Tag: "hk-tuic", Proto: store.ProtoTUIC, Port: 8449, Enabled: true, TLSMode: "tls", SNI: "e.example.com"},
	} {
		if err := st.SaveNode(n); err != nil {
			t.Fatal(err)
		}
		if err := st.Grant(n.Tag, u.Name); err != nil {
			t.Fatal(err)
		}
	}

	body, skipped, err := AJSON(st, u)
	if err != nil {
		t.Fatal(err)
	}
	_, proxies := decodeAJSON(t, body)
	for _, p := range proxies {
		if proto := p["protocol"]; proto == "vmess" || proto == "tuic" {
			t.Fatalf("不该出现 %v: %#v", proto, p)
		}
	}
	if len(skipped) != 2 {
		t.Fatalf("应当报出 2 个跳过的节点，实际 %v", skipped)
	}
	for _, reason := range skipped {
		if !strings.Contains(reason, "不支持") {
			t.Fatalf("跳过原因不清楚: %q", reason)
		}
	}
}

// 裸地址上，带 X-Anywhere-Format 的请求要给 AJSON；不带的老客户端仍拿 Clash。
func TestServerServesAJSONOnHeader(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)

	h := &handler{st: st, cfg: Config{}}
	token, err := st.SubToken(u.Name)
	if err != nil {
		t.Fatal(err)
	}
	request := func(headers map[string]string) string {
		req := httptest.NewRequest(http.MethodGet, "/sub/"+token, nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.subscription(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}

	ajson := request(map[string]string{"X-Anywhere-Format": "ajson/1", "User-Agent": "Anywhere"})
	if !strings.HasPrefix(strings.TrimSpace(ajson), "{") {
		t.Fatalf("带 X-Anywhere-Format 的请求应当回 AJSON，实际开头: %.40q", ajson)
	}
	decodeAJSON(t, ajson)

	legacy := request(map[string]string{"User-Agent": "Anywhere"})
	if strings.HasPrefix(strings.TrimSpace(legacy), "{") {
		t.Fatal("不带 X-Anywhere-Format 时不该回 AJSON（老版本 Anywhere 读不了）")
	}

	// 显式路径也要能用
	req := httptest.NewRequest(http.MethodGet, "/sub/"+token+"/ajson", nil)
	w := httptest.NewRecorder()
	h.subscription(w, req)
	if w.Code != http.StatusOK || !strings.HasPrefix(strings.TrimSpace(w.Body.String()), "{") {
		t.Fatalf("/ajson 路径没生效: HTTP %d %.60q", w.Code, w.Body.String())
	}
}

func TestWantsAJSON(t *testing.T) {
	cases := map[string]bool{
		"":          false,
		"ajson/1":   true,
		"AJSON/1":   true,
		" ajson/2 ": true,
		"clash":     false,
	}
	for header, want := range cases {
		req := httptest.NewRequest(http.MethodGet, "/sub/x", nil)
		if header != "" {
			req.Header.Set("X-Anywhere-Format", header)
		}
		if got := wantsAJSON(req); got != want {
			t.Errorf("X-Anywhere-Format=%q: wantsAJSON=%t，想要 %t", header, got, want)
		}
	}
}

func TestAJSONNeverReplacesEntryWithSNI(t *testing.T) {
	for _, tc := range []struct {
		host, sni, entrySNI string
		reject              bool
	}{
		{"edge.example.net", "origin.example.com", "", true},
		{"192.0.2.1", "origin.example.com", "", true},
		{"edge.example.net", "origin.example.com", "edge.example.net", false},
		{"edge.example.net", "EDGE.EXAMPLE.NET.", "", false},
		{"edge.example.net", "", "", false},
	} {
		t.Run(tc.host+tc.sni+tc.entrySNI, func(t *testing.T) {
			e := endpoint{Host: tc.host, Port: 8446, Node: store.Node{Tag: "relay", Proto: store.ProtoNowhere, SNI: tc.sni, EntrySNI: tc.entrySNI}, User: store.User{SharedKey: "0123456789abcdef0123456789abcdef"}}
			p, err := ajsonProxy(e)
			if tc.reject {
				if err == nil {
					t.Fatalf("silently changed or accepted incompatible entry: %v", p)
				}
				return
			}
			if err != nil || p["server"] != tc.host || p["port"] != 8446 {
				t.Fatalf("entry changed: %v %v", p, err)
			}
		})
	}
	st := testStore(t)
	u := seed(t, st)
	_, skipped, err := AJSON(st, u)
	if err != nil || !strings.Contains(strings.Join(skipped, " "), "hk-nw") {
		t.Fatalf("missing explicit skip: %v %v", skipped, err)
	}
}
