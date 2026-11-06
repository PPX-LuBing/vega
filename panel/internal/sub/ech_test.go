package sub

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

// 和 store 的 ECH 测试用同一对真值（`vega generate ech-keypair` 的输出）
const (
	testECHKeyPEM = `-----BEGIN ECH KEYS-----
ACALy7qgKWAfkexxLtT/UCVgj1j29GQmm1yrRVP9YXavywBb/g0AVwAAIAAgg4Rc
/OoTydpjJ86c2G2/Wb7+P7ocd3R8VXpC4i3xZ30ADAABAAEAAQACAAEAAwAgMjYw
Mi1mNTA2LTgxLS02NDQwLTEzMTkuc3NsaXAuaW8AAA==
-----END ECH KEYS-----
`
	testECHConfigPEM = `-----BEGIN ECH CONFIGS-----
AFv+DQBXAAAgACCDhFz86hPJ2mMnzpzYbb9Zvv4/uhx3dHxVekLiLfFnfQAMAAEA
AQABAAIAAQADACAyNjAyLWY1MDYtODEtLTY0NDAtMTMxOS5zc2xpcC5pbwAA
-----END ECH CONFIGS-----
`
	// 公钥 PEM 里去掉头尾和换行的裸 base64，也就是 clash / AJSON 要的形式
	testECHB64 = "AFv+DQBXAAAgACCDhFz86hPJ2mMnzpzYbb9Zvv4/uhx3dHxVekLiLfFnfQAMAAEA" +
		"AQABAAIAAQADACAyNjAyLWY1MDYtODEtLTY0NDAtMTMxOS5zc2xpcC5pbwAA"
)

func echStore(t *testing.T) (*store.Store, store.User) {
	t.Helper()
	st := testStore(t)
	u := seed(t, st)
	err := st.SaveNode(store.Node{
		Tag: "hk-ech", Proto: store.ProtoAnyTLS, Port: 8448, Enabled: true,
		TLSMode: "tls", SNI: "ech.example.com",
		ECHKey: testECHKeyPEM, ECHConfig: testECHConfigPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = st.Grant("hk-ech", u.Name); err != nil {
		t.Fatal(err)
	}
	return st, u
}

// 三个客户端要的 ECH 格式**不一样**：sing-box 要整段 PEM，mihomo(FlClash) 和
// Anywhere 要裸 base64。
//
// 发错了客户端不会报错、只会静默不用 ECH（观察者照样看得见 SNI），所以必须逐个盯。
func TestECHFormatsPerClient(t *testing.T) {
	st, u := echStore(t)

	t.Run("clash 要裸 base64", func(t *testing.T) {
		body, _, err := Clash(st, u)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(body, "ech-opts:") {
			t.Fatal("clash 订阅里没有 ech-opts")
		}
		if !strings.Contains(body, "enable: true") {
			t.Fatal("ech-opts 没有 enable: true")
		}
		if !strings.Contains(body, testECHB64) {
			t.Fatalf("clash 里找不到裸 base64 的 ECHConfigList；相关片段:\n%s", snippet(body, "ech-opts"))
		}
		if strings.Contains(snippet(body, "ech-opts"), "BEGIN ECH") {
			t.Fatal("clash 里出现了 PEM 头：mihomo 的 ech-opts.config 只吃裸 base64")
		}
	})

	t.Run("singbox 要整段 PEM", func(t *testing.T) {
		body, _, err := Singbox(st, u)
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Outbounds []map[string]any `json:"outbounds"`
		}
		if err = json.Unmarshal([]byte(body), &cfg); err != nil {
			t.Fatal(err)
		}
		var found map[string]any
		for _, ob := range cfg.Outbounds {
			if ob["tag"] == "hk-ech" {
				found = ob
			}
		}
		if found == nil {
			t.Fatal("sing-box 订阅里没有 hk-ech")
		}
		tls, ok := found["tls"].(map[string]any)
		if !ok {
			t.Fatalf("hk-ech 缺 tls 块: %#v", found)
		}
		ech, ok := tls["ech"].(map[string]any)
		if !ok {
			t.Fatalf("tls 里没有 ech: %#v", tls)
		}
		if enabled, _ := ech["enabled"].(bool); !enabled {
			t.Fatal("ech 没有 enabled")
		}
		configs, ok := ech["config"].([]any)
		if !ok || len(configs) != 1 {
			t.Fatalf("ech.config 应当是长度 1 的数组: %#v", ech["config"])
		}
		if got, _ := configs[0].(string); got != testECHConfigPEM {
			t.Fatalf("sing-box 的 ech.config 不是整段 PEM，实际:\n%q", got)
		}
	})

	t.Run("AJSON 要裸 base64", func(t *testing.T) {
		body, _, err := AJSON(st, u)
		if err != nil {
			t.Fatal(err)
		}
		_, proxies := decodeAJSON(t, body)
		security := securityOf(t, proxyByTag(t, proxies, "hk-ech"))
		got, _ := security["ech"].(string)
		if got != testECHB64 {
			t.Fatalf("AJSON 的 security.ech = %q，想要裸 base64 %q", got, testECHB64)
		}
	})

	t.Run("没开 ECH 的节点不该冒出这些字段", func(t *testing.T) {
		clash, _, err := Clash(st, u)
		if err != nil {
			t.Fatal(err)
		}
		// hk-any（a.example.com）没开 ECH，它的块里不该有 ech-opts
		if strings.Contains(snippet(clash, "a.example.com"), "ech-opts") {
			t.Fatal("没开 ECH 的节点也发了 ech-opts")
		}
	})
}

// snippet 取某个关键词附近的文本，用于断言失败时看清上下文。
func snippet(body, keyword string) string {
	index := strings.Index(body, keyword)
	if index < 0 {
		return ""
	}
	start := index - 200
	if start < 0 {
		start = 0
	}
	end := index + 400
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}
