package kernel

import (
	"testing"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

// 和 store / sub 的 ECH 测试用同一对真值（`vega generate ech-keypair` 的输出）
const testECHKeyPEM = `-----BEGIN ECH KEYS-----
ACALy7qgKWAfkexxLtT/UCVgj1j29GQmm1yrRVP9YXavywBb/g0AVwAAIAAgg4Rc
/OoTydpjJ86c2G2/Wb7+P7ocd3R8VXpC4i3xZ30ADAABAAEAAQACAAEAAwAgMjYw
Mi1mNTA2LTgxLS02NDQwLTEzMTkuc3NsaXAuaW8AAA==
-----END ECH KEYS-----
`

// 内核拿的是**私钥**（ECH KEYS PEM），客户端拿的是公钥——两列别搞反。
// 格式必须是 PEM：内核用 pem.Decode + 写死块类型校验。
func TestBuildTLSIncludesECH(t *testing.T) {
	node := store.Node{
		Tag: "ix-ech", Proto: store.ProtoAnyTLS, TLSMode: "tls", SNI: "a.example.com",
		ECHKey: testECHKeyPEM,
	}
	block := buildTLS(node, Paths{})
	if block == nil {
		t.Fatal("tls 模式应当返回 tls 块")
	}
	ech, ok := block["ech"].(map[string]any)
	if !ok {
		t.Fatalf("tls 块里没有 ech: %#v", block)
	}
	if enabled, _ := ech["enabled"].(bool); !enabled {
		t.Fatal("ech 没有 enabled")
	}
	keys, ok := ech["key"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("ech.key 应当是长度 1 的数组: %#v", ech["key"])
	}
	if got, _ := keys[0].(string); got != testECHKeyPEM {
		t.Fatalf("ech.key 不是原样的 ECH KEYS PEM:\n%q", got)
	}

	// 没开 ECH 时不该凭空多出这一段
	node.ECHKey = ""
	if _, exists := buildTLS(node, Paths{})["ech"]; exists {
		t.Fatal("没开 ECH 也下发了 ech 块")
	}

	// REALITY 分支必须完全不认识 ECH（ValidateNode 会拦住，这里确认内核侧也不会误发）
	reality := store.Node{
		Tag: "ix-r", Proto: store.ProtoVLESS, TLSMode: "reality", SNI: "c.example.com",
		Dest: "www.apple.com:443", PrivKey: "x", ShortID: "0123456789abcdef",
		ECHKey: testECHKeyPEM,
	}
	if _, exists := buildTLS(reality, Paths{})["ech"]; exists {
		t.Fatal("REALITY 的 tls 块里不该有 ech")
	}
}
