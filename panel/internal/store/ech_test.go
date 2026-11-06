package store

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
)

// 真值来自 `vega generate ech-keypair 2602-f506-81--6440-1319.sslip.io`。
// 必须和内核逐字节一致：内核是 pem.Decode + 写死块类型（"ECH KEYS" /
// "ECH CONFIGS"）来校验的。
const (
	echKeyPEM = `-----BEGIN ECH KEYS-----
ACALy7qgKWAfkexxLtT/UCVgj1j29GQmm1yrRVP9YXavywBb/g0AVwAAIAAgg4Rc
/OoTydpjJ86c2G2/Wb7+P7ocd3R8VXpC4i3xZ30ADAABAAEAAQACAAEAAwAgMjYw
Mi1mNTA2LTgxLS02NDQwLTEzMTkuc3NsaXAuaW8AAA==
-----END ECH KEYS-----
`
	echConfigPEM = `-----BEGIN ECH CONFIGS-----
AFv+DQBXAAAgACCDhFz86hPJ2mMnzpzYbb9Zvv4/uhx3dHxVekLiLfFnfQAMAAEA
AQABAAIAAQADACAyNjAyLWY1MDYtODEtLTY0NDAtMTMxOS5zc2xpcC5pbwAA
-----END ECH CONFIGS-----
`
)

func echNode() Node {
	return Node{
		Tag: "ix-ech", Proto: ProtoAnyTLS, Port: 8444, Enabled: true, Listen: "0.0.0.0",
		TLSMode: "tls", SNI: "a.example.com",
		ECHKey: echKeyPEM, ECHConfig: echConfigPEM,
	}
}

// realityNode 构造一个**本身合法**的 REALITY 节点，用来验证「REALITY 不能开 ECH」。
// 密钥在测试里现生成：ValidateNode 会从私钥推导公钥并比对，写死的常量很容易对不上。
func realityNode() Node {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return Node{
		Tag: "ix-reality", Proto: ProtoVLESS, Port: 443, Enabled: true, Listen: "0.0.0.0",
		TLSMode: "reality", SNI: "c.example.com", Dest: "www.apple.com:443",
		PrivKey: base64.RawURLEncoding.EncodeToString(key.Bytes()),
		PubKey:  base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
		ShortID: "0123456789abcdef",
	}
}

// ECH 只有真 TLS 入站能用，而且私钥公钥必须成对、PEM 类型必须对。
// 这些限制都放在 ValidateNode 里，免得要等内核启动或客户端连接才发现。
func TestValidateNodeECH(t *testing.T) {
	plain := echNode()
	plain.ECHKey, plain.ECHConfig = "", ""
	if err := ValidateNode(plain); err != nil {
		t.Fatalf("不开 ECH 的节点不该受任何限制: %v", err)
	}
	if err := ValidateNode(echNode()); err != nil {
		t.Fatalf("成对的 ECH 节点应当通过: %v", err)
	}
	if err := ValidateNode(realityNode()); err != nil {
		t.Fatalf("不带 ECH 的 REALITY 节点应当通过: %v", err)
	}

	// 每条用例都要先满足它前面那些校验，否则测到的是别的错误信息。
	cases := []struct {
		name  string
		build func(*Node)
		want  string
	}{
		{"REALITY 不能开", func(n *Node) {
			base := realityNode()
			*n = base
			n.ECHKey, n.ECHConfig = echKeyPEM, echConfigPEM
		}, "只支持 tls"},
		{"none 不能开", func(n *Node) {
			// 换成允许 tls_mode=none 的协议，否则先被「anytls requires TLS」拦住
			n.Proto = ProtoVLESS
			n.TLSMode = "none"
		}, "只支持 tls"},
		{"没有 SNI", func(n *Node) {
			// 显式给证书路径，才能绕过「TLS 没有 cert/key 就必须要 SNI」那条
			n.SNI = ""
			n.CertPath = "/tmp/cert.pem"
			n.KeyPath = "/tmp/key.pem"
		}, "需要 SNI"},
		{"只有私钥", func(n *Node) { n.ECHConfig = "" }, "必须成对"},
		{"只有公钥", func(n *Node) { n.ECHKey = "" }, "必须成对"},
		{"私钥 PEM 类型不对", func(n *Node) { n.ECHKey = echConfigPEM }, "ECH KEYS"},
		{"公钥 PEM 类型不对", func(n *Node) { n.ECHConfig = echKeyPEM }, "ECH CONFIGS"},
		{"根本不是 PEM", func(n *Node) { n.ECHConfig = "QUJD" }, "ECH CONFIGS"},
		{"PEM 后面粘了东西", func(n *Node) { n.ECHKey = echKeyPEM + "extra" }, "多余内容"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			node := echNode()
			tc.build(&node)
			err := ValidateNode(node)
			if err == nil {
				t.Fatal("应当报错但没有")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("错误信息 %q 里没有 %q", err.Error(), tc.want)
			}
		})
	}
}

// ECH 两列要能原样存取（老库靠 ALTER TABLE 补列，新库走建表语句）。
func TestSaveNodeKeepsECH(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	node := echNode()
	if err = s.SaveNode(node); err != nil {
		t.Fatal(err)
	}
	got, err := s.Node(node.Tag)
	if err != nil {
		t.Fatal(err)
	}
	if got.ECHKey != echKeyPEM {
		t.Fatalf("ECH 私钥没有原样存回:\n%q", got.ECHKey)
	}
	if got.ECHConfig != echConfigPEM {
		t.Fatalf("ECH 公钥没有原样存回:\n%q", got.ECHConfig)
	}

	// 关掉也要能存回去（node ech --disable 走这条路）
	node.ECHKey, node.ECHConfig = "", ""
	if err = s.SaveNode(node); err != nil {
		t.Fatal(err)
	}
	if got, err = s.Node(node.Tag); err != nil || got.ECHKey != "" || got.ECHConfig != "" {
		t.Fatalf("关掉 ECH 没写回去: %+v %v", got, err)
	}
}
