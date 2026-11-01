package nowhere

import (
	"crypto/tls"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/option"

	"github.com/ohmycggk/nowhere-go/wire"
)

// targetSocksaddr 是纯函数，最容易出错（IP/域名两种形态 + 端口翻译）。
func TestTargetSocksaddr(t *testing.T) {
	ipTarget, err := wire.NewIPTarget(netip.MustParseAddr("1.2.3.4"), 443)
	if err != nil {
		t.Fatal(err)
	}
	got := targetSocksaddr(ipTarget)
	if got.Addr.String() != "1.2.3.4" || got.Port != 443 || got.Fqdn != "" {
		t.Fatalf("IP target 翻译错误: %+v", got)
	}

	domainTarget, err := wire.NewDomainTarget("example.com", 8443)
	if err != nil {
		t.Fatal(err)
	}
	got = targetSocksaddr(domainTarget)
	if got.Fqdn != "example.com" || got.Port != 8443 {
		t.Fatalf("域名 target 翻译错误: %+v", got)
	}
}

const testKeyAlice = "eda652c66b00ac40a45287c8a100ab2a"
const testKeyBob = "0123456789abcdef0123456789abcdef"

// 凭据解析：单密钥与多用户互斥，多用户必须每个用户都有密钥。
func TestResolveCredentials(t *testing.T) {
	if _, _, err := resolveCredentials(option.NowhereInboundOptions{}); err == nil {
		t.Fatal("空配置应当报错")
	}

	// 单密钥模式
	users, key, err := resolveCredentials(option.NowhereInboundOptions{SharedKey: testKeyAlice})
	if err != nil || key != testKeyAlice || len(users) != 0 {
		t.Fatalf("单密钥模式解析错误: %v %q %v", users, key, err)
	}

	// 多用户模式
	users, key, err = resolveCredentials(option.NowhereInboundOptions{
		Users: []option.NowhereUser{
			{Name: "alice", SharedKey: testKeyAlice},
			{Name: "bob", SharedKey: testKeyBob},
		},
	})
	if err != nil || key != "" || len(users) != 2 {
		t.Fatalf("多用户模式解析错误: %v %q %v", users, key, err)
	}
	if users[1].Name != "bob" || users[1].SharedKey != testKeyBob {
		t.Fatalf("用户顺序/内容错了: %+v", users[1])
	}

	// 互斥
	if _, _, err = resolveCredentials(option.NowhereInboundOptions{
		SharedKey: testKeyAlice,
		Users:     []option.NowhereUser{{Name: "alice", SharedKey: testKeyAlice}},
	}); err == nil {
		t.Fatal("单密钥与多用户同时给出应当报错")
	}

	// 用户缺密钥不能静默通过
	if _, _, err = resolveCredentials(option.NowhereInboundOptions{
		Users: []option.NowhereUser{{Name: "alice"}},
	}); err == nil {
		t.Fatal("用户缺密钥应当报错")
	}
}

// TLS 是 portal 的硬前提：没有证书必须启动时就拦下，
// 否则错误会推迟到每个连接握手时，日志里只剩一堆握手失败。
func TestValidateTLS(t *testing.T) {
	if err := validateTLS(&tls.Config{}); err == nil {
		t.Fatal("没有证书应当报错")
	}
	if err := validateTLS(&tls.Config{
		Certificates: []tls.Certificate{{}},
	}); err != nil {
		t.Fatalf("有证书不应报错: %v", err)
	}
}

func ptrBool(v bool) *bool { return &v }
