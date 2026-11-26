package morph

import (
	"testing"
)

// 开启 ECH 的客户端会发上百字节的 ECH 扩展。这条用例保证我们不会因为
// ECH 校验过严而把合法客户端拒掉（真机上就这样挂了两周才发现）。
func TestOuterECHAdmitted(t *testing.T) {
	ech := realOuterECH()
	if len(ech) < 50 {
		t.Fatalf("测试样本不像真实 ECH：只有 %d 字节", len(ech))
	}
	if !validClientExtension(0xfe0d, ech) {
		t.Fatalf("真实形状的 outer ECH（%d 字节）被拒绝 —— 会挡掉开启 ECH 的客户端", len(ech))
	}
	// 完整握手也要能过
	ext := append(append([]byte{0, 43, 0, 3, 2, 3, 4}, 0, 13, 0, 4, 0, 2, 8, 4), 0xfe, 0x0d, byte(len(ech)>>8), byte(len(ech)))
	ext = append(ext, ech...)
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	msg := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	if !clientHelloWellFormed(msg) {
		t.Fatal("带真实 ECH 的完整 ClientHello 被拒绝")
	}
	t.Log("✅ 真实 ECH 扩展通过校验")
}
