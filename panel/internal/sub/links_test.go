package sub

import (
	"net/url"
	"strings"
	"testing"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

// tuic:// 的分享链接有固定形态：userinfo 是 uuid:password，参数按
// v2rayN / NekoBox 的事实标准（congestion_control + alpn + udp_relay_mode）。
// 传输层的 type/path 对 TUIC 无意义，带了会让客户端把 network 设成 tcp。
func TestTUICShareLink(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)
	node := store.Node{
		Tag: "sg-tuic", Proto: store.ProtoTUIC, Port: 8445, Enabled: true,
		TLSMode: "tls", SNI: "sub.example.com", EntryHost: "sub.example.com",
	}
	if err := st.SaveNode(node); err != nil {
		t.Fatal(err)
	}
	if err := st.Grant("sg-tuic", u.Name); err != nil {
		t.Fatal(err)
	}

	body, skipped, err := Links(st, u, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range skipped {
		if strings.Contains(tag, "tuic") {
			t.Fatalf("TUIC 不该被跳过: %v", skipped)
		}
	}
	var line string
	for _, candidate := range strings.Split(body, "\n") {
		if strings.HasPrefix(candidate, "tuic://") {
			line = candidate
			break
		}
	}
	if line == "" {
		t.Fatalf("分享链接里没有 tuic://\n%s", body)
	}

	parsed, err := url.Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.User.Username() != u.UUID {
		t.Fatalf("userinfo 的 uuid 不对: %q，想要 %q", parsed.User.Username(), u.UUID)
	}
	if password, ok := parsed.User.Password(); !ok || password != u.Password {
		t.Fatalf("userinfo 的 password 不对: %q ok=%v", password, ok)
	}

	q := parsed.Query()
	for key, want := range map[string]string{
		"congestion_control": "bbr",
		"udp_relay_mode":     "native",
		"alpn":               "h3",
		"security":           "tls",
		"sni":                "sub.example.com",
	} {
		if got := q.Get(key); got != want {
			t.Errorf("%s = %q，想要 %q", key, got, want)
		}
	}
	for _, key := range []string{"type", "path", "host", "serviceName"} {
		if q.Has(key) {
			t.Errorf("TUIC 链接不该带 %s 参数", key)
		}
	}
}

// Hysteria2 同样不走传输层，链接里不该出现 type/path/host，否则客户端会把
// network 设成 tcp。
func TestHysteria2ShareLinkClean(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)
	if err := st.SaveNode(store.Node{
		Tag: "sg-hy2", Proto: store.ProtoHysteria2, Port: 8448, Enabled: true,
		TLSMode: "tls", SNI: "sub.example.com", EntryHost: "sub.example.com", Path: "/",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Grant("sg-hy2", u.Name); err != nil {
		t.Fatal(err)
	}
	body, _, err := Links(st, u, false)
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, candidate := range strings.Split(body, "\n") {
		// seed() 里已经有一个无 SNI 的 hy2 节点，按端口精确挑我们自己建的那个
		if strings.HasPrefix(candidate, "hysteria2://") && strings.Contains(candidate, ":8448?") {
			line = candidate
			break
		}
	}
	if line == "" {
		t.Fatalf("没有 hysteria2:// 链接\n%s", body)
	}
	parsed, err := url.Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	q := parsed.Query()
	if q.Get("sni") != "sub.example.com" {
		t.Errorf("sni = %q", q.Get("sni"))
	}
	for _, key := range []string{"type", "path", "host", "serviceName"} {
		if q.Has(key) {
			t.Errorf("Hysteria2 链接不该带 %s 参数", key)
		}
	}
}
