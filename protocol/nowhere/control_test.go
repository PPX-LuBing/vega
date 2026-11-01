package nowhere

import (
	"strings"
	"testing"
)

// 控制端点必须拒绝绑非回环地址——它没有任何鉴权，暴露到公网等于把用户名单
// 交给任何人改。
func TestIsLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:10087", "[::1]:10087", "localhost:10087"} {
		if !isLoopback(addr) {
			t.Errorf("%s 应当被判定为回环", addr)
		}
	}
	for _, addr := range []string{"0.0.0.0:10087", "192.168.1.1:10087", ":10087", "example.com:10087", "坏地址"} {
		if isLoopback(addr) {
			t.Errorf("%s 不该被判定为回环", addr)
		}
	}
}

func TestParseControlUsers(t *testing.T) {
	users, err := parseControlUsers([]controlUser{
		{Name: "alice", SharedKey: strings.Repeat("a", 32)},
		{Name: " bob ", SharedKey: strings.Repeat("b", 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || users[1].Name != "bob" {
		t.Fatalf("名字没被 trim: %+v", users)
	}

	if _, err = parseControlUsers([]controlUser{{Name: "  "}}); err == nil {
		t.Fatal("空名字应当报错")
	}
	if _, err = parseControlUsers([]controlUser{{Name: "a"}, {Name: "a"}}); err == nil {
		t.Fatal("重名应当报错")
	}
	// 空列表是合法的（表示把人都摘掉）
	if users, err = parseControlUsers(nil); err != nil || len(users) != 0 {
		t.Fatalf("空列表应当合法: %v %v", users, err)
	}
}

// 注册表的增删要正确，否则 /health 会报出不存在的入站。
func TestControlRegistry(t *testing.T) {
	controlMu.Lock()
	saved := controlInbounds
	controlInbounds = map[string]*Inbound{}
	controlMu.Unlock()
	t.Cleanup(func() {
		controlMu.Lock()
		controlInbounds = saved
		controlMu.Unlock()
	})

	if tags := controlTags(); len(tags) != 0 {
		t.Fatalf("初始应为空: %v", tags)
	}
	controlMu.Lock()
	controlInbounds["b-tag"] = &Inbound{}
	controlInbounds["a-tag"] = &Inbound{}
	controlMu.Unlock()

	tags := controlTags()
	if len(tags) != 2 || tags[0] != "a-tag" || tags[1] != "b-tag" {
		t.Fatalf("应当按名字排序: %v", tags)
	}
}
