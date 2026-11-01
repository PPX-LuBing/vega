package nowhere

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ohmycggk/nowhere-go/portal"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// 控制端点即使有令牌也只能绑定回环，避免暴露管理面。
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

func TestControlAuthenticationValidationAndCleanup(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	newInbound := func(tag string) *Inbound {
		server, err := portal.New(portal.Config{Users: []portal.User{{Name: "alice", SharedKey: testKeyAlice}}, TLS: &tls.Config{}, Upstream: portal.Direct{}})
		if err != nil {
			t.Fatal(err)
		}
		return &Inbound{Adapter: inbound.NewAdapter("nowhere", tag), ctx: context.Background(), logger: log.NewNOPFactory().NewLogger("test"), server: server,
			options: option.NowhereInboundOptions{Users: []option.NowhereUser{{Name: "alice", SharedKey: testKeyAlice}}, ControlAddr: addr, ControlSecret: "test-secret"}}
	}
	first := newInbound("first")
	if err = first.registerControl(addr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.unregisterControl() })
	request := func(body, auth string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/users", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	valid := fmt.Sprintf(`{"inbound":"first","users":[{"name":"alice","shared_key":"%s"}]}`, testKeyAlice)
	for _, auth := range []string{"", "Bearer wrong"} {
		if got := request(valid, auth); got != http.StatusUnauthorized {
			t.Fatalf("unauthorized request: %d", got)
		}
	}
	for _, body := range []string{`{}`, `{"users":null}`, `{"users":[],"unknown":true}`, `{"users":[]} {}`, `{"users":[{"name":"alice","shared_key":"bad"}]}`} {
		if got := request(body, "Bearer test-secret"); got != http.StatusBadRequest {
			t.Fatalf("body %s: %d", body, got)
		}
	}
	if got := request(valid, "Bearer test-secret"); got != http.StatusOK {
		t.Fatal(got)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = controlTags()
		}
	}()
	for i := 0; i < 30; i++ {
		h := newInbound(fmt.Sprint("n", i))
		if err = h.registerControl(addr); err != nil {
			t.Fatal(err)
		}
		if err = h.unregisterControl(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	if err = first.unregisterControl(); err != nil {
		t.Fatal(err)
	}
	if len(controlTags()) != 0 {
		t.Fatal("stale inbounds")
	}
	if err = first.registerControl(addr); err != nil {
		t.Fatalf("endpoint not released: %v", err)
	}
}

func TestMissingUsersDoesNotClearRegistry(t *testing.T) {
	w := httptest.NewRecorder()
	handleControlUsers(w, httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatal(w.Code)
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
