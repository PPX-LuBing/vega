package nowhere

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ohmycggk/nowhere-go/portal"
)

// 控制端点：让面板在**不重启内核**的前提下增删用户。
//
// sing-box 原生没有这个能力——改用户只能改配置再重启，所有人断线一次。
// Nowhere 的认证是「逐个试解密钥」，本来就不需要重启：换一份名单，
// 新连接按新名单认证，老连接按原样跑完。
//
// 为什么是进程级而不是每个入站一个：一台机器上通常有多个 nowhere 入站
// （不同端口/不同证书），如果各自绑一个端口，第二个就会 bind 失败。
// 所以由第一个启动的入站负责监听，其余注册进来，请求里用 inbound 字段定向。
//
// 安全边界：只监听本机回环。和内核自己的 clash_api / v2ray_api 一个级别
// （它们同样没有鉴权），能连上回环的人本来就能读配置文件。

var (
	controlMu       sync.Mutex
	controlInbounds = map[string]*Inbound{} // tag -> 入站
	controlServer   *http.Server
	controlListen   string
)

// controlUser 是控制端点接收的用户条目。
type controlUser struct {
	Name      string `json:"name"`
	SharedKey string `json:"shared_key"`
}

type controlRequest struct {
	// Inbound 指定只改哪个入站；留空表示改全部已注册的 nowhere 入站。
	Inbound string        `json:"inbound,omitempty"`
	Users   []controlUser `json:"users"`
}

type controlResponse struct {
	OK      bool     `json:"ok"`
	Updated []string `json:"updated,omitempty"`
	Users   int      `json:"users,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// registerControl 把本入站登记进共享控制端点，必要时负责监听。
func (h *Inbound) registerControl(addr string) error {
	if strings.TrimSpace(addr) == "" || addr == "off" {
		return nil
	}
	if !isLoopback(addr) {
		return fmt.Errorf("nowhere: control_addr 必须绑回环（收到 %q）", addr)
	}

	controlMu.Lock()
	defer controlMu.Unlock()

	controlInbounds[h.Tag()] = h
	if controlServer != nil {
		// 已经有端点在跑：确认地址一致就够了（不一致说明配置自相矛盾）
		if controlListen != addr {
			return fmt.Errorf("nowhere: 控制端点已监听 %s，入站 %s 却要求 %s（同一进程内必须一致）",
				controlListen, h.Tag(), addr)
		}
		h.logger.Info("nowhere: 入站 ", h.Tag(), " 已登记到控制端点 ", addr)
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/users", handleControlUsers)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeControl(w, http.StatusOK, controlResponse{OK: true, Updated: controlTags()})
	})

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		delete(controlInbounds, h.Tag())
		return fmt.Errorf("nowhere: 控制端点监听失败: %w", err)
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	controlServer = server
	controlListen = addr

	go func() { _ = server.Serve(listener) }()
	go func() {
		<-h.ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		controlMu.Lock()
		controlServer = nil
		controlListen = ""
		controlMu.Unlock()
		_ = server.Shutdown(shutdownCtx)
	}()

	h.logger.Info("nowhere: 控制端点在 ", addr, "（POST /users 可不重启改用户）")
	return nil
}

func controlTags() []string {
	out := make([]string, 0, len(controlInbounds))
	for tag := range controlInbounds {
		out = append(out, tag)
	}
	sort.Strings(out)
	return out
}

func handleControlUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		writeControl(w, http.StatusMethodNotAllowed, controlResponse{Error: "只接受 POST"})
		return
	}
	var request controlRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil {
		writeControl(w, http.StatusBadRequest, controlResponse{Error: "请求体不是合法 JSON: " + err.Error()})
		return
	}

	users, err := parseControlUsers(request.Users)
	if err != nil {
		writeControl(w, http.StatusBadRequest, controlResponse{Error: err.Error()})
		return
	}

	controlMu.Lock()
	targets := make([]*Inbound, 0, len(controlInbounds))
	if request.Inbound != "" {
		target, ok := controlInbounds[request.Inbound]
		if !ok {
			controlMu.Unlock()
			writeControl(w, http.StatusNotFound, controlResponse{
				Error: fmt.Sprintf("没有这个 nowhere 入站: %s（现有：%s）",
					request.Inbound, strings.Join(controlTags(), ", "))})
			return
		}
		targets = append(targets, target)
	} else {
		for _, target := range controlInbounds {
			targets = append(targets, target)
		}
	}
	controlMu.Unlock()

	if len(targets) == 0 {
		writeControl(w, http.StatusServiceUnavailable, controlResponse{Error: "没有已注册的 nowhere 入站"})
		return
	}

	// 逐个改：任一失败就如实汇报，不假装全部成功
	updated := make([]string, 0, len(targets))
	for _, target := range targets {
		if err = target.server.UpdateUsers(users); err != nil {
			writeControl(w, http.StatusBadRequest, controlResponse{
				Error: fmt.Sprintf("入站 %s 更新失败: %v", target.Tag(), err), Updated: updated})
			return
		}
		target.logger.Info("nowhere: 用户名单已更新为 ", len(users), " 人（未重启）")
		updated = append(updated, target.Tag())
	}
	sort.Strings(updated)
	writeControl(w, http.StatusOK, controlResponse{OK: true, Updated: updated, Users: len(users)})
}

// parseControlUsers 校验并归一化请求里的用户列表。
func parseControlUsers(items []controlUser) ([]portal.User, error) {
	users := make([]portal.User, 0, len(items))
	seen := map[string]bool{}
	for i, item := range items {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			return nil, fmt.Errorf("第 %d 个用户没有名字", i)
		}
		if seen[name] {
			return nil, fmt.Errorf("用户名重复: %s", name)
		}
		seen[name] = true
		users = append(users, portal.User{Name: name, SharedKey: item.SharedKey})
	}
	return users, nil
}

func writeControl(w http.ResponseWriter, status int, payload controlResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// isLoopback 判断监听地址是否只绑回环。
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}
