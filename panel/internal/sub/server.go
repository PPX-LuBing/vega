package sub

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/kernel"
	"github.com/PPX-LuBing/vega/panel/internal/store"
)

// Config 是订阅服务的运行参数。
type Config struct {
	// Listen 是监听地址，如 127.0.0.1:8080。反代（nginx/caddy）放前面时绑回环。
	Listen string
	// Base 是订阅地址的前缀，如 https://sub.example.com。
	// 它决定了客户端拿到的 URL 长什么样，也用于日志里回显。
	Base string
	// Interval 是客户端多久来拉一次，默认 12 小时。
	Interval time.Duration
}

// Serve 起订阅 HTTP 服务，ctx 结束时优雅关闭。
func Serve(ctx context.Context, st *store.Store, cfg Config) error {
	if cfg.Listen == "" {
		return fmt.Errorf("订阅服务缺少 listen 地址")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 12 * time.Hour
	}
	handler := &handler{st: st, cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("/sub/", handler.subscription)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("vega sub ok\n"))
	})

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("订阅服务监听 %s 失败: %w", cfg.Listen, err)
	}
	log.Printf("订阅服务在 %s（base=%s）", cfg.Listen, cfg.Base)

	go func() { _ = server.Serve(listener) }()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(shutdownCtx)
}

type handler struct {
	st  *store.Store
	cfg Config
}

// subscription 处理 /sub/<token>[/<format>]。
//
// token 放在路径里而不是查询串：查询串更容易被日志和 Referer 带出去，
// 而且路径形式对各类客户端的自定义订阅地址更友好。
func (h *handler) subscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "只接受 GET", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/sub/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "缺少订阅 token", http.StatusNotFound)
		return
	}
	token := parts[0]
	format := ""
	if len(parts) > 1 {
		format = strings.ToLower(parts[1])
	}

	user, err := h.st.UserBySubToken(token)
	if err != nil {
		// 不回显 token，避免它被写进别人的日志
		http.Error(w, "订阅地址无效", http.StatusNotFound)
		return
	}

	// 三道闸门在这里也要过一遍：订阅是客户端拿到节点的唯一途径，
	// 不在这里挡，停用/过期/超额的用户照样能拿到配置去连。
	if reason := h.blocked(user); reason != "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.Error(w, reason, http.StatusForbidden)
		return
	}

	if format == "" {
		format = formatFor(r.UserAgent())
	}

	var (
		body    string
		skipped []string
	)
	switch format {
	case "clash", "mihomo", "yaml":
		body, skipped, err = Clash(h.st, user)
	case "singbox", "sing-box", "json":
		body, skipped, err = Singbox(h.st, user)
	default:
		http.Error(w, "未知格式 "+format+"，用 clash 或 singbox", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	if len(skipped) > 0 {
		log.Printf("订阅 %s(%s) 跳过了 %d 个节点: %s", user.Name, format, len(skipped), strings.Join(skipped, "; "))
	}

	w.Header().Set("Content-Type", contentTypeFor(format))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Profile-Update-Interval", fmt.Sprint(int(h.cfg.Interval.Hours())))
	// clash / mihomo 读这个头在节点列表里显示用量
	w.Header().Set("Subscription-Userinfo", h.userinfo(user))
	_, _ = w.Write([]byte(body))
}

// blocked 返回空串表示放行，否则返回给客户端看的原因。
//
// 和内核侧的 kernel.Usable 是同一套规则——两边判断不一致的话会出现
// 「内核里已经摘掉了，订阅里还发着」这种自相矛盾的状态。
func (h *handler) blocked(u store.User) string {
	up, down, err := h.st.Usage(u.Name)
	if err != nil {
		return "读不到该用户的用量，拒绝下发"
	}
	switch kernel.EvaluateUser(u, up+down, time.Now()) {
	case kernel.UserStateDisabled:
		return "该用户已被停用"
	case kernel.UserStateExpired:
		return "该用户的订阅已过期"
	case kernel.UserStateOverQuota:
		return "该用户已超出配额"
	}
	return ""
}

// userinfo 生成 clash 用的用量头：upload;download;total;expire
//
// 0 表示不限量 / 不过期，这是 clash 的约定。
func (h *handler) userinfo(u store.User) string {
	up, down, err := h.st.Usage(u.Name)
	if err != nil {
		up, down = 0, 0
	}
	return fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", up, down, u.QuotaBytes, u.ExpiresAt)
}

// formatFor 按 User-Agent 猜客户端想要的格式。
//
// 猜错的代价只是拿到一份用不了的配置，客户端会报错，用户可以显式带
// /clash 或 /singbox 纠正，所以这里不需要太聪明。
func formatFor(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "sing-box"), strings.Contains(ua, "singbox"),
		strings.Contains(ua, "sfa"), strings.Contains(ua, "sfi"), strings.Contains(ua, "sfm"):
		return "singbox"
	default:
		// clash / mihomo / stash / clash-verge / flclash 等一律走 clash 格式，
		// 它是这个生态里兼容面最广的
		return "clash"
	}
}

func contentTypeFor(format string) string {
	if format == "clash" || format == "mihomo" || format == "yaml" {
		return "text/yaml; charset=utf-8"
	}
	return "application/json; charset=utf-8"
}
