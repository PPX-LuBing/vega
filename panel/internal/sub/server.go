package sub

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/cert"
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

	// 以下是 ACME 自动签发。全留空表示不启用，TLS 交给前面的反代。
	// 启用时 ACMEDomain 必填，服务会自己开 443 和 80。
	ACMEDomain   string
	ACMEEmail    string
	ACMECacheDir string
	// ACMECertDir 是面板统一管理的证书目录：签发/续期后会把稳定的 PEM 写到
	// <ACMECertDir>/<域名>/{cert.pem,key.pem}，内核节点直接读同一份文件。
	ACMECertDir string
	// OnCertChange 在稳定证书文件内容变化后调用（同步），用来重启内核——
	// sing-box 只在启动时读证书文件，不重启不生效。
	OnCertChange func(cert.Change)
	// ACMEHTTPAddr 是 HTTP-01 挑战与跳转用的地址，默认 :80。
	ACMEHTTPAddr string
	// ACMETLSAddr 是 HTTPS 监听地址，默认 :443。
	ACMETLSAddr string
	CertFile    string
	KeyFile     string
}

// Serve 起订阅 HTTP 服务，ctx 结束时优雅关闭。
func Serve(ctx context.Context, st *store.Store, cfg Config) error {
	if cfg.Interval <= 0 {
		cfg.Interval = 12 * time.Hour
	}
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return fmt.Errorf("TLS requires both certificate and key")
	}
	if cfg.ACMEDomain != "" && cfg.CertFile != "" {
		return fmt.Errorf("choose ACME or certificate files, not both")
	}
	addr := cfg.Listen
	if cfg.ACMEDomain != "" || cfg.CertFile != "" {
		addr = cfg.ACMETLSAddr
		if addr == "" {
			addr = ":443"
		}
	}
	if addr == "" {
		return fmt.Errorf("subscription listen address is required")
	}
	h := &handler{st: st, cfg: cfg}
	mux := http.NewServeMux()
	mux.HandleFunc("/sub/", h.subscription)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "vega sub ok") })
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	var challenge *http.Server
	var challengeListener net.Listener
	var manager *cert.Manager
	if cfg.ACMEDomain != "" {
		if cfg.ACMECacheDir == "" {
			return fmt.Errorf("ACME requires acme_cache")
		}
		if cfg.ACMECertDir == "" {
			return fmt.Errorf("ACME requires cert_dir")
		}
		if err := os.MkdirAll(cfg.ACMECacheDir, 0700); err != nil {
			return err
		}
		base, err := url.Parse(cfg.Base)
		if err != nil || base.Scheme != "https" || base.Hostname() != cfg.ACMEDomain || base.User != nil {
			return fmt.Errorf("ACME base must be an HTTPS URL for the configured domain")
		}
		manager, err = cert.New(cert.Config{
			Domain:   cfg.ACMEDomain,
			Email:    cfg.ACMEEmail,
			CacheDir: cfg.ACMECacheDir,
			CertDir:  cfg.ACMECertDir,
			OnChange: cfg.OnCertChange,
		})
		if err != nil {
			return err
		}
		server.TLSConfig = manager.TLSConfig()
		challenge = &http.Server{Handler: manager.HTTPHandler(httpsRedirect(base)), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
		httpAddr := cfg.ACMEHTTPAddr
		if httpAddr == "" {
			httpAddr = ":80"
		}
		challengeListener, err = net.Listen("tcp", httpAddr)
		if err != nil {
			return fmt.Errorf("ACME HTTP listen: %w", err)
		}
		defer challengeListener.Close()
	} else if cfg.CertFile != "" {
		pair, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("load subscription certificate: %w", err)
		}
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("subscription listen: %w", err)
	}
	defer listener.Close()
	servers := []*http.Server{server}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, srv := range servers {
			if err := srv.Shutdown(shutdown); err != nil {
				_ = srv.Close()
			}
		}
	}()
	failures := make(chan error, 2)
	if challenge != nil {
		servers = append(servers, challenge)
		go func() { failures <- challenge.Serve(challengeListener) }()
	}
	if manager != nil {
		// 挑战监听起来之后再碰 ACME。顺序是：先把缓存里已有的证书落成稳定
		// 文件（升级场景：证书是升级前签的，缓存里有、稳定文件没有），再走
		// 一遍取证书流程，把 autocert 自己的续期定时器挂上——不挂的话，
		// 证书到期前没人续。放 goroutine 是因为首次签发要等 ACME 来回。
		go func() {
			if _, err := manager.Sync(ctx); err != nil {
				log.Printf("ACME: 同步稳定证书文件失败: %v", err)
			}
			if err := manager.Arm(); err != nil {
				log.Printf("ACME: %v", err)
			}
		}()
	}
	useTLS := server.TLSConfig != nil
	go func() {
		if useTLS {
			failures <- server.ServeTLS(listener, "", "")
		} else {
			failures <- server.Serve(listener)
		}
	}()
	log.Printf("subscription listening on %s (TLS=%t)", listener.Addr(), useTLS)
	select {
	case <-ctx.Done():
		return nil
	case err := <-failures:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func httpsRedirect(base *url.URL) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := *base
		target.Path, target.RawPath, target.RawQuery = r.URL.Path, r.URL.RawPath, r.URL.RawQuery
		http.Redirect(w, r, target.String(), http.StatusMovedPermanently)
	})
}

type handler struct {
	st  *store.Store
	cfg Config
}

// subscription 处理 /sub/<token>[/<format>]。
//
// The path contains a bearer credential; reverse proxies must redact access logs.
func (h *handler) subscription(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "只接受 GET", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/sub/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || len(parts) > 2 || parts[0] == "" {
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

	if format == "" && wantsAJSON(r) {
		// Anywhere 会主动带这个头来要它自己的格式。裸地址按 UA 猜是猜不出来的：
		// 它带过来的 UA 也叫 Anywhere，而老版本不带这个头、只看得懂别的格式。
		format = "ajson"
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
	case "plain", "base64":
		body, skipped, err = Links(h.st, user, format == "base64")
	case "nowhere", "nw3":
		body, skipped, err = Nowhere(h.st, user)
	case "ajson", "anywhere":
		body, skipped, err = AJSON(h.st, user)
	default:
		http.Error(w, "未知格式 "+format+"，用 clash、singbox、nowhere 或 ajson", http.StatusNotFound)
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
	w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte(h.st.Setting("sub_title", "Vega"))))
	// clash / mihomo 读这个头在节点列表里显示用量
	w.Header().Set("Subscription-Userinfo", h.userinfo(user))
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body))
	}
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

// wantsAJSON 判断客户端是不是在要 Anywhere 的 AJSON 格式。
//
// 官方约定：请求带 X-Anywhere-Format: ajson/1 时服务端「可以」回 AJSON 文档；
// 老版本 Anywhere 不带这个头，就继续给它看得懂的格式（Clash / link-list），
// 所以这里只认这个头，不去猜 User-Agent。
func wantsAJSON(r *http.Request) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(r.Header.Get("X-Anywhere-Format"))), "ajson")
}

func contentTypeFor(format string) string {
	switch format {
	case "clash", "mihomo", "yaml":
		return "text/yaml; charset=utf-8"
	case "nowhere", "nw3", "plain", "base64":
		// 纯文本 URI 列表，不是 YAML 也不是 JSON
		return "text/plain; charset=utf-8"
	default:
		return "application/json; charset=utf-8"
	}
}
