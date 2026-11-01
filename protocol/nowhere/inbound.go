package nowhere

import (
	"context"
	"crypto/tls"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	singtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"

	"github.com/ohmycggk/nowhere-go/portal"
	nowherewire "github.com/ohmycggk/nowhere-go/wire"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.NowhereInboundOptions](registry, C.TypeNowhere, NewInbound)
}

// Inbound 是 Nowhere(nw3) 的 Portal 入站。
//
// 与其它入站的区别：协议握手由 nowhere-go 的 portal 包完成，它需要
// **自己 accept**（portal.Serve(ctx, ln)），所以这里不设 ConnectionHandler，
// 而是把 listener 的底层 net.Listener 交给它。
type Inbound struct {
	inbound.Adapter
	ctx       context.Context
	tlsConfig singtls.ServerConfig
	router    adapter.ConnectionRouterEx
	logger    logger.ContextLogger
	listener  *listener.Listener
	options   option.NowhereInboundOptions
	server    *portal.Server
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NowhereInboundOptions) (adapter.Inbound, error) {
	inb := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeNowhere, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
	}

	// Nowhere 建立在 TLS 之上，没有 TLS 就没有 Portal。
	if options.Egress {
		return nil, E.New("nowhere: egress requires QUIC, which this inbound does not support")
	}
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, E.New("nowhere: TLS is required")
	}
	tlsConfig, err := singtls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	inb.tlsConfig = tlsConfig

	// 凭据在构造期就校验掉，配错了不该等到 Start。
	if _, _, err = resolveCredentials(options); err != nil {
		return nil, err
	}
	if options.ControlAddr != "" && options.ControlAddr != "off" {
		if !isLoopback(options.ControlAddr) {
			return nil, E.New("nowhere: control_addr must be loopback")
		}
		if strings.TrimSpace(options.ControlSecret) == "" {
			return nil, E.New("nowhere: control_secret is required when control_addr is enabled")
		}
	}
	inb.options = options

	inb.listener = listener.New(listener.Options{
		Context: ctx,
		Logger:  logger,
		Network: []string{N.NetworkTCP},
		Listen:  options.ListenOptions,
		// 不设 ConnectionHandler：accept 由 portal 自己做
	})
	return inb, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	h.ctx = scope.Context()
	if err := h.tlsConfig.Start(); err != nil {
		return err
	}
	scope.Add(h.tlsConfig.Close)

	stdTLS, err := portalTLS(h.tlsConfig)
	if err != nil {
		return err
	}
	portalUsers, sharedKey, err := resolveCredentials(h.options)
	if err != nil {
		return err
	}
	morph := true
	if h.options.Morph != nil {
		morph = *h.options.Morph
	}
	server, err := portal.New(portal.Config{
		SharedKey:    sharedKey,
		Users:        portalUsers,
		Morph:        morph,
		TLS:          stdTLS,
		Upstream:     &upstream{router: h.router, ctx: h.ctx, tag: h.Tag()},
		Egress:       h.options.Egress,
		UploadMbps:   h.options.UploadMbps,
		DownloadMbps: h.options.DownloadMbps,
	})
	if err != nil {
		return E.New("nowhere: create portal: ", err)
	}
	h.server = server

	// 控制端点：让面板不重启就能改用户
	controlAddr := h.options.ControlAddr
	if controlAddr == "" {
		controlAddr = "127.0.0.1:10087"
	}
	if controlAddr != "off" && h.options.ControlSecret != "" {
		if err = h.registerControl(controlAddr); err != nil {
			return err
		}
		scope.Add(h.unregisterControl)
	}

	// 这里**不能**用 listener.Start()：它会连自己的 accept 循环一起启动
	// （loopTCPIn 直接调用 connHandler，而本入站没有 connHandler，会空指针崩）。
	// Nowhere 的握手必须由 portal 完成，所以只建监听、把 listener 交出去。
	ln, err := h.listener.ListenTCP()
	if err != nil {
		return err
	}
	scope.Add(h.listener.Close)

	go func() {
		if serveErr := h.server.Serve(h.ctx, ln); serveErr != nil && h.ctx.Err() == nil {
			h.logger.Error("nowhere portal stopped: ", serveErr)
		}
	}()
	return nil
}

// portalTLS 取出 portal 需要的标准库 TLS 配置，并修好 ALPN。
//
// 必须放在 tlsConfig.Start() 之后调用：sing-box 的 Start 会安装
// GetConfigForClient 回调，提前取到的配置还没有它。
func portalTLS(tlsConfig singtls.ServerConfig) (*tls.Config, error) {
	stdTLS, err := tlsConfig.STDConfig()
	if err != nil {
		return nil, E.New("nowhere: build tls config: ", err)
	}
	if err = validateTLS(stdTLS); err != nil {
		return nil, err
	}
	wrapALPN(stdTLS)
	return stdTLS, nil
}

// wrapALPN 让 GetConfigForClient 返回的配置也带上 nw3 的 ALPN 与 TLS1.3 约束。
//
// 为什么必须做：sing-box 的回调实现是 `return serverConfig.config, nil`
// （common/tls/std_server.go），返回的是**原始** config；而 portal 是在
// cfg.TLS.Clone() 出来的副本上设 NextProtos 的——回调把副本整个绕过，
// 结果是握手成功但 NegotiatedProtocol 为空，portal 判定不是 nw3 后
// 静默断开，客户端只看到 TRANSPORT_FAILED，日志里什么都没有。
func wrapALPN(stdTLS *tls.Config) {
	inner := stdTLS.GetConfigForClient
	stdTLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		var base *tls.Config
		if inner != nil {
			var err error
			base, err = inner(hello)
			if err != nil {
				return nil, err
			}
		}
		if base == nil {
			base = stdTLS
		}
		cloned := base.Clone()
		cloned.MinVersion = tls.VersionTLS13
		cloned.MaxVersion = tls.VersionTLS13
		cloned.NextProtos = []string{nowherewire.ALPN}
		cloned.SessionTicketsDisabled = true
		// 返回的配置是最终配置，crypto/tls 不会再回调一次；显式清掉
		// 以免将来有人改成递归调用时绕不出来。
		cloned.GetConfigForClient = nil
		return cloned, nil
	}
}

// validateTLS 检查 portal 必需的最小 TLS 配置。
//
// portal 直接用这个 *tls.Config 做 tls.Server()，没有证书会握手必败，
// 而失败发生在连接期、日志里只是一堆握手错误——不如启动时就报清楚。
func validateTLS(config *tls.Config) error {
	if len(config.Certificates) == 0 && config.GetCertificate == nil && config.GetConfigForClient == nil {
		return E.New("nowhere: tls certificate is required")
	}
	return nil
}

// resolveCredentials 决定 Portal 的凭据形态：单密钥还是多用户。
//
// nw3 的 AuthFrame 不带身份字段，多用户靠「逐个试解」识别：
// 开了 Morph 时试 prelude，否则试 AuthFrame 本身（两者都是定长 + 纯校验）。
func resolveCredentials(options option.NowhereInboundOptions) ([]portal.User, string, error) {
	if options.SharedKey != "" && len(options.Users) > 0 {
		return nil, "", E.New("nowhere: shared_key and users are mutually exclusive")
	}
	if len(options.Users) > 0 {
		users := make([]portal.User, 0, len(options.Users))
		names, keys := map[string]bool{}, map[string]bool{}
		for i, u := range options.Users {
			if err := nowherewire.ValidateServiceKey(u.SharedKey); err != nil {
				return nil, "", E.Cause(err, "nowhere: users[", i, "]")
			}
			if strings.TrimSpace(u.Name) != u.Name || u.Name == "" || names[u.Name] || keys[u.SharedKey] {
				return nil, "", E.New("nowhere: users require unique nonempty names and keys")
			}
			names[u.Name], keys[u.SharedKey] = true, true
			users = append(users, portal.User{Name: u.Name, SharedKey: u.SharedKey})
		}
		return users, "", nil
	}
	if options.SharedKey == "" {
		return nil, "", E.New("nowhere: shared_key or users is required")
	}
	if err := nowherewire.ValidateServiceKey(options.SharedKey); err != nil {
		return nil, "", err
	}
	return nil, options.SharedKey, nil
}
