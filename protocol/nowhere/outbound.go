package nowhere

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/ohmycggk/nowhere-go/vector"
	"github.com/ohmycggk/nowhere-go/wire"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.NowhereOutboundOptions](registry, C.TypeNowhere, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

// Outbound 是 Nowhere(nw3) 的 Vector 出站。
//
// 复用 Vector 的认证和 Morph 状态；TCP+TLS 载体仍按官方协议每条 flow
// 单独握手，不引入私有连接复用格式。
type Outbound struct {
	outbound.Adapter
	ctx    context.Context
	logger log.ContextLogger
	client *vector.Client
}

func NewOutbound(ctx context.Context, _ adapter.Router, logger log.ContextLogger, tag string, options option.NowhereOutboundOptions) (adapter.Outbound, error) {
	if options.SharedKey == "" {
		return nil, E.New("nowhere: 出站需要 shared_key")
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	// 载体：TCP + TLS1.3。ALPN 必须是 nw3，否则服务端会当成普通
	// TLS 流量丢掉；这个由 vector 在 Clone 出来的副本上设置。
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, E.New("nowhere: 出站需要启用 TLS")
	}
	clientConfig, err := tls.NewClient(ctx, logger, options.ServerOptions.Build().String(), common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	tlsConfig, err := clientConfig.STDConfig()
	if err != nil {
		return nil, E.Cause(err, "nowhere: 构建 TLS 配置失败")
	}

	portalAddr := options.ServerOptions.Build().String()
	client, err := vector.New(vector.Config{
		SharedKey:  options.SharedKey,
		Morph:      options.Morph == nil || *options.Morph,
		PortalAddr: portalAddr,
		TLS:        tlsConfig,
		DialTCP: func(dialCtx context.Context, addr string) (net.Conn, error) {
			return outboundDialer.DialContext(dialCtx, N.NetworkTCP, M.ParseSocksaddr(addr))
		},
		UploadMbps:   options.UploadMbps,
		DownloadMbps: options.DownloadMbps,
	})
	if err != nil {
		return nil, E.Cause(err, "nowhere: 建立 Vector 失败")
	}

	return &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeNowhere, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:     ctx,
		logger:  logger,
		client:  client,
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination

	target := wireTarget(destination)
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "nowhere flow (tcp) to ", destination)
		return h.client.OpenTCP(ctx, target)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "nowhere flow (udp) to ", destination)
		return h.client.OpenUDP(ctx, target)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

// ListenPacket 返回一个能发往任意目标的 PacketConn。
//
// nw3 的每个 flow 是绑定到单个目标的（不像 shadowsocks 的 UDP 那样在
// 一个连接里带目标地址），所以这里按目标惰性开 flow 并缓存：同一个目标
// 复用同一条 flow，不同目标各开一条。
func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "nowhere packet connection")
	return newPacketConn(ctx, destination, h.client.OpenUDP), nil
}

func (h *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	if h.client != nil {
		scope.Add(func() error { return h.client.Close() })
	}
	return nil
}

// wireTarget 把 sing-box 的目标地址转成 nw3 的目标。
//
// 域名要保持是域名：让服务端去解析，客户端解析会把 DNS 暴露在本地，
// 也让服务端的分流规则（按域名）失效。
func wireTarget(destination M.Socksaddr) wire.Target {
	// 用 Addr 是否有效来区分，不用已废弃的 IsFqdn：后者会拒绝掉一些
	// 其实合法的域名写法，反而把能用的目标判成 IP。
	if destination.Addr.IsValid() {
		return wire.Target{Addr: destination.Addr, Port: destination.Port}
	}
	return wire.Target{Host: destination.Fqdn, Port: destination.Port}
}
