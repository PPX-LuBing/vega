package nowhere

import (
	"context"
	"net"
	"sync"
	"time"

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
// 一个 Vector 就是一条到 Portal 的载体（TCP+TLS 或 QUIC），上面可以开
// 任意多条 flow。所以这里持有的是**一个长期存在的 client**，而不是每次
// 拨号都握手一遍——握手要跑 TLS1.3 + Morph + AuthFrame，每次新建连接都
// 做一遍会让短连接场景慢得没法用。
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
		Morph:      common.PtrValueOrDefault(options.Morph),
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
	return &packetConn{ctx: ctx, outbound: h, ready: make(chan struct{})}, nil
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

// packetConn 把「按目标开 flow」包装成 sing-box 要的 net.PacketConn。
type packetConn struct {
	ctx      context.Context
	outbound *Outbound

	mu    sync.Mutex
	flows map[string]net.Conn
	order []string
	// ready 在第一条 flow 建好时关闭，readyDone 防止重复关闭。
	//
	// 为什么需要它：sing-box 的 packet 下载循环是**立刻**启动的，所以第一次
	// ReadFrom 必然早于第一次 WriteTo（WriteTo 才会建 flow）。那时候如果
	// ReadFrom 返回错误，route/conn.go 的 packetConnectionCopy 会
	// `common.Close(source, destination)` 把整个 UDP 会话两个方向一起关掉，
	// 表现就是 UDP 静默不通、而且服务端日志里什么都没有。所以这里必须**等**。
	ready     chan struct{}
	readyDone bool
}

// maxCachedFlows 限制缓存的目标数。
//
// 不设上限的话，一个扫描型应用（比如 BT、端口扫描）能把 flow 数量顶到
// 几千条，每条都占着服务端的会话。超出就丢最旧的。
const maxCachedFlows = 64

func (c *packetConn) flowFor(destination M.Socksaddr) (net.Conn, error) {
	key := destination.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.flows == nil {
		c.flows = make(map[string]net.Conn)
	}
	if conn, ok := c.flows[key]; ok {
		return conn, nil
	}
	conn, err := c.outbound.client.OpenUDP(c.ctx, wireTarget(destination))
	if err != nil {
		return nil, err
	}
	c.flows[key] = conn
	c.order = append(c.order, key)
	if !c.readyDone {
		// 第一条 flow 建好了，唤醒可能正阻塞在 ReadFrom 的下载循环
		c.readyDone = true
		close(c.ready)
	}
	if len(c.order) > maxCachedFlows {
		oldest := c.order[0]
		c.order = c.order[1:]
		if old, ok := c.flows[oldest]; ok {
			_ = old.Close()
			delete(c.flows, oldest)
		}
	}
	return conn, nil
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	// nw3 的 flow 是单向绑定的，读回来的数据不带来源地址。
	// 这里只能返回一个空地址，调用方（内核的 UDP 会话）本来就按
	// 自己记录的目标来配，不会依赖它。
	conn := c.firstFlow()
	if conn == nil {
		// 还没写过任何目标。**必须等第一条 flow 建起来**，不能返回错误：
		// 读方向的 error 会被 route/conn.go 当成会话结束，连写方向一起关掉，
		// 结果就是 UDP 完全不通（详见 packetConn.ready 的注释）。
		select {
		case <-c.ready:
			conn = c.firstFlow()
		case <-c.ctx.Done():
			return 0, nil, c.ctx.Err()
		}
	}
	if conn == nil {
		// ready 已关却还是没有 flow：只可能是缓存淘汰时刚好清空。
		// 这里再等 ctx 结束，避免空转刷 CPU。
		<-c.ctx.Done()
		return 0, nil, c.ctx.Err()
	}
	n, err := conn.Read(p)
	if err != nil {
		return 0, nil, err
	}
	return n, M.Socksaddr{}, nil
}

// firstFlow 返回缓存里最早的那条 flow，没有就返回 nil。
func (c *packetConn) firstFlow() net.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, key := range c.order {
		if candidate := c.flows[key]; candidate != nil {
			return candidate
		}
	}
	return nil
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(addr)
	if !destination.IsValid() {
		// 有些调用方传的是零值地址，此时退回 ctx 里带的目标
		destination = M.Socksaddr{}
	}
	conn, err := c.flowFor(destination)
	if err != nil {
		return 0, err
	}
	return conn.Write(p)
}

func (c *packetConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, conn := range c.flows {
		_ = conn.Close()
		delete(c.flows, key)
	}
	c.order = nil
	return nil
}

func (c *packetConn) LocalAddr() net.Addr { return M.Socksaddr{} }

func (c *packetConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, conn := range c.flows {
		_ = conn.SetDeadline(t)
	}
	return nil
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, conn := range c.flows {
		_ = conn.SetReadDeadline(t)
	}
	return nil
}

func (c *packetConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, conn := range c.flows {
		_ = conn.SetWriteDeadline(t)
	}
	return nil
}
