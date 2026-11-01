package nowhere

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/ohmycggk/nowhere-go/portal"
	"github.com/ohmycggk/nowhere-go/wire"
)

// upstream 把 nowhere Portal 的「拉模型」上游接到 sing-box 的「推模型」路由上。
//
// portal.Upstream 要求我们自己拨号并把 net.Conn 交回去：
//
//	DialTCP(ctx, target) (net.Conn, error)
//
// 而 sing-box 的 router 是反过来的——我们给它一个 conn，它去路由：
//
//	RouteConnectionEx(ctx, conn, metadata, onClose)
//
// 两者用 net.Pipe() 桥接：拿到的其中一端交给 router，另一端还给 portal。
// portal 往这端写什么，router 就从那端读到什么。
//
// UDP 暂时走 portal.Direct（直连），因为 net.Pipe 是流式的，
// 承载不了 datagram 语义。要让 Nowhere 的 UDP 也吃上 sing-box 路由，
// 需要一对本地 UDP socket 做桥，见 TODO。
type upstream struct {
	portal.Direct
	router adapter.ConnectionRouterEx
	logger logger.ContextLogger
}

// DialTCP 通过 sing-box 路由建立到 target 的连接。
func (u *upstream) DialTCP(ctx context.Context, target wire.Target) (net.Conn, error) {
	destination := targetSocksaddr(target)
	client, server := net.Pipe()

	var metadata adapter.InboundContext
	metadata.Inbound = "nowhere"
	metadata.InboundType = "nowhere"
	metadata.Destination = destination
	// portal 在试解 prelude/AuthFrame 时确定了用户身份，带进来之后
	// sing-box 的连接元数据、路由规则和统计都能看到这个用户。
	if user := portal.UserFromContext(ctx); user != "" {
		metadata.User = user
	}

	go func() {
		u.router.RouteConnectionEx(ctx, server, metadata, func(err error) {
			_ = server.Close()
		})
	}()
	return client, nil
}

// targetSocksaddr 把 nowhere 的 wire.Target 翻译成 sing-box 的 Socksaddr。
//
// wire.Target 要么带 Addr（IP 直连），要么带 Host（域名），不会同时有。
func targetSocksaddr(target wire.Target) M.Socksaddr {
	if target.Host != "" {
		return M.ParseSocksaddrHostPort(target.Host, target.Port)
	}
	return M.Socksaddr{
		Fqdn: "",
		Addr: target.Addr,
		Port: target.Port,
	}
}
