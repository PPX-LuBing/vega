package nowhere

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/ohmycggk/nowhere-go/portal"
	"github.com/ohmycggk/nowhere-go/wire"
)

type upstream struct {
	router adapter.ConnectionRouterEx
	ctx    context.Context
	tag    string
}

func (u *upstream) metadata(ctx context.Context, target wire.Target) adapter.InboundContext {
	return adapter.InboundContext{
		Inbound: u.tag, InboundType: "nowhere",
		Destination: targetSocksaddr(target), User: portal.UserFromContext(ctx),
		Source: M.SocksaddrFromNet(portal.SourceFromContext(ctx)),
	}
}

func (u *upstream) DialTCP(ctx context.Context, target wire.Target) (net.Conn, error) {
	client, server := streamPair()
	stop := context.AfterFunc(u.ctx, func() { _ = client.Close(); _ = server.Close() })
	go u.router.RouteConnectionEx(ctx, server, u.metadata(ctx, target), func(error) {
		stop()
		_ = client.Close()
		_ = server.Close()
	})
	return client, nil
}

func (u *upstream) DialUDP(ctx context.Context, target wire.Target) (net.Conn, error) {
	client, server := net.Pipe()
	stop := context.AfterFunc(u.ctx, func() { _ = client.Close(); _ = server.Close() })
	metadata := u.metadata(ctx, target)
	packet := bufio.NewUnbindPacketConnWithAddr(&datagramConn{Conn: server}, metadata.Destination)
	go u.router.RoutePacketConnectionEx(ctx, packet, metadata, func(error) {
		stop()
		_ = client.Close()
		_ = server.Close()
	})
	return &datagramConn{Conn: client}, nil
}

// Each direction has its own pipe so an EOF does not discard the response.
type streamConn struct {
	net.Conn
	writer net.Conn
}

func streamPair() (net.Conn, net.Conn) {
	aRead, bWrite := net.Pipe()
	bRead, aWrite := net.Pipe()
	return &streamConn{Conn: aRead, writer: aWrite}, &streamConn{Conn: bRead, writer: bWrite}
}

func (c *streamConn) Write(p []byte) (int, error)        { return c.writer.Write(p) }
func (c *streamConn) CloseWrite() error                  { return c.writer.Close() }
func (c *streamConn) Close() error                       { _ = c.Conn.Close(); return c.writer.Close() }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.writer.SetWriteDeadline(t) }
func (c *streamConn) SetDeadline(t time.Time) error {
	if err := c.Conn.SetReadDeadline(t); err != nil {
		return err
	}
	return c.writer.SetWriteDeadline(t)
}

// Preserve UDP packet boundaries across the in-memory byte stream.
type datagramConn struct {
	net.Conn
	readMu, writeMu sync.Mutex
}

func (c *datagramConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	packet, err := wire.ReadUoT(c.Conn)
	if err != nil {
		return 0, err
	}
	// 缓冲区装不下时**截断**，不返回 io.ErrShortBuffer。
	//
	// ReadUoT 已经把整个包从流里读出来了，此时再报错就等于把这一份
	// 报文静默丢掉；而调用方看到错误通常会重试，重试拿到的却是下一
	// 个包，数据就串位了。截断是 UDP 的常规语义（net.UDPConn.Read
	// 也是这么做的），至少不会破坏流的边界。
	if len(packet) > len(p) {
		return copy(p, packet), nil
	}
	return copy(p, packet), nil
}

func (c *datagramConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := wire.WriteUoT(c.Conn, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

var _ N.WriteCloser = (*streamConn)(nil)

func targetSocksaddr(target wire.Target) M.Socksaddr {
	if target.Host != "" {
		return M.ParseSocksaddrHostPort(target.Host, target.Port)
	}
	return M.Socksaddr{Addr: target.Addr, Port: target.Port}
}
