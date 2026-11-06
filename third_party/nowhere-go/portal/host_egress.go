package portal

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/ohmycggk/nowhere-go/wire"
)

func (s *Server) registryForKey(key string) *registry {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	return s.registries[key]
}

func (s *Server) registryForUser(name string) *registry {
	if !s.multiUserMode {
		return s.reg
	}
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	for _, u := range s.users {
		if u.Name == name {
			return s.registries[u.SharedKey]
		}
	}
	return nil
}

// DialEgress lets the host route and account a flow before selecting its exit.
// The username must come from authenticated inbound metadata, never a wire field.
func (s *Server) DialEgress(ctx context.Context, user string, kind wire.FlowKind, target wire.Target) (net.Conn, error) {
	if !s.acceptEgress || s.registryForUser(user) == nil {
		return nil, errors.New("nw3: no Egress for authenticated user")
	}
	a, b := streamPair()
	relayCtx, cancelRelay := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, func() { cancelRelay(); _ = a.Close(); _ = b.Close() })
	go func() {
		defer b.Close()
		defer cancelRelay()
		s.serveViaEgress(ContextWithUser(relayCtx, user), kind, target, &pipe{Reader: b, write: b, closer: b}, nil, 0)
	}()
	result, err := wire.ReadSetupResult(a)
	if !stop() || ctx.Err() != nil {
		cancelRelay()
		_ = a.Close()
		_ = b.Close()
		return nil, context.Canceled
	}
	if err != nil {
		cancelRelay()
		_ = a.Close()
		return nil, err
	}
	if result != wire.SetupReady {
		cancelRelay()
		_ = a.Close()
		return nil, wire.SetupError{Result: result}
	}
	owned := &egressConn{Conn: a, cancel: cancelRelay}
	if kind == wire.FlowUDP {
		return &egressDatagram{owned}, nil
	}
	return owned, nil
}

type egressConn struct {
	net.Conn
	cancel context.CancelFunc
}

func (c *egressConn) Close() error      { c.cancel(); return c.Conn.Close() }
func (c *egressConn) CloseWrite() error { return c.Conn.(interface{ CloseWrite() error }).CloseWrite() }

type egressDatagram struct{ net.Conn }

func (c *egressDatagram) Read(p []byte) (int, error) {
	b, err := wire.ReadUoT(c.Conn)
	if err != nil {
		return 0, err
	}
	return copy(p, b), nil
}
func (c *egressDatagram) Write(p []byte) (int, error) {
	if err := wire.WriteUoT(c.Conn, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Independent directions preserve TCP half-close through the host adapter.
type streamPipe struct {
	net.Conn
	writer net.Conn
}

func streamPair() (net.Conn, net.Conn) {
	ar, bw := net.Pipe()
	br, aw := net.Pipe()
	return &streamPipe{ar, aw}, &streamPipe{br, bw}
}
func (c *streamPipe) Write(p []byte) (int, error)        { return c.writer.Write(p) }
func (c *streamPipe) CloseWrite() error                  { return c.writer.Close() }
func (c *streamPipe) Close() error                       { _ = c.Conn.Close(); return c.writer.Close() }
func (c *streamPipe) SetWriteDeadline(t time.Time) error { return c.writer.SetWriteDeadline(t) }
func (c *streamPipe) SetDeadline(t time.Time) error {
	_ = c.Conn.SetReadDeadline(t)
	return c.writer.SetWriteDeadline(t)
}
