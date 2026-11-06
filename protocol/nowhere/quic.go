//go:build with_quic

package nowhere

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/ohmycggk/nowhere-go/morph"
	"github.com/ohmycggk/nowhere-go/qio"
	nruntime "github.com/ohmycggk/nowhere-go/runtime"
	"github.com/ohmycggk/nowhere-go/wire"
	quic "github.com/sagernet/quic-go"
)

func init() {
	quicAvailable = true
	dialQUIC = dialNowhereQUIC
	listenQUIC = listenNowhereQUIC
}

func quicConfig(rt nruntime.Settings) *quic.Config {
	return &quic.Config{
		Versions: []quic.Version{quic.Version1}, EnableDatagrams: true, Allow0RTT: false,
		HandshakeIdleTimeout: rt.HandshakeTimeout, MaxIdleTimeout: rt.UDPIdleTimeout, KeepAlivePeriod: rt.UDPIdleTimeout / 2,
		InitialStreamReceiveWindow: rt.Profile.Stream, MaxStreamReceiveWindow: rt.Profile.Stream,
		InitialConnectionReceiveWindow: nruntime.PreAuthConnWindow, MaxConnectionReceiveWindow: rt.Profile.Connection,
		MaxIncomingStreams: 4096, MaxIncomingUniStreams: -1,
	}
}

type authWindowKey struct{}

func listenNowhereQUIC(pc net.PacketConn, config *tls.Config, key string, masked bool, keys func() []morph.Keys) (qio.Listener, error) {
	rt, err := nruntime.Load(key, false)
	if err != nil {
		return nil, err
	}
	if keys != nil && os.Getenv(nruntime.EnvHandshakeTimeout) == "" {
		// QUIC TLS precedes user authentication; allow the largest derived budget.
		rt.HandshakeTimeout = 30 * time.Second
	}
	cids := &morphCIDGenerator{}
	if _, err := rand.Read(cids.secret[:]); err != nil {
		return nil, err
	}
	if masked && keys != nil {
		pc = morph.WrapPacketConnMulti(pc, keys, cids.valid)
	} else if masked {
		pc, err = morph.WrapPacketConn(pc, morph.Derive([]byte(key)), false)
		if err != nil {
			return nil, err
		}
	}
	transport := &quic.Transport{Conn: pc, DisableVersionNegotiationPackets: masked, ConnectionIDGenerator: cids,
		ConnContext: func(ctx context.Context, _ *quic.ClientInfo) (context.Context, error) {
			return context.WithValue(ctx, authWindowKey{}, &atomic.Bool{}), nil
		},
	}
	cfg := quicConfig(rt)
	// Admission state is per connection, not shared by every peer on a listener.
	cfg.AllowConnectionWindowIncrease = func(c *quic.Conn, _ uint64) bool {
		flag, _ := c.Context().Value(authWindowKey{}).(*atomic.Bool)
		return flag != nil && flag.Load()
	}
	ln, err := transport.Listen(config, cfg)
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	return &quicListener{ln: ln, transport: transport, socket: pc}, nil
}

func dialNowhereQUIC(ctx context.Context, pc net.PacketConn, addr net.Addr, config *tls.Config, key string, masked bool) (qio.Conn, error) {
	rt, err := nruntime.Load(key, masked)
	if err != nil {
		_ = pc.Close()
		return nil, err
	}
	if masked {
		wrapped, wrapErr := morph.WrapPacketConn(pc, morph.Derive([]byte(key)), true)
		if wrapErr != nil {
			_ = pc.Close()
			return nil, wrapErr
		}
		pc = wrapped
	}
	cfg := config.Clone()
	cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	cfg.NextProtos, cfg.ClientSessionCache = []string{wire.ALPN}, nil
	transport := &quic.Transport{Conn: pc}
	qc := quicConfig(rt)
	qc.InitialConnectionReceiveWindow = rt.Profile.Connection
	c, err := transport.Dial(ctx, addr, cfg, qc)
	if err != nil {
		_ = transport.Close()
		_ = pc.Close()
		return nil, err
	}
	go func() { <-c.Context().Done(); _ = transport.Close(); _ = pc.Close() }()
	return &quicConn{conn: c}, nil
}

type quicListener struct {
	ln        *quic.Listener
	transport *quic.Transport
	socket    net.PacketConn
}

func (l *quicListener) Accept(ctx context.Context) (qio.Conn, error) {
	c, err := l.ln.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &quicConn{conn: c}, nil
}
func (l *quicListener) Close() error {
	_ = l.ln.Close()
	_ = l.transport.Close()
	return l.socket.Close()
}

type quicConn struct {
	conn    *quic.Conn
	maxData atomic.Int64
}

func (c *quicConn) ReleasePreAuth() {
	if flag, _ := c.conn.Context().Value(authWindowKey{}).(*atomic.Bool); flag != nil {
		flag.Store(true)
	}
}
func (c *quicConn) TLSVersion() uint16 { return c.conn.ConnectionState().TLS.Version }
func (c *quicConn) ALPN() string       { return c.conn.ConnectionState().TLS.NegotiatedProtocol }
func (c *quicConn) Exporter() ([]byte, error) {
	state := c.conn.ConnectionState().TLS
	return state.ExportKeyingMaterial(wire.ExporterLabel, []byte{}, wire.ExporterLen)
}
func (c *quicConn) AcceptStream(ctx context.Context) (qio.Stream, error) {
	s, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &quicStream{s}, nil
}
func (c *quicConn) OpenStream(ctx context.Context) (qio.Stream, error) {
	s, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &quicStream{s}, nil
}
func (c *quicConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return c.conn.ReceiveDatagram(ctx)
}
func (c *quicConn) SendDatagram(b []byte) error {
	err := c.conn.SendDatagram(b)
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) && tooLarge.MaxDatagramPayloadSize > 0 {
		c.maxData.Store(tooLarge.MaxDatagramPayloadSize)
	}
	return err
}
func (c *quicConn) MaxDatagramSize() int {
	if n := c.maxData.Load(); n > 0 {
		return int(n)
	}
	return 1150
}
func (c *quicConn) CloseWithError(code uint64, message string) error {
	return c.conn.CloseWithError(quic.ApplicationErrorCode(code), message)
}
func (c *quicConn) Context() context.Context { return c.conn.Context() }
func (c *quicConn) RemoteAddr() net.Addr     { return c.conn.RemoteAddr() }

type quicStream struct{ *quic.Stream }

func (s *quicStream) ID() uint64        { return uint64(s.StreamID()) }
func (s *quicStream) CloseWrite() error { return s.Stream.Close() }
func (s *quicStream) Close() error      { s.CancelRead(0); return s.Stream.Close() }

type morphCIDGenerator struct{ secret [32]byte }

func (g *morphCIDGenerator) ConnectionIDLen() int { return 16 }
func (g *morphCIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b[:8]); err != nil {
		return quic.ConnectionID{}, err
	}
	h := hmac.New(sha256.New, g.secret[:])
	h.Write(b[:8])
	copy(b[8:], h.Sum(nil)[:8])
	return quic.ConnectionIDFromBytes(b), nil
}
func (g *morphCIDGenerator) valid(b []byte) bool {
	if len(b) != 16 {
		return false
	}
	h := hmac.New(sha256.New, g.secret[:])
	h.Write(b[:8])
	return hmac.Equal(b[8:], h.Sum(nil)[:8])
}
