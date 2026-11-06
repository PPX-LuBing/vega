// Package vector is the Nowhere 3 client. One process uses either TLS or QUIC,
// and the TLS/QUIC handshake offers only ALPN nw3.
package vector

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ohmycggk/nowhere-go/dgram"
	"github.com/ohmycggk/nowhere-go/flowio"
	"github.com/ohmycggk/nowhere-go/morph"
	"github.com/ohmycggk/nowhere-go/qio"
	"github.com/ohmycggk/nowhere-go/runtime"
	"github.com/ohmycggk/nowhere-go/wire"
)

// Config opens a Vector. Set DialQUIC for a QUIC carrier; otherwise DialTCP and
// TLS are required. Exactly one carrier is used.
type Config struct {
	SharedKey    string
	Morph        bool
	PortalAddr   string
	TLS          *tls.Config
	DialTCP      func(ctx context.Context, addr string) (net.Conn, error)
	DialQUIC     func(ctx context.Context) (qio.Conn, error)
	UploadMbps   int
	DownloadMbps int
	// DatagramOverhead is subtracted from the QUIC datagram size. Morph UDP
	// uses 12 for the unmasked nonce so the prefix counts toward the path MTU.
	DatagramOverhead int
}

// Client opens TCP and UDP flows.
type Client struct {
	creds        *wire.Credentials
	keys         *morph.Keys
	cfg          Config
	up           *flowio.Limiter
	down         *flowio.Limiter
	mu           sync.Mutex
	sessionState *quicSession
	dialing      chan struct{}
	dialCancel   context.CancelFunc
	closed       bool
}

type quicSession struct {
	conn     qio.Conn
	router   *dgram.Router
	cancel   context.CancelFunc
	mu       sync.Mutex
	started  bool
	ready    chan struct{}
	authErr  error
	draining bool
}

// New validates the shared key and carrier selection.
func New(cfg Config) (*Client, error) {
	if err := wire.ValidateServiceKey(cfg.SharedKey); err != nil {
		return nil, err
	}
	creds, err := wire.NewCredentials(cfg.SharedKey)
	if err != nil {
		return nil, err
	}
	if cfg.DialQUIC != nil {
		if cfg.DialTCP != nil {
			return nil, errors.New("nw3: vector requires exactly one carrier")
		}
	} else if cfg.DialTCP == nil || cfg.TLS == nil {
		return nil, errors.New("nw3: vector requires exactly one carrier")
	}
	c := &Client{creds: creds, cfg: cfg, up: flowio.NewMbps(cfg.UploadMbps), down: flowio.NewMbps(cfg.DownloadMbps)}
	if cfg.Morph {
		keys := morph.Derive([]byte(cfg.SharedKey))
		c.keys = &keys
	}
	if cfg.TLS != nil {
		tlsCfg := cfg.TLS.Clone()
		tlsCfg.MinVersion = tls.VersionTLS13
		tlsCfg.MaxVersion = tls.VersionTLS13
		tlsCfg.NextProtos = []string{wire.ALPN}
		tlsCfg.ClientSessionCache = nil
		c.cfg.TLS = tlsCfg
	}
	return c, nil
}

// OpenTCP opens one TCP flow.
func (c *Client) OpenTCP(ctx context.Context, target wire.Target) (net.Conn, error) {
	return c.open(ctx, wire.FlowTCP, target)
}

// OpenUDP opens one UDP association. Each Read/Write is one datagram.
func (c *Client) OpenUDP(ctx context.Context, target wire.Target) (net.Conn, error) {
	return c.open(ctx, wire.FlowUDP, target)
}

// Close releases the QUIC connection, if any.
func (c *Client) Close() error {
	c.mu.Lock()
	c.closed = true
	sess := c.sessionState
	c.sessionState = nil
	cancel := c.dialCancel
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if sess != nil {
		sess.cancel()
		return sess.conn.CloseWithError(0, "")
	}
	return nil
}

func (c *Client) open(ctx context.Context, kind wire.FlowKind, target wire.Target) (net.Conn, error) {
	c.mu.Lock()
	closed := c.closed
	c.mu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	if c.cfg.DialQUIC != nil {
		return c.openQUIC(ctx, kind, target)
	}
	return c.openTLS(ctx, kind, target)
}

func (c *Client) openTLS(ctx context.Context, kind wire.FlowKind, target wire.Target) (net.Conn, error) {
	raw, err := c.cfg.DialTCP(ctx, c.cfg.PortalAddr)
	if err != nil {
		return nil, err
	}
	// HandshakeContext only covers TLS, not Morph or the auth/setup exchange.
	// Keep cancellation active until ownership passes to the caller.
	setupConn := raw
	setupCtx, finishSetup := context.WithCancel(ctx)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-setupCtx.Done()
		if ctx.Err() != nil {
			_ = setupConn.Close()
		}
	}()
	stop := func() { finishSetup(); <-stopped }
	defer stop()
	if c.keys != nil {
		wrapped, wrapErr := morph.WrapTCPClient(raw, *c.keys)
		if wrapErr != nil {
			_ = raw.Close()
			return nil, wrapErr
		}
		raw = wrapped
	}
	tlsConn := tls.Client(raw, c.cfg.TLS)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	state := tlsConn.ConnectionState()
	exp, err := exportTLS(state)
	if err != nil || state.NegotiatedProtocol != wire.ALPN || state.Version != tls.VersionTLS13 {
		_ = tlsConn.Close()
		if err == nil {
			err = errors.New("nw3: TLS handshake rejected")
		}
		return nil, err
	}
	if err := wire.WriteAuthFrame(tlsConn, c.creds, wire.RoleVector, wire.AuthTLS, exp); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if err := wire.WriteFlowRequest(tlsConn, kind, target); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	result, err := wire.ReadSetupResult(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if result != wire.SetupReady {
		_ = tlsConn.Close()
		return nil, wire.SetupError{Result: result}
	}
	stop()
	if err := ctx.Err(); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	var conn net.Conn = tlsConn
	if kind == wire.FlowUDP {
		conn = &uotConn{Conn: tlsConn}
	}
	return newLimitedConn(conn, c.up, c.down), nil
}

func (c *Client) openQUIC(ctx context.Context, kind wire.FlowKind, target wire.Target) (net.Conn, error) {
	sess, err := c.session(ctx)
	if err != nil {
		return nil, err
	}
	conn, router := sess.conn, sess.router
	sess.mu.Lock()
	first := !sess.started
	sess.started = true
	sess.mu.Unlock()
	if !first {
		select {
		case <-sess.ready:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-conn.Context().Done():
			return nil, conn.Context().Err()
		}
		if sess.authErr != nil {
			return nil, sess.authErr
		}
	}
	rt, err := runtime.Load(c.cfg.SharedKey, false)
	if err != nil {
		return nil, err
	}
	setupCtx, cancel := context.WithTimeout(ctx, rt.FlowSetupTimeout)
	defer cancel()
	st, err := conn.OpenStream(setupCtx)
	finishAuth := func(e error) {
		if first {
			sess.authErr = e
			close(sess.ready)
			first = false
			if e != nil {
				c.failSession(sess)
			}
		}
	}
	if err != nil {
		finishAuth(err)
		return nil, err
	}
	deadline, _ := setupCtx.Deadline()
	_ = st.SetDeadline(deadline)
	stop := context.AfterFunc(setupCtx, func() { _ = st.Close() })
	defer stop()
	if first {
		if st.ID() != 0 {
			err = errors.New("nw3: authentication stream was not stream 0")
		} else {
			var exp wire.Exporter
			exp, err = connExporter(conn)
			if err == nil {
				err = wire.WriteAuthFrame(st, c.creds, wire.RoleVector, wire.AuthQUIC, exp)
			}
		}
		finishAuth(err)
		if err != nil {
			_ = st.Close()
			return nil, err
		}
	}
	var flow *dgram.Flow
	if kind == wire.FlowUDP {
		id, e := wire.UDPFlowID(st.ID(), false)
		if e != nil {
			_ = st.Close()
			go c.drainAndDrop(sess, rt.ShutdownTimeout)
			return nil, e
		}
		flow = router.Register(id)
	}
	owned := false
	defer func() {
		if !owned {
			_ = st.Close()
			if flow != nil {
				router.CloseFlow(flow.ID)
			}
		}
	}()
	if err = wire.WriteFlowRequest(st, kind, target); err != nil {
		return nil, err
	}
	br := bufio.NewReader(st)
	result, err := wire.ReadSetupResult(br)
	if err != nil {
		if conn.Context().Err() != nil {
			c.failSession(sess)
		}
		return nil, err
	}
	if result != wire.SetupReady {
		return nil, wire.SetupError{Result: result}
	}
	if !stop() || setupCtx.Err() != nil {
		return nil, context.Canceled
	}
	_ = st.SetDeadline(time.Time{})
	owned = true
	rw := &streamConn{Reader: br, Stream: st, local: addr("quic-local"), remote: conn.RemoteAddr()}
	if kind == wire.FlowTCP {
		return newLimitedConn(rw, c.up, c.down), nil
	}
	pc := &udpConn{PacketConn: &dgram.PacketConn{Router: router, Flow: flow, Done: make(chan struct{})}, st: st}
	go func() { var b [1]byte; _, _ = br.Read(b[:]); _ = pc.Close() }()
	return newLimitedConn(pc, c.up, c.down), nil
}

func (c *Client) drainAndDrop(sess *quicSession, bound time.Duration) {
	c.mu.Lock()
	sess.draining = true
	c.mu.Unlock()
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-sess.conn.Context().Done():
	}
	c.failSession(sess)
}

// A failed old flow must never close its replacement session.
func (c *Client) failSession(sess *quicSession) {
	c.mu.Lock()
	if c.sessionState == sess {
		c.sessionState = nil
	}
	c.mu.Unlock()
	sess.cancel()
	_ = sess.conn.CloseWithError(0, "session")
}

func (c *Client) session(ctx context.Context) (*quicSession, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, net.ErrClosed
		}
		if sess := c.sessionState; sess != nil {
			if sess.draining && sess.conn.Context().Err() == nil {
				c.mu.Unlock()
				return nil, errors.New("nw3: session draining")
			}
			if sess.conn.Context().Err() == nil && !sess.draining {
				c.mu.Unlock()
				return sess, nil
			}
			c.sessionState = nil
			sess.cancel()
			_ = sess.conn.CloseWithError(0, "idle")
		}
		if wait := c.dialing; wait != nil {
			c.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		wait := make(chan struct{})
		c.dialing = wait
		dialCtx, cancel := context.WithCancel(ctx)
		c.dialCancel = cancel
		c.mu.Unlock()
		conn, err := c.cfg.DialQUIC(dialCtx)
		cancel()
		if err == nil && (conn.ALPN() != wire.ALPN || conn.TLSVersion() != tls.VersionTLS13) {
			_ = conn.CloseWithError(0, "alpn")
			err = errors.New("nw3: QUIC handshake rejected")
		}
		c.mu.Lock()
		c.dialing = nil
		c.dialCancel = nil
		close(wait)
		if c.closed && err == nil {
			_ = conn.CloseWithError(0, "closed")
			err = net.ErrClosed
		}
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		runCtx, cancelRun := context.WithCancel(conn.Context())
		router := dgram.NewRouter(conn, 0)
		router.SetOverhead(c.cfg.DatagramOverhead)
		sess := &quicSession{conn: conn, router: router, cancel: cancelRun, ready: make(chan struct{})}
		c.sessionState = sess
		c.mu.Unlock()
		go router.Run(runCtx)
		return sess, nil
	}
}

func exportTLS(state tls.ConnectionState) (wire.Exporter, error) {
	var out wire.Exporter
	b, err := state.ExportKeyingMaterial(wire.ExporterLabel, []byte{}, wire.ExporterLen)
	if err != nil {
		return out, err
	}
	if copy(out[:], b) != wire.ExporterLen {
		return out, errors.New("nw3: short exporter")
	}
	return out, nil
}

func connExporter(conn qio.Conn) (wire.Exporter, error) {
	var out wire.Exporter
	b, err := conn.Exporter()
	if err != nil {
		return out, err
	}
	if copy(out[:], b) != wire.ExporterLen {
		return out, errors.New("nw3: short exporter")
	}
	return out, nil
}

type addr string

func (a addr) Network() string { return "nw3" }
func (a addr) String() string  { return string(a) }

type streamConn struct {
	io.Reader
	qio.Stream
	local, remote net.Addr
}

func (c *streamConn) Read(p []byte) (int, error) { return c.Reader.Read(p) }
func (c *streamConn) LocalAddr() net.Addr        { return c.local }
func (c *streamConn) RemoteAddr() net.Addr       { return c.remote }

type limitedConn struct {
	net.Conn
	up, down *flowio.Limiter
	ctx      context.Context
	cancel   context.CancelFunc
}

func newLimitedConn(conn net.Conn, up, down *flowio.Limiter) *limitedConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &limitedConn{Conn: conn, up: up, down: down, ctx: ctx, cancel: cancel}
}

func (c *limitedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func (c *limitedConn) Close() error {
	c.cancel()
	return c.Conn.Close()
}

func (c *limitedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		if waitErr := c.down.WaitN(c.ctx, n); waitErr != nil {
			return n, waitErr
		}
	}
	return n, err
}

func (c *limitedConn) Write(p []byte) (int, error) {
	if err := c.up.WaitN(c.ctx, len(p)); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

type uotConn struct{ net.Conn }

func (c *uotConn) Read(p []byte) (int, error) {
	pkt, err := wire.ReadUoT(c.Conn)
	if err != nil {
		return 0, err
	}
	n := copy(p, pkt)
	return n, nil
}

func (c *uotConn) Write(p []byte) (int, error) {
	if err := wire.WriteUoT(c.Conn, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

type udpConn struct {
	*dgram.PacketConn
	st qio.Stream
}

func (c *udpConn) Read(p []byte) (int, error) { return c.PacketConn.Read(p) }
func (c *udpConn) Write(p []byte) (int, error) {
	n, err := c.PacketConn.Write(p)
	return n, err
}
func (c *udpConn) Close() error {
	_ = c.PacketConn.Close()
	// FIN the control stream before cancelling its read. CLOSE is only a hint.
	_ = c.st.CloseWrite()
	_ = c.st.Close()
	return nil
}
func (c *udpConn) LocalAddr() net.Addr                { return addr("udp") }
func (c *udpConn) RemoteAddr() net.Addr               { return addr("udp") }
func (c *udpConn) SetDeadline(t time.Time) error      { return c.st.SetDeadline(t) }
func (c *udpConn) SetReadDeadline(t time.Time) error  { return c.st.SetReadDeadline(t) }
func (c *udpConn) SetWriteDeadline(t time.Time) error { return c.st.SetWriteDeadline(t) }

// Ensure limitedConn is a net.Conn at compile time.
var _ net.Conn = (*limitedConn)(nil)
