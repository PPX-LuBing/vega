// Package egress is the Nowhere 3 exit client. It dials Portal over one
// carrier, registers, and only then dials targets for Portal-opened flows.
// TLS keeps a standby pool. QUIC keeps one connection and accepts many flows.
package egress

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/ohmycggk/nowhere-go/dgram"
	"github.com/ohmycggk/nowhere-go/flowio"
	"github.com/ohmycggk/nowhere-go/morph"
	"github.com/ohmycggk/nowhere-go/qio"
	"github.com/ohmycggk/nowhere-go/runtime"
	"github.com/ohmycggk/nowhere-go/wire"
)

const keepalive = 15 * time.Second

// Config is one Egress process. Set DialQUIC or DialTCP, not both.
type Config struct {
	SharedKey  string
	Morph      bool
	PortalAddr string
	TLS        *tls.Config
	DialTCP    func(ctx context.Context, addr string) (net.Conn, error)
	DialQUIC   func(ctx context.Context) (qio.Conn, error)
	Upstream   interface {
		DialTCP(ctx context.Context, target wire.Target) (net.Conn, error)
		DialUDP(ctx context.Context, target wire.Target) (net.Conn, error)
	}
	UploadMbps   int
	DownloadMbps int
	// DatagramOverhead is subtracted from the QUIC datagram size. Morph UDP
	// uses 12 for the unmasked nonce so the prefix counts toward the path MTU.
	DatagramOverhead int
}

// ErrBusy is returned when a single registration finds the Portal at its
// pending TLS cap. The TLS supervisor treats it as a full pool, not a failure.
var ErrBusy = errors.New("nw3: egress registration busy")

// Run registers with Portal and serves flows until ctx ends.
func Run(ctx context.Context, cfg Config) error {
	if err := wire.ValidateServiceKey(cfg.SharedKey); err != nil {
		return err
	}
	if cfg.Upstream == nil {
		return errors.New("nw3: egress requires an upstream")
	}
	if (cfg.DialQUIC == nil) == (cfg.DialTCP == nil) {
		return errors.New("nw3: egress requires exactly one carrier")
	}
	rt, err := runtime.Load(cfg.SharedKey, cfg.Morph && cfg.DialQUIC != nil)
	if err != nil {
		return err
	}
	creds, err := wire.NewCredentials(cfg.SharedKey)
	if err != nil {
		return err
	}
	if cfg.DialTCP != nil {
		if cfg.TLS == nil {
			return errors.New("nw3: egress TLS carrier requires a TLS config")
		}
		tlsCfg := cfg.TLS.Clone()
		tlsCfg.MinVersion = tls.VersionTLS13
		tlsCfg.MaxVersion = tls.VersionTLS13
		tlsCfg.NextProtos = []string{wire.ALPN}
		cfg.TLS = tlsCfg
		return runTLS(ctx, cfg, creds, rt)
	}
	return runQUIC(ctx, cfg, creds, rt)
}

type session struct {
	cfg   Config
	creds *wire.Credentials
	rt    runtime.Settings
	up    *flowio.Limiter
	down  *flowio.Limiter
	keys  *morph.Keys
}

func newSession(cfg Config, creds *wire.Credentials, rt runtime.Settings) *session {
	s := &session{
		cfg: cfg, creds: creds, rt: rt,
		up: flowio.NewMbps(cfg.UploadMbps), down: flowio.NewMbps(cfg.DownloadMbps),
	}
	if cfg.Morph {
		keys := morph.Derive([]byte(cfg.SharedKey))
		s.keys = &keys
	}
	return s
}

// runTLS is the Hydra supervisor. The budget counts connections being
// established, registering, or waiting. Active flows do not count. It starts
// with one seed and adds up to two replacements when a standby connection
// receives FlowStart. Failures do not grow the pool. At zero it restores one
// seed after the service cooldown.
func runTLS(ctx context.Context, cfg Config, creds *wire.Credentials, rt runtime.Settings) error {
	s := newSession(cfg, creds, rt)
	var mu sync.Mutex
	budget := 0
	wake := make(chan struct{}, 1)
	signal := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	var wg sync.WaitGroup
	var launch func(n int)
	launch = func(n int) {
		mu.Lock()
		var starts int
		for ; n > 0 && ctx.Err() == nil && budget < rt.EgressTLSPoolMax; n-- {
			budget++
			starts++
		}
		mu.Unlock()
		for i := 0; i < starts; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				released := false
				release := func(grow bool) {
					if released {
						return
					}
					released = true
					mu.Lock()
					budget--
					mu.Unlock()
					if grow {
						launch(2)
					}
					signal()
				}
				s.tlsOnce(ctx, func() { release(true) })
				release(false)
				signal()
			}()
		}
	}
	launch(1)
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return ctx.Err()
		case <-wake:
		}
		mu.Lock()
		empty := budget == 0
		mu.Unlock()
		if !empty {
			continue
		}
		timer := time.NewTimer(rt.ServiceCooldown)
		select {
		case <-ctx.Done():
			timer.Stop()
			wg.Wait()
			return ctx.Err()
		case <-timer.C:
			launch(1)
		}
	}
}

// tlsOnce replenishes the standby pool on FlowStart, before serving the flow.
func (s *session) tlsOnce(ctx context.Context, claimed func()) int {
	if ctx.Err() != nil {
		return 0
	}
	dialCtx, cancel := context.WithTimeout(ctx, s.rt.HandshakeTimeout)
	raw, err := s.cfg.DialTCP(dialCtx, s.cfg.PortalAddr)
	cancel()
	if err != nil {
		s.cool(ctx)
		return 0
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	_ = raw.SetDeadline(time.Now().Add(s.rt.HandshakeTimeout))
	enableKeepalive(raw)
	var carrier net.Conn = raw
	if s.keys != nil {
		carrier, err = morph.WrapTCPClient(raw, *s.keys)
		if err != nil {
			return 0
		}
	}
	tlsConn := tls.Client(carrier, s.cfg.TLS)
	_ = tlsConn.SetDeadline(time.Now().Add(s.rt.HandshakeTimeout))
	err = tlsConn.Handshake()
	if err != nil {
		_ = tlsConn.Close()
		s.cool(ctx)
		return 0
	}
	state := tlsConn.ConnectionState()
	exp, err := exportTLS(state)
	if err != nil || state.NegotiatedProtocol != wire.ALPN || state.Version != tls.VersionTLS13 {
		_ = tlsConn.Close()
		s.cool(ctx)
		return 0
	}
	if err := wire.WriteAuthFrame(tlsConn, s.creds, wire.RoleEgress, wire.AuthTLS, exp); err != nil {
		_ = tlsConn.Close()
		return 0
	}
	res, err := wire.ReadRegistrationResult(tlsConn)
	if err != nil || res == wire.RegistrationBusy {
		_ = tlsConn.Close()
		return 0
	}
	_ = tlsConn.SetDeadline(time.Time{})
	// The standby TTL starts only after ACCEPTED. The first read is FlowStart;
	// its arrival, or the deadline, ends standby. A deadline is expiry and
	// does not grow the pool.
	br := bufio.NewReader(tlsConn)
	_ = tlsConn.SetReadDeadline(time.Now().Add(runtime.TLSStandbyTTL))
	kind, target, ok, err := wire.ReadFlowRequest(br)
	_ = tlsConn.SetReadDeadline(time.Time{})
	if err != nil || !ok {
		if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			_ = wire.WriteSetupResult(tlsConn, wire.SetupInvalidRequest)
		}
		_ = tlsConn.Close()
		return 0
	}
	claimed()
	s.serveOne(ctx, &pipe{Reader: br, write: tlsConn, closer: tlsConn}, nil, kind, target, 1, true)
	return 2
}

func (s *session) cool(ctx context.Context) {
	timer := time.NewTimer(s.rt.ServiceCooldown)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

func runQUIC(ctx context.Context, cfg Config, creds *wire.Credentials, rt runtime.Settings) error {
	s := newSession(cfg, creds, rt)
	for {
		if err := s.quicOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			s.cool(ctx)
			continue
		}
		return nil
	}
}

func (s *session) quicOnce(ctx context.Context) error {
	conn, err := s.cfg.DialQUIC(ctx)
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")
	ctx, cancelConn := context.WithCancel(ctx)
	defer cancelConn()
	stopConn := context.AfterFunc(conn.Context(), cancelConn)
	defer stopConn()
	stop := context.AfterFunc(ctx, func() { _ = conn.CloseWithError(0, "shutdown") })
	defer stop()
	if conn.ALPN() != wire.ALPN || conn.TLSVersion() != tls.VersionTLS13 {
		return errors.New("nw3: QUIC handshake rejected")
	}
	regCtx, cancel := context.WithTimeout(ctx, s.rt.HandshakeTimeout)
	defer cancel()
	st, err := conn.OpenStream(regCtx)
	if err != nil {
		return err
	}
	if st.ID() != 0 {
		return errors.New("nw3: authentication stream was not stream 0")
	}
	_ = st.SetDeadline(time.Now().Add(s.rt.HandshakeTimeout))
	exp, err := exporter(conn)
	if err != nil {
		return err
	}
	if err := wire.WriteAuthFrame(st, s.creds, wire.RoleEgress, wire.AuthQUIC, exp); err != nil {
		return err
	}
	if err := st.CloseWrite(); err != nil {
		return err
	}
	res, err := wire.ReadRegistrationResult(st)
	if err != nil {
		return err
	}
	if res == wire.RegistrationBusy {
		return ErrBusy
	}
	if res != wire.RegistrationAccepted {
		return errors.New("nw3: invalid registration result")
	}
	_ = st.SetDeadline(time.Time{})
	router := dgram.NewRouter(conn, s.rt.QUICUDPQueue)
	router.SetOverhead(s.cfg.DatagramOverhead)
	go router.Run(ctx)
	slots := make(chan struct{}, 4096)
	var flows sync.WaitGroup
	defer func() { cancelConn(); _ = conn.CloseWithError(0, "shutdown"); flows.Wait() }()
	for {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		flow, err := conn.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if flow.ID()&2 != 0 || flow.ID()&1 == 0 {
			_ = conn.CloseWithError(0, "direction")
			return errors.New("nw3: invalid business stream direction")
		}
		flows.Add(1)
		go func() { defer flows.Done(); defer func() { <-slots }(); s.serveStream(ctx, router, flow, true) }()
	}
}

func (s *session) serveStream(ctx context.Context, router *dgram.Router, st qio.Stream, server bool) {
	defer st.Close()
	_ = st.SetReadDeadline(time.Now().Add(s.rt.FlowSetupTimeout))
	br := bufio.NewReader(st)
	kind, target, ok, err := wire.ReadFlowRequest(br)
	_ = st.SetReadDeadline(time.Time{})
	if !ok && err == nil {
		// A clean EOF before FlowStart is an idle close, not a bad request.
		return
	}
	if err != nil || !ok {
		_ = wire.WriteSetupResult(st, wire.SetupInvalidRequest)
		return
	}
	s.serveOne(ctx, &pipe{Reader: br, write: st, closer: st}, router, kind, target, st.ID(), server)
}

func (s *session) serveOne(ctx context.Context, client *pipe, router *dgram.Router, kind wire.FlowKind, target wire.Target, streamID uint64, server bool) {
	dialCtx, cancel := context.WithTimeout(ctx, s.rt.UDPDialTimeout)
	if kind == wire.FlowTCP {
		cancel()
		dialCtx, cancel = context.WithTimeout(ctx, s.rt.TCPDialTimeout)
	}
	defer cancel()
	var peer net.Conn
	var err error
	if kind == wire.FlowTCP {
		peer, err = s.cfg.Upstream.DialTCP(dialCtx, target)
	} else {
		peer, err = s.cfg.Upstream.DialUDP(dialCtx, target)
	}
	if err != nil {
		_ = wire.WriteSetupResult(client, wire.SetupDialFailed)
		return
	}
	defer peer.Close()
	stopPeer := context.AfterFunc(ctx, func() { _ = peer.Close(); _ = client.Close() })
	defer stopPeer()
	var id uint32
	if kind == wire.FlowUDP && router != nil {
		id, err = wire.UDPFlowID(streamID, server)
		if err != nil {
			_ = wire.WriteSetupResult(client, wire.SetupFlowLimit)
			return
		}
	}
	if kind == wire.FlowUDP && router != nil {
		router.Ensure(id)
		defer router.CloseFlow(id)
	}
	if err := wire.WriteSetupResult(client, wire.SetupReady); err != nil {
		return
	}
	if kind == wire.FlowTCP {
		flowio.Relay(client, peer, s.up, s.down)
		return
	}
	if router == nil {
		relayUoT(client, peer, s.up, s.down, s.rt.UDPIdleTimeout)
		return
	}
	relayQUIC(router, id, client, peer, s.up, s.down, s.rt.UDPIdleTimeout)
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

func exporter(conn qio.Conn) (wire.Exporter, error) {
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

func enableKeepalive(conn net.Conn) {
	type keep interface {
		SetKeepAlive(bool) error
		SetKeepAlivePeriod(time.Duration) error
	}
	if k, ok := conn.(keep); ok {
		_ = k.SetKeepAlive(true)
		_ = k.SetKeepAlivePeriod(keepalive)
	}
}

type pipe struct {
	io.Reader
	write  io.Writer
	closer io.Closer
}

func (p *pipe) Read(b []byte) (int, error)  { return p.Reader.Read(b) }
func (p *pipe) Write(b []byte) (int, error) { return p.write.Write(b) }
func (p *pipe) Close() error                { return p.closer.Close() }
func (p *pipe) CloseWrite() error {
	if cw, ok := p.write.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return p.Close()
}

func relayUoT(client *pipe, udp net.Conn, up, down *flowio.Limiter, idle time.Duration) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			pkt, err := wire.ReadUoT(client)
			if err != nil {
				break
			}
			_ = up.WaitN(context.Background(), len(pkt))
			if _, err := udp.Write(pkt); err != nil {
				break
			}
		}
		_ = udp.Close()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			_ = udp.SetReadDeadline(time.Now().Add(idle))
			n, err := udp.Read(buf)
			if err != nil {
				break
			}
			_ = down.WaitN(context.Background(), n)
			if err := wire.WriteUoT(client, buf[:n]); err != nil {
				break
			}
		}
		_ = client.CloseWrite()
	}()
	wg.Wait()
}

func relayQUIC(router *dgram.Router, id uint32, client *pipe, udp net.Conn, up, down *flowio.Limiter, idle time.Duration) {
	flow := router.Ensure(id)
	defer router.CloseFlow(id)
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		var b [1]byte
		_, _ = client.Read(b[:])
		finish()
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			_ = udp.SetReadDeadline(time.Now().Add(idle))
			n, err := udp.Read(buf)
			if err != nil {
				finish()
				return
			}
			_ = down.WaitN(context.Background(), n)
			if err := router.Send(id, buf[:n]); err != nil {
				finish()
				return
			}
		}
	}()
	for {
		select {
		case <-done:
			_ = client.CloseWrite()
			return
		case pkt, ok := <-flow.C:
			if !ok {
				_ = client.CloseWrite()
				return
			}
			_ = up.WaitN(context.Background(), len(pkt))
			if _, err := udp.Write(pkt); err != nil {
				finish()
				_ = client.CloseWrite()
				return
			}
		}
	}
}
