// Package portal is the Nowhere 3 server. A listener accepts only ALPN nw3.
package portal

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
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

const (
	maxUnauth    = 256
	maxPerSource = 32
	maxFlows     = 4096
)

// Config is a Portal. Egress mode ignores Upstream and bridges to the registered exit.
type Config struct {
	// SharedKey 是单密钥模式。与 Users 互斥。
	SharedKey string

	// Users 是多用户模式：每个用户一把共享密钥。
	//
	// nw3 的 AuthFrame 不带身份字段，服务端靠「逐个试解密钥」识别用户，
	// 所以多用户模式要求 Morph 也支持多密钥（见 morph.WrapTCPServerMulti）。
	Users []User

	Morph        bool
	TLS          *tls.Config
	Upstream     Upstream
	Egress       bool
	UploadMbps   int
	DownloadMbps int
	// DatagramOverhead is subtracted from the QUIC datagram size before
	// encoding. Morph UDP uses 12 for the unmasked nonce.
	DatagramOverhead int
}

// User 是多用户模式下的一个 Portal 用户。
type User struct {
	Name      string
	SharedKey string
}

// Server accepts Vector and, when Egress is set, a FIFO of Egress registrations.
type Server struct {
	creds *wire.Credentials
	keys  *morph.Keys
	tls   *tls.Config

	// 多用户模式（Users）。与上面的单密钥字段互斥。
	//
	// 这三个字段可以在运行期被 UpdateUsers 替换，读写都要持 usersMu。
	usersMu           sync.RWMutex
	credsList         []*wire.Credentials
	keysList          []morph.Keys
	users             []User
	handshakeTimeout  time.Duration
	handshakeOverride bool

	// multiUserMode / morphEnabled 是构造时定下的模式，运行期不变。
	// 必须显式记住：UpdateUsers 如果无条件填 keysList，plain 模式会被
	// 误判成开了 Morph，服务端开始等 prelude，而客户端根本没发。
	multiUserMode bool
	morphEnabled  bool
	up            Upstream
	egress        bool
	upload        *flowio.Limiter
	download      *flowio.Limiter
	rt            runtime.Settings

	admit    admit
	flows    gate
	reg      *registry
	overhead int
}

// New checks the shared key and exit mode.
func New(cfg Config) (*Server, error) {
	multi := len(cfg.Users) > 0
	if cfg.SharedKey == "" && !multi {
		return nil, errors.New("nw3: shared key or users is required")
	}
	if cfg.SharedKey != "" && multi {
		return nil, errors.New("nw3: shared key and users are mutually exclusive")
	}
	if multi && cfg.Egress {
		return nil, errors.New("nw3: multi-user portal does not support Egress")
	}
	if multi {
		if err := validateUsers(cfg.Users); err != nil {
			return nil, err
		}
		for i, u := range cfg.Users {
			if err := wire.ValidateServiceKey(u.SharedKey); err != nil {
				return nil, fmt.Errorf("nw3: user %d (%q): %w", i, u.Name, err)
			}
		}
	} else if err := wire.ValidateServiceKey(cfg.SharedKey); err != nil {
		return nil, err
	}
	if cfg.TLS == nil {
		return nil, errors.New("nw3: missing portal TLS config")
	}
	if !cfg.Egress && cfg.Upstream == nil {
		return nil, errors.New("nw3: missing portal upstream")
	}
	var creds *wire.Credentials
	var err error
	if !multi {
		creds, err = wire.NewCredentials(cfg.SharedKey)
		if err != nil {
			return nil, err
		}
	}
	runtimeKey := cfg.SharedKey
	if multi {
		runtimeKey = cfg.Users[0].SharedKey
	}
	rt, err := runtime.Load(runtimeKey, false)
	if err != nil {
		return nil, err
	}
	tlsCfg := cfg.TLS.Clone()
	tlsCfg.MinVersion = tls.VersionTLS13
	tlsCfg.MaxVersion = tls.VersionTLS13
	tlsCfg.NextProtos = []string{wire.ALPN}
	tlsCfg.SessionTicketsDisabled = true
	s := &Server{
		creds:    creds,
		tls:      tlsCfg,
		up:       cfg.Upstream,
		egress:   cfg.Egress,
		upload:   flowio.NewMbps(cfg.UploadMbps),
		download: flowio.NewMbps(cfg.DownloadMbps),
		rt:       rt,
		admit:    admit{per: map[string]int{}},
		reg:      newRegistry(rt.PortalTLSIdleMax),
		overhead: cfg.DatagramOverhead,
	}
	s.multiUserMode = multi
	s.morphEnabled = cfg.Morph
	_, s.handshakeOverride = os.LookupEnv(runtime.EnvHandshakeTimeout)
	s.handshakeTimeout = s.userHandshakeTimeout(cfg.Users)
	if multi {
		s.users = append([]User(nil), cfg.Users...)
		s.credsList = make([]*wire.Credentials, 0, len(cfg.Users))
		if cfg.Morph {
			s.keysList = make([]morph.Keys, 0, len(cfg.Users))
		}
		for _, u := range cfg.Users {
			userCreds, err := wire.NewCredentials(u.SharedKey)
			if err != nil {
				return nil, err
			}
			s.credsList = append(s.credsList, userCreds)
			if cfg.Morph {
				s.keysList = append(s.keysList, morph.Derive([]byte(u.SharedKey)))
			}
		}
		return s, nil
	}
	if cfg.Morph {
		keys := morph.Derive([]byte(cfg.SharedKey))
		s.keys = &keys
	}
	return s, nil
}

// multiUser 报告当前是否是多用户模式。
func (s *Server) multiUser() bool {
	return s.multiUserMode
}

// UserCount 返回当前生效的用户数。
//
// 单密钥模式下是 1（那个共享密钥本身），多用户模式下是名单长度。
// 控制端点的 /health 用它报出实际人数，而不是写死 0。
func (s *Server) UserCount() int {
	if s == nil {
		return 0
	}
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	if s.multiUserMode {
		return len(s.users)
	}
	if s.creds != nil {
		return 1
	}
	return 0
}

// UpdateUsers 在运行期替换多用户列表，**不中断已建立的连接**。
//
// 面板改用户（加人、停用、超额摘除）不必重启内核：新连接立刻按新名单认证，
// 老连接按原样跑完。这是 sing-box 原生没有的能力（它只能改配置重启）。
//
// 单密钥模式（Config.SharedKey）不支持运行期改用户，调用会返回错误。
func (s *Server) UpdateUsers(users []User) error {
	if !s.multiUserMode {
		return errors.New("nw3: update users requires multi-user mode")
	}
	if err := validateUsers(users); err != nil {
		return err
	}
	s.usersMu.Lock()
	defer s.usersMu.Unlock()
	oldKeys := make(map[string]morph.Keys, len(s.keysList))
	for i, key := range s.keysList {
		oldKeys[s.users[i].SharedKey] = key
	}
	credsList := make([]*wire.Credentials, 0, len(users))
	keysList := make([]morph.Keys, 0, len(users))
	for i, u := range users {
		if err := wire.ValidateServiceKey(u.SharedKey); err != nil {
			return fmt.Errorf("nw3: user %d (%q): %w", i, u.Name, err)
		}
		creds, err := wire.NewCredentials(u.SharedKey)
		if err != nil {
			return err
		}
		credsList = append(credsList, creds)
		if s.morphEnabled {
			key, exists := oldKeys[u.SharedKey]
			if !exists {
				key = morph.Derive([]byte(u.SharedKey))
			}
			keysList = append(keysList, key)
		}
	}

	s.users = append([]User(nil), users...)
	s.credsList = credsList
	s.handshakeTimeout = s.userHandshakeTimeout(users)
	if s.morphEnabled {
		s.keysList = keysList
	} else {
		s.keysList = nil // plain 模式不能留 keysList，否则 morphing 会误判成 true
	}
	return nil
}

func validateUsers(users []User) error {
	names, keys := map[string]bool{}, map[string]bool{}
	for _, user := range users {
		if user.Name == "" || names[user.Name] || keys[user.SharedKey] {
			return errors.New("nw3: users require unique nonempty names and keys")
		}
		if err := wire.ValidateServiceKey(user.SharedKey); err != nil {
			return err
		}
		names[user.Name], keys[user.SharedKey] = true, true
	}
	return nil
}

// snapshotUsers 取一份用户凭据快照，供单个连接在认证期间使用。
//
// 取快照而不是逐次读字段：一次连接的 Morph 试解与 AuthFrame 试解必须
// 用同一份名单，否则中途换人会串号。
func (s *Server) snapshotUsers() ([]*wire.Credentials, []morph.Keys, []User, time.Duration) {
	s.usersMu.RLock()
	defer s.usersMu.RUnlock()
	return s.credsList, s.keysList, s.users, s.handshakeTimeout
}

func (s *Server) userHandshakeTimeout(users []User) time.Duration {
	if !s.multiUserMode || s.handshakeOverride || len(users) == 0 {
		return s.rt.HandshakeTimeout
	}
	// Identity is unknown before authentication. Admit every configured key's
	// official timeout, without deriving a fictitious timeout from an empty key.
	var longest time.Duration
	for _, user := range users {
		if timeout := runtime.HandshakeTimeout(user.SharedKey); timeout > longest {
			longest = timeout
		}
	}
	return longest
}

// userCtxKey 是用户身份的 context 键。
type userCtxKey struct{}
type sourceCtxKey struct{}

func SourceFromContext(ctx context.Context) net.Addr {
	addr, _ := ctx.Value(sourceCtxKey{}).(net.Addr)
	return addr
}

// ContextWithUser 把用户身份放进 context，供上游做按用户统计。
func ContextWithUser(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, userCtxKey{}, name)
}

// UserFromContext 取出该连接所属的用户名；单密钥模式返回空串。
func UserFromContext(ctx context.Context) string {
	name, _ := ctx.Value(userCtxKey{}).(string)
	return name
}

// Serve accepts TLS connections. The listener is closed when ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
		case <-done:
		}
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go s.serveTCP(ctx, conn)
	}
}

// ServeQUIC accepts QUIC connections that already negotiated ALPN nw3 inside the host stack.
// The host TLS config must offer only nw3; mismatched ALPNs are closed here as well.
func (s *Server) ServeQUIC(ctx context.Context, ln qio.Listener) error {
	if s.multiUser() {
		// 多用户的 UDP 路径需要 morph.WrapPacketConn 也支持多密钥试解，
		// 目前只做了 TCP。这里显式拒绝，避免走到 nil creds 上崩掉。
		return errors.New("nw3: multi-user portal does not support QUIC yet")
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go s.serveQUIC(ctx, conn)
	}
}

func (s *Server) serveTCP(ctx context.Context, raw net.Conn) {
	conn := raw
	parent := ctx
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-parent.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	transferred := false
	defer func() {
		if !transferred {
			_ = conn.Close()
		}
	}()
	ctx = context.WithValue(ctx, sourceCtxKey{}, raw.RemoteAddr())
	acceptedAt := time.Now()
	credsList, keysList, userList, handshakeTimeout := s.snapshotUsers()
	deadline := acceptedAt.Add(handshakeTimeout)
	if s.multiUserMode && len(credsList) == 0 {
		return
	}
	morphing := s.keys != nil || len(keysList) > 0
	if morphing {
		// Abortive close stays on until Vector authentication succeeds.
		if err := setZeroLinger(raw); err != nil {
			_ = raw.Close()
			return
		}
	}
	if !s.admit.take(raw.RemoteAddr()) {
		if !morphing {
			_ = raw.Close()
			return
		}
		// A Morph TCP connection waits for a slot until the handshake deadline
		// instead of being dropped. The wait does not read the socket.
		if !s.admit.wait(ctx, raw.RemoteAddr(), deadline) {
			_ = raw.Close()
			return
		}
	}
	held := true
	defer func() {
		if held {
			s.admit.release(raw.RemoteAddr())
		}
	}()
	if morphing {
		if len(keysList) > 0 {
			raw = morph.WrapTCPServerMulti(raw, keysList)
		} else {
			raw = morph.WrapTCPServer(raw, *s.keys)
		}
	}
	tlsConn := tls.Server(raw, s.tls)
	_ = tlsConn.SetDeadline(deadline)
	if err := tlsConn.Handshake(); err != nil {
		// A rejected prelude or ClientHello is not drained: the Morph reader
		// stops returning socket bytes once admission fails. The slot is released
		// before the hold, because the connection will not authenticate. The
		// socket itself stays open until the deadline captured at accept.
		// crypto/tls does not preserve the admission error, so every Morph
		// failure before a TLS response takes this path.
		if morphing {
			s.admit.release(raw.RemoteAddr())
			held = false
			parkUntil(deadline)
		}
		_ = tlsConn.Close()
		return
	}
	state := tlsConn.ConnectionState()
	exp, err := exportState(state)
	if err != nil || state.NegotiatedProtocol != wire.ALPN || state.Version != tls.VersionTLS13 {
		_ = tlsConn.Close()
		return
	}
	br := bufio.NewReader(tlsConn)
	creds := s.creds
	authDone := false
	role := wire.RoleVector
	if len(credsList) > 0 {
		// 两条识别路径：
		//   - 开了 Morph：prelude 已在 TLS 握手时逐个试解，命中下标即用户；
		//   - 没开 Morph：AuthFrame 是定长 16 字节 + 纯校验函数，读一次逐个试。
		// 两者都不消费 socket 之外的副作用，失败的候选不留痕迹。
		idx := -1
		if morphing {
			idx = morph.MatchedKeyIndex(raw)
		}
		if idx >= 0 && idx < len(credsList) {
			creds = credsList[idx]
		} else {
			var frame [wire.AuthFrameLen]byte
			if _, readErr := io.ReadFull(br, frame[:]); readErr != nil {
				_ = tlsConn.Close()
				s.admit.release(raw.RemoteAddr())
				held = false
				return
			}
			for i, candidate := range credsList {
				role, validateErr := wire.ValidateAuthFrame(frame[:], candidate, wire.AuthTLS, exp)
				if validateErr == nil && role == wire.RoleVector {
					idx = i
					break
				}
			}
			if idx < 0 {
				_ = tlsConn.Close()
				s.admit.release(raw.RemoteAddr())
				held = false
				return
			}
			authDone = true
		}
		ctx = ContextWithUser(ctx, userList[idx].Name)
	}
	if !authDone {
		var authErr error
		role, authErr = wire.ReadAuthFrame(br, creds, wire.AuthTLS, exp)
		s.admit.release(raw.RemoteAddr())
		held = false
		if authErr != nil || (role != wire.RoleVector && (s.multiUserMode || role != wire.RoleEgress)) {
			_ = tlsConn.Close()
			return
		}
	} else {
		s.admit.release(raw.RemoteAddr())
		held = false
	}
	if morphing {
		if err := morph.ReleaseAuthenticated(raw, deadline); err != nil {
			_ = tlsConn.Close()
			return
		}
	}
	if role == wire.RoleEgress && s.egress {
		// Standby lasts 120s. The handshake deadline must not expire it.
		_ = tlsConn.SetDeadline(time.Time{})
		transferred = s.serveEgressTLS(ctx, tlsConn, br)
		return
	}
	if role != wire.RoleVector {
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Now().Add(s.rt.FlowSetupTimeout))
	kind, target, ok, err := wire.ReadFlowRequest(br)
	rw := &pipe{Reader: br, write: tlsConn, closer: tlsConn}
	if err != nil || !ok {
		if ok || err != nil {
			_ = wire.WriteSetupResult(tlsConn, wire.SetupInvalidRequest)
		}
		_ = tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})
	s.serveFlow(ctx, kind, target, rw, nil, 0, true)
}

func (s *Server) serveQUIC(ctx context.Context, conn qio.Conn) {
	defer conn.CloseWithError(0, "")
	if conn.ALPN() != wire.ALPN || conn.TLSVersion() != tls.VersionTLS13 {
		return
	}
	if !s.admit.take(conn.RemoteAddr()) {
		return
	}
	dropCtx, cancelDrop := context.WithCancel(ctx)
	dropDone := make(chan struct{})
	go func() {
		defer close(dropDone)
		for {
			if _, err := conn.ReceiveDatagram(dropCtx); err != nil {
				return
			}
		}
	}()
	authCtx, cancelAuth := context.WithTimeout(ctx, s.rt.HandshakeTimeout)
	st, err := conn.AcceptStream(authCtx)
	cancelAuth()
	if err != nil || st.ID() != 0 {
		cancelDrop()
		<-dropDone
		s.admit.release(conn.RemoteAddr())
		return
	}
	exp, err := exportConn(conn)
	if err != nil {
		cancelDrop()
		<-dropDone
		s.admit.release(conn.RemoteAddr())
		return
	}
	_ = st.SetDeadline(time.Now().Add(s.rt.HandshakeTimeout))
	br := bufio.NewReader(st)
	role, err := wire.ReadAuthFrame(br, s.creds, wire.AuthQUIC, exp)
	s.admit.release(conn.RemoteAddr())
	cancelDrop()
	<-dropDone
	if err != nil {
		return
	}
	if release, ok := conn.(qio.PreAuth); ok {
		release.ReleasePreAuth()
	}
	_ = st.SetDeadline(time.Time{})
	router := dgram.NewRouter(conn, s.rt.QUICUDPQueue)
	router.SetOverhead(s.overhead)
	go router.Run(ctx)
	switch role {
	case wire.RoleVector:
		s.serveVectorConn(ctx, conn, router, st, br)
	case wire.RoleEgress:
		s.serveEgressConn(ctx, conn, router, st, br)
	default:
	}
}

func (s *Server) serveVectorConn(ctx context.Context, conn qio.Conn, router *dgram.Router, first qio.Stream, br *bufio.Reader) {
	go s.readAndServe(ctx, router, first, br, true)
	for {
		if !s.flows.try() {
			// The application flow cap is full. Stop accepting until one
			// finishes, so a peer cannot hold a goroutine per stream on QUIC
			// credit alone. The wait is bounded by the flow setup timeout.
			if !s.flows.wait(ctx, s.rt.FlowSetupTimeout) {
				return
			}
		}
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		if st.ID()&2 != 0 || st.ID()&1 != 0 {
			_ = conn.CloseWithError(0, "direction")
			return
		}
		go s.readAndServe(ctx, router, st, bufio.NewReader(st), true)
	}
}

func (s *Server) readAndServe(ctx context.Context, router *dgram.Router, st qio.Stream, br *bufio.Reader, client bool) {
	_ = st.SetReadDeadline(time.Now().Add(s.rt.FlowSetupTimeout))
	kind, target, ok, err := wire.ReadFlowRequest(br)
	_ = st.SetReadDeadline(time.Time{})
	if err != nil || !ok {
		if err != nil {
			_ = wire.WriteSetupResult(st, wire.SetupInvalidRequest)
		}
		_ = st.CloseWrite()
		return
	}
	rw := &pipe{Reader: br, write: st, closer: st}
	s.serveFlow(ctx, kind, target, rw, router, st.ID(), client)
}

func (s *Server) serveFlow(ctx context.Context, kind wire.FlowKind, target wire.Target, client *pipe, router *dgram.Router, streamID uint64, clientInitiated bool) {
	if !s.flows.acquire() {
		_ = wire.WriteSetupResult(client, wire.SetupFlowLimit)
		_ = client.Close()
		return
	}
	defer s.flows.release()
	setupCtx, cancel := context.WithTimeout(ctx, s.rt.FlowSetupTimeout)
	defer cancel()
	if s.egress {
		s.serveViaEgress(setupCtx, kind, target, client, router, streamID)
		return
	}
	var peer net.Conn
	var err error
	if kind == wire.FlowTCP {
		peer, err = s.up.DialTCP(setupCtx, target)
	} else {
		peer, err = s.up.DialUDP(setupCtx, target)
	}
	if err != nil {
		_ = wire.WriteSetupResult(client, wire.SetupDialFailed)
		_ = client.Close()
		return
	}
	defer peer.Close()
	var id uint32
	if kind == wire.FlowUDP && router != nil {
		id, err = wire.UDPFlowID(streamID, !clientInitiated)
		if err != nil {
			_ = wire.WriteSetupResult(client, wire.SetupFlowLimit)
			_ = client.Close()
			return
		}
	}
	if err := wire.WriteSetupResult(client, wire.SetupReady); err != nil {
		return
	}
	if kind == wire.FlowTCP {
		flowio.Relay(client, peer, s.upload, s.download)
		return
	}
	if router == nil {
		relayUoT(client, peer, s.upload, s.download, s.rt.UDPIdleTimeout)
		return
	}
	relayQUICUDP(router, id, client, peer, s.upload, s.download, s.rt.UDPIdleTimeout)
}

func (s *Server) serveViaEgress(ctx context.Context, kind wire.FlowKind, target wire.Target, client *pipe, router *dgram.Router, streamID uint64) {
	deadline, _ := ctx.Deadline()
	if deadline.IsZero() {
		deadline = time.Now().Add(s.rt.FlowSetupTimeout)
	}
	slot, tlsSlot, ok := s.reg.claim(ctx, deadline)
	if !ok {
		_ = wire.WriteSetupResult(client, wire.SetupDialFailed)
		_ = client.Close()
		return
	}
	if tlsSlot && slot.tlsConn == nil {
		_ = wire.WriteSetupResult(client, wire.SetupInternalError)
		_ = client.Close()
		return
	}
	var st qio.Stream
	var err error
	if tlsSlot {
		st = &tlsStream{Conn: slot.tlsConn, reader: slot.reader}
		err = wire.WriteFlowRequest(slot.tlsConn, kind, target)
		if err == nil {
			// The standby read deadline is how the Egress learns it was
			// claimed. Cancelling it here would leave that read parked.
			slot.close()
		}
	} else {
		st, err = slot.conn.OpenStream(ctx)
		if err == nil {
			err = wire.WriteFlowRequest(st, kind, target)
		}
	}
	if err != nil || st == nil {
		if st != nil {
			_ = st.Close()
		}
		_ = wire.WriteSetupResult(client, wire.SetupDialFailed)
		_ = client.Close()
		return
	}
	defer st.Close()
	_ = st.SetReadDeadline(time.Now().Add(timeLeft(ctx, s.rt.FlowSetupTimeout)))
	res, err := wire.ReadSetupResult(st)
	_ = st.SetReadDeadline(time.Time{})
	if err != nil {
		res = wire.SetupDialFailed
	}
	if res != wire.SetupReady {
		_ = wire.WriteSetupResult(client, res)
		_ = client.Close()
		return
	}
	if err := wire.WriteSetupResult(client, wire.SetupReady); err != nil {
		return
	}
	peer := &pipe{Reader: st, write: st, closer: st}
	if kind == wire.FlowTCP {
		flowio.Relay(client, peer, s.upload, s.download)
		return
	}
	switch {
	case router == nil && slot.router == nil:
		relayUoTPair(client, peer, s.upload, s.download)
	case router == nil:
		eid, err := wire.UDPFlowID(st.ID(), true)
		if err != nil {
			return
		}
		bridgeUoT(client, slot.router, eid, peer, s.upload, s.download, true)
	case slot.router == nil:
		vid, err := wire.UDPFlowID(streamID, false)
		if err != nil {
			return
		}
		bridgeUoT(peer, router, vid, client, s.upload, s.download, false)
	default:
		vid, err := wire.UDPFlowID(streamID, false)
		if err != nil {
			return
		}
		eid, err := wire.UDPFlowID(st.ID(), true)
		if err != nil {
			return
		}
		bridgeUDP(router, vid, client, slot.router, eid, peer)
	}
}

// serveEgressTLS registers one TLS connection. It carries a single flow and
// leaves the FIFO when claimed. BUSY does not enter the FIFO. The result reports
// whether the registry took ownership, so serveTCP must not close a claimed flow.
func (s *Server) serveEgressTLS(ctx context.Context, conn net.Conn, br *bufio.Reader) bool {
	if !s.egress || !s.reg.reservePending() {
		_ = wire.WriteRegistrationResult(conn, wire.RegistrationBusy)
		select {
		case <-ctx.Done():
		case <-time.After(s.rt.HandshakeTimeout):
		}
		_ = conn.Close()
		return false
	}
	slot := &egressSlot{
		tls:     true,
		tlsConn: conn,
		reader:  br,
		expires: time.Now().Add(runtime.TLSStandbyTTL),
		dead:    make(chan struct{}),
	}
	if err := wire.WriteRegistrationResult(conn, wire.RegistrationAccepted); err != nil {
		s.reg.releasePending()
		_ = conn.Close()
		return false
	}
	s.reg.push(slot)
	// Standby has nothing to read. Closing the socket unblocks a claim that
	// loses the race with expiry.
	select {
	case <-ctx.Done():
	case <-slot.dead:
	}
	if s.reg.take(slot, true) {
		slot.close()
		_ = conn.Close()
		return false
	}
	return true
}

func (s *Server) serveEgressConn(ctx context.Context, conn qio.Conn, router *dgram.Router, st qio.Stream, br *bufio.Reader) {
	if !s.egress {
		return
	}
	_ = st.SetReadDeadline(time.Now().Add(s.rt.HandshakeTimeout))
	var extra [1]byte
	if n, err := br.Read(extra[:]); n > 0 || (err != nil && !errors.Is(err, io.EOF)) {
		return
	}
	if err := wire.WriteRegistrationResult(st, wire.RegistrationAccepted); err != nil {
		return
	}
	if err := st.CloseWrite(); err != nil {
		return
	}
	slot := &egressSlot{conn: conn, router: router, dead: make(chan struct{})}
	s.reg.push(slot)
	defer func() {
		s.reg.take(slot, false)
		slot.close()
	}()
	for {
		stray, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		// AcceptStream delivers peer-opened streams. A client bidirectional
		// stream is a role-direction violation. Unidirectional streams carry
		// no NW3 messages and are discarded.
		if stray.ID()&2 == 0 && stray.ID()&1 == 0 {
			_ = stray.Close()
			_ = conn.CloseWithError(0, "direction")
			return
		}
		_ = stray.Close()
	}
}

// tlsStream is the single TLS Egress connection after registration. Reads use
// the buffered handshake reader so a pipelined byte is not lost.
type tlsStream struct {
	net.Conn
	reader io.Reader
}

func (s *tlsStream) Read(p []byte) (int, error) {
	if s.reader != nil {
		return s.reader.Read(p)
	}
	return s.Conn.Read(p)
}

func (s *tlsStream) ID() uint64 { return 1 }

func (s *tlsStream) CloseWrite() error {
	if cw, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

type pipe struct {
	io.Reader
	write  io.Writer
	closer io.Closer
}

func (p *pipe) Read(b []byte) (int, error)  { return p.Reader.Read(b) }
func (p *pipe) Write(b []byte) (int, error) { return p.write.Write(b) }
func (p *pipe) Close() error {
	if p.closer != nil {
		return p.closer.Close()
	}
	return nil
}
func (p *pipe) CloseWrite() error {
	if cw, ok := p.write.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	if cw, ok := p.closer.(interface{ CloseWrite() error }); ok {
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

func relayQUICUDP(router *dgram.Router, id uint32, client *pipe, udp net.Conn, up, down *flowio.Limiter, idle time.Duration) {
	flow := router.Register(id)
	defer router.CloseFlow(id)
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		var b [1]byte
		_, _ = client.Read(b[:])
		finish()
	}()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
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
			wg.Wait()
			// The reliable control stream owns the route. CLOSE above is only
			// a hint; FIN is what lets the peer drop it.
			_ = client.CloseWrite()
			return
		case pkt, ok := <-flow.C:
			if !ok {
				wg.Wait()
				_ = client.CloseWrite()
				return
			}
			_ = up.WaitN(context.Background(), len(pkt))
			if _, err := udp.Write(pkt); err != nil {
				finish()
				wg.Wait()
				_ = client.CloseWrite()
				return
			}
		}
	}
}

// relayUoTPair copies length-prefixed datagrams between two TLS UDP flows.
func relayUoTPair(left, right *pipe, up, down *flowio.Limiter) {
	var wg sync.WaitGroup
	wg.Add(2)
	copy := func(dst, src *pipe, lim *flowio.Limiter) {
		defer wg.Done()
		for {
			pkt, err := wire.ReadUoT(src)
			if err != nil {
				break
			}
			_ = lim.WaitN(context.Background(), len(pkt))
			if err := wire.WriteUoT(dst, pkt); err != nil {
				break
			}
		}
		_ = dst.CloseWrite()
	}
	go copy(right, left, up)
	go copy(left, right, down)
	wg.Wait()
}

// bridgeUoT joins one TLS UDP flow to one QUIC datagram flow. toQUIC is true
// when the first pipe is the TLS side.
func bridgeUoT(tls *pipe, router *dgram.Router, id uint32, quic *pipe, up, down *flowio.Limiter, toQUIC bool) {
	if router == nil {
		return
	}
	flow := router.Register(id)
	defer router.CloseFlow(id)
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		var b [1]byte
		_, _ = quic.Read(b[:])
		finish()
	}()
	go func() {
		for {
			pkt, err := wire.ReadUoT(tls)
			if err != nil {
				finish()
				return
			}
			lim := up
			if !toQUIC {
				lim = down
			}
			_ = lim.WaitN(context.Background(), len(pkt))
			if err := router.Send(id, pkt); err != nil {
				finish()
				return
			}
		}
	}()
	for {
		select {
		case <-done:
			_ = tls.CloseWrite()
			_ = quic.CloseWrite()
			return
		case pkt, ok := <-flow.C:
			if !ok {
				_ = tls.CloseWrite()
				_ = quic.CloseWrite()
				return
			}
			lim := down
			if !toQUIC {
				lim = up
			}
			_ = lim.WaitN(context.Background(), len(pkt))
			if err := wire.WriteUoT(tls, pkt); err != nil {
				finish()
				_ = tls.CloseWrite()
				_ = quic.CloseWrite()
				return
			}
		}
	}
}

func bridgeUDP(from *dgram.Router, fromID uint32, fromCtl *pipe, to *dgram.Router, toID uint32, toCtl *pipe) {
	left := from.Register(fromID)
	right := to.Register(toID)
	defer from.CloseFlow(fromID)
	defer to.CloseFlow(toID)
	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }
	go func() {
		var b [1]byte
		_, _ = fromCtl.Read(b[:])
		finish()
	}()
	go func() {
		var b [1]byte
		_, _ = toCtl.Read(b[:])
		finish()
	}()
	for {
		select {
		case <-done:
			_ = fromCtl.CloseWrite()
			_ = toCtl.CloseWrite()
			return
		case pkt, ok := <-left.C:
			if !ok || to.Send(toID, pkt) != nil {
				finish()
			}
		case pkt, ok := <-right.C:
			if !ok || from.Send(fromID, pkt) != nil {
				finish()
			}
		}
	}
}

func exportState(state tls.ConnectionState) (wire.Exporter, error) {
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

func exportConn(conn qio.Conn) (wire.Exporter, error) {
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

func timeLeft(ctx context.Context, fallback time.Duration) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return fallback
	}
	left := time.Until(deadline)
	if left < 0 {
		return 0
	}
	return left
}

type admit struct {
	mu   sync.Mutex
	cond *sync.Cond
	n    int
	per  map[string]int
}

func (a *admit) take(addr net.Addr) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.takeLocked(sourceKey(addr))
}

func (a *admit) takeLocked(key string) bool {
	if a.n >= maxUnauth || a.per[key] >= maxPerSource {
		return false
	}
	a.n++
	a.per[key]++
	return true
}

// wait blocks until a slot is taken, ctx ends, or deadline passes. The
// capacity check and the wait share one lock, so a release cannot pass
// unnoticed between them. It is used only for Morph TCP.
func (a *admit) wait(ctx context.Context, addr net.Addr, deadline time.Time) bool {
	a.mu.Lock()
	if a.cond == nil {
		a.cond = sync.NewCond(&a.mu)
	}
	key := sourceKey(addr)
	timer := time.NewTimer(time.Until(deadline))
	stop := make(chan struct{})
	defer func() {
		timer.Stop()
		close(stop)
	}()
	go func() {
		select {
		case <-timer.C:
		case <-ctx.Done():
		case <-stop:
			return
		}
		a.mu.Lock()
		a.cond.Broadcast()
		a.mu.Unlock()
	}()
	for {
		if a.takeLocked(key) {
			a.mu.Unlock()
			return true
		}
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			a.mu.Unlock()
			return false
		}
		a.cond.Wait()
	}
}

func (a *admit) release(addr net.Addr) {
	key := sourceKey(addr)
	a.mu.Lock()
	if a.n > 0 {
		a.n--
	}
	if a.per[key] > 0 {
		a.per[key]--
	}
	if a.cond != nil {
		a.cond.Broadcast()
	}
	a.mu.Unlock()
}

func setZeroLinger(conn net.Conn) error {
	type linger interface {
		SetLinger(int) error
	}
	if conn, ok := conn.(linger); ok {
		return conn.SetLinger(0)
	}
	return nil
}

func parkUntil(deadline time.Time) {
	if wait := time.Until(deadline); wait > 0 {
		time.Sleep(wait)
	}
}

func sourceKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	v6 := ip.To16()
	if v6 == nil {
		return host
	}
	return hex.EncodeToString(v6[:8])
}

type gate struct {
	mu   sync.Mutex
	cond *sync.Cond
	n    int
}

func (g *gate) acquire() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.n >= maxFlows {
		return false
	}
	g.n++
	return true
}

// try reports whether another flow would fit without taking the slot.
func (g *gate) try() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.n < maxFlows
}

// wait blocks until a flow slot is free, ctx ends, or the bound passes.
func (g *gate) wait(ctx context.Context, bound time.Duration) bool {
	g.mu.Lock()
	if g.cond == nil {
		g.cond = sync.NewCond(&g.mu)
	}
	deadline := time.Now().Add(bound)
	timer := time.AfterFunc(bound, func() {
		g.mu.Lock()
		g.cond.Broadcast()
		g.mu.Unlock()
	})
	defer timer.Stop()
	stop := context.AfterFunc(ctx, func() {
		g.mu.Lock()
		g.cond.Broadcast()
		g.mu.Unlock()
	})
	defer stop()
	for g.n >= maxFlows && ctx.Err() == nil && time.Now().Before(deadline) {
		g.cond.Wait()
	}
	ok := g.n < maxFlows && ctx.Err() == nil
	g.mu.Unlock()
	return ok
}

func (g *gate) release() {
	g.mu.Lock()
	if g.n > 0 {
		g.n--
	}
	if g.cond != nil {
		g.cond.Broadcast()
	}
	g.mu.Unlock()
}
