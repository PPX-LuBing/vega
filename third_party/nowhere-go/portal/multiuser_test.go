package portal

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/vector"
	"github.com/ohmycggk/nowhere-go/wire"
)

// recordingUpstream 记录每次拨号时 context 里的用户名。
//
// 身份是靠 Morph prelude 试解出来的（AuthFrame 没有身份字段），
// 所以只有真正走到 Upstream 才能证明「用户被认出来了」。
type recordingUpstream struct {
	Direct
	users chan string
}

func (u *recordingUpstream) DialTCP(ctx context.Context, target wire.Target) (net.Conn, error) {
	select {
	case u.users <- UserFromContext(ctx):
	default:
	}
	return u.Direct.DialTCP(ctx, target)
}

const (
	keyAlice   = "0123456789abcdef0123456789abcdef"
	keyBob     = "fedcba9876543210fedcba9876543210"
	keyUnknown = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// 多用户 Portal：两个用户各自的密钥都能连上，且被识别成正确的用户。
func TestMultiUserPortalIdentifiesUser(t *testing.T) {
	for _, morph := range []bool{false, true} {
		name := map[bool]string{false: "plain", true: "morph"}[morph]
		t.Run(name, func(t *testing.T) {
			echo := echoServer(t)
			cert := testCert(t)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			recorder := &recordingUpstream{users: make(chan string, 4)}
			srv, err := New(Config{
				Users: []User{
					{Name: "alice", SharedKey: keyAlice},
					{Name: "bob", SharedKey: keyBob},
				},
				Morph:    morph,
				TLS:      &tls.Config{Certificates: []tls.Certificate{cert}},
				Upstream: recorder,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !srv.multiUser() {
				t.Fatal("应当进入多用户模式")
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = srv.Serve(ctx, ln) }()

			// 用第二个用户（bob）的密钥连接
			conn := dialAs(t, ln, keyBob, morph, echo)
			defer conn.Close()

			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(conn, buf); err != nil {
				t.Fatal(err)
			}
			if string(buf) != "ping" {
				t.Fatalf("回显错误: %q", buf)
			}

			select {
			case got := <-recorder.users:
				if got != "bob" {
					t.Fatalf("用户识别错误：期望 bob，得到 %q", got)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Upstream 没有被调用")
			}
		})
	}
}

// 不在名单里的密钥必须被拒（否则多用户就形同虚设）。
func TestMultiUserPortalRejectsUnknownKey(t *testing.T) {
	for _, morph := range []bool{false, true} {
		name := map[bool]string{false: "plain", true: "morph"}[morph]
		t.Run(name, func(t *testing.T) {
			echo := echoServer(t)
			cert := testCert(t)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			srv, err := New(Config{
				Users: []User{
					{Name: "alice", SharedKey: keyAlice},
					{Name: "bob", SharedKey: keyBob},
				},
				Morph:    morph,
				TLS:      &tls.Config{Certificates: []tls.Certificate{cert}},
				Upstream: Direct{},
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = srv.Serve(ctx, ln) }()

			conn := dialAs(t, ln, keyUnknown, morph, echo)
			defer conn.Close()
			_ = echo

			// 写入应当失败或读不到回显：无论如何都不能正常建立 flow
			_, _ = conn.Write([]byte("ping"))
			buf := make([]byte, 4)
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			if n, err := conn.Read(buf); err == nil && n > 0 {
				t.Fatalf("未知密钥竟然拿到了 %d 字节数据", n)
			}
		})
	}
}

// 单密钥与多用户互斥，配置错误要在构造期就报出来。
func TestConfigValidation(t *testing.T) {
	cert := testCert(t)
	base := func() Config {
		return Config{
			Morph:    true,
			TLS:      &tls.Config{Certificates: []tls.Certificate{cert}},
			Upstream: Direct{},
		}
	}

	cfg := base()
	if _, err := New(cfg); err == nil {
		t.Fatal("既没有 shared_key 也没有 users，应当报错")
	}

	cfg = base()
	cfg.SharedKey = keyAlice
	cfg.Users = []User{{Name: "alice", SharedKey: keyAlice}}
	if _, err := New(cfg); err == nil {
		t.Fatal("shared_key 与 users 同时给出，应当报错")
	}

	cfg = base()
	cfg.Users = []User{{Name: "alice", SharedKey: "not-hex"}}
	if _, err := New(cfg); err == nil {
		t.Fatal("用户密钥格式非法，应当报错")
	}

	// 多用户 + QUIC 目前不支持，必须显式报错而不是崩掉
	cfg = base()
	cfg.Users = []User{{Name: "alice", SharedKey: keyAlice}}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ServeQUIC(context.Background(), nil); err == nil {
		t.Fatal("多用户 QUIC 应当明确报错")
	}
}

// dialAs 用指定密钥作为 Vector 连上 Portal，返回一条已认证的 flow 连接。
func dialAs(t *testing.T, ln net.Listener, key string, morph bool, targetAddr string) net.Conn {
	t.Helper()
	client, err := vector.New(vector.Config{
		SharedKey:  key,
		Morph:      morph,
		PortalAddr: ln.Addr().String(),
		TLS: &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "nowhere",
		},
		DialTCP: func(ctx context.Context, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	target := ipTarget(t, targetAddr)
	flowCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	conn, err := client.OpenTCP(flowCtx, target)
	if err != nil {
		// 认证失败时 OpenTCP 会报错，这是预期路径之一
		return errConn{err: err}
	}
	return conn
}

func ipTarget(t *testing.T, addr string) wire.Target {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	target, err := wire.NewIPTarget(netip.MustParseAddr(host), mustPort(t, port))
	if err != nil {
		t.Fatal(err)
	}
	return target
}

// errConn 把 OpenTCP 的错误包成 net.Conn，让调用方统一处理。
type errConn struct{ err error }

func (c errConn) Read([]byte) (int, error)         { return 0, c.err }
func (c errConn) Write([]byte) (int, error)        { return 0, c.err }
func (c errConn) Close() error                     { return nil }
func (c errConn) LocalAddr() net.Addr              { return nil }
func (c errConn) RemoteAddr() net.Addr             { return nil }
func (c errConn) SetDeadline(time.Time) error      { return nil }
func (c errConn) SetReadDeadline(time.Time) error  { return nil }
func (c errConn) SetWriteDeadline(time.Time) error { return nil }

// UpdateUsers 必须在运行期生效：新连接按新名单认证，且不需要重启监听。
func TestUpdateUsersAtRuntime(t *testing.T) {
	for _, morph := range []bool{false, true} {
		name := map[bool]string{false: "plain", true: "morph"}[morph]
		t.Run(name, func(t *testing.T) {
			echo := echoServer(t)
			cert := testCert(t)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			srv, err := New(Config{
				Users:    []User{{Name: "alice", SharedKey: keyAlice}},
				Morph:    morph,
				TLS:      &tls.Config{Certificates: []tls.Certificate{cert}},
				Upstream: Direct{},
			})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = srv.Serve(ctx, ln) }()

			// 初始：alice 能通
			if !echoThrough(t, ln, keyAlice, morph, echo) {
				t.Fatal("初始用户 alice 应当能连上")
			}

			// 运行期换成只有 bob
			if err := srv.UpdateUsers([]User{{Name: "bob", SharedKey: keyBob}}); err != nil {
				t.Fatal(err)
			}

			// bob 立刻可用，alice 立刻失效——监听没动过
			if !echoThrough(t, ln, keyBob, morph, echo) {
				t.Fatal("换人后 bob 应当能连上")
			}
			if echoThrough(t, ln, keyAlice, morph, echo) {
				t.Fatal("换人后 alice 不该还能连上")
			}

			// 再换一次：加回 alice
			if err = srv.UpdateUsers([]User{
				{Name: "alice", SharedKey: keyAlice},
				{Name: "bob", SharedKey: keyBob},
			}); err != nil {
				t.Fatal(err)
			}
			if !echoThrough(t, ln, keyAlice, morph, echo) {
				t.Fatal("加回后 alice 应当能连上")
			}

			// 非法密钥要在改之前就被拦下，不能把名单改坏
			if err = srv.UpdateUsers([]User{{Name: "bad", SharedKey: "not-hex"}}); err == nil {
				t.Fatal("非法密钥应当报错")
			}
			if !echoThrough(t, ln, keyAlice, morph, echo) {
				t.Fatal("失败的 UpdateUsers 不该破坏原名单")
			}
		})
	}
}

// 单密钥模式不支持运行期改用户，必须明确报错而不是静默无效。
func TestUpdateUsersRejectsSingleKeyMode(t *testing.T) {
	cert := testCert(t)
	srv, err := New(Config{
		SharedKey: keyAlice,
		Morph:     true,
		TLS:       &tls.Config{Certificates: []tls.Certificate{cert}},
		Upstream:  Direct{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = srv.UpdateUsers([]User{{Name: "bob", SharedKey: keyBob}}); err == nil {
		t.Fatal("单密钥模式应当拒绝运行期改用户")
	}
}

// echoThrough 用指定密钥连一次并回显，成功返回 true。
func echoThrough(t *testing.T, ln net.Listener, key string, morph bool, echo string) bool {
	t.Helper()
	conn := dialAs(t, ln, key, morph, echo)
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		return false
	}
	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return false
	}
	return string(buf) == "ping"
}

