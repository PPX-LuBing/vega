package portal

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/egress"
	"github.com/ohmycggk/nowhere-go/wire"
)

func TestHostEgressIsolationHalfCloseAndCancel(t *testing.T) {
	t.Setenv("NOW_FLOW_SETUP_TIMEOUT", "1s")
	t.Setenv("NOW_HANDSHAKE_TIMEOUT", "1s")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	s, err := New(Config{Users: []User{{Name: "alice", SharedKey: keyAlice}, {Name: "bob", SharedKey: keyBob}}, Morph: true, AcceptEgress: true, Upstream: Direct{}, TLS: &tls.Config{Certificates: []tls.Certificate{testCert(t)}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Serve(ctx, ln)
	done := make(chan error, 1)
	go func() {
		done <- egress.Run(ctx, egress.Config{SharedKey: keyBob, Morph: true, PortalAddr: ln.Addr().String(), TLS: &tls.Config{InsecureSkipVerify: true}, DialTCP: func(ctx context.Context, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
		}, Upstream: Direct{}})
	}()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); b, _ := io.ReadAll(c); _, _ = c.Write(b) }()
		}
	}()
	target := wire.Target{Host: "127.0.0.1", Port: uint16(echo.Addr().(*net.TCPAddr).Port)}
	short, stop := context.WithTimeout(ctx, 60*time.Millisecond)
	if c, err := s.DialEgress(short, "alice", wire.FlowTCP, target); err == nil {
		c.Close()
		t.Fatal("alice consumed bob's exit")
	}
	stop()
	c, err := s.DialEgress(ctx, "bob", wire.FlowTCP, target)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, _ = c.Write([]byte("half-close"))
	if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "half-close" {
		t.Fatalf("half close %q: %v", b, err)
	}
	if err := s.UpdateUsers([]User{{Name: "alice", SharedKey: keyAlice}}); err != nil {
		t.Fatal(err)
	}
	if c, err := s.DialEgress(ctx, "bob", wire.FlowTCP, target); err == nil {
		c.Close()
		t.Fatal("revoked user retained exit")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("egress shutdown stalled")
	}
}

func TestRegistryCanceledClaimDoesNotConsume(t *testing.T) {
	r := newRegistry(1)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if !r.reservePending() {
		t.Fatal("reserve")
	}
	slot := &egressSlot{tls: true, tlsConn: a, dead: make(chan struct{}), expires: time.Now().Add(time.Minute)}
	r.push(slot)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, ok := r.claim(ctx, time.Now().Add(time.Second)); ok {
		t.Fatal("canceled claim consumed slot")
	}
	if got, _, ok := r.claim(context.Background(), time.Now().Add(time.Second)); !ok || got != slot {
		t.Fatal("slot lost")
	}
	slot.close()
	r.close()
}
