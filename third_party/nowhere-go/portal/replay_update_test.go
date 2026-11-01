package portal

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/morph"
)

type auditCapture struct{ bytes.Buffer }

func (*auditCapture) Read([]byte) (int, error)         { return 0, io.EOF }
func (*auditCapture) Close() error                     { return nil }
func (*auditCapture) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*auditCapture) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*auditCapture) SetDeadline(time.Time) error      { return nil }
func (*auditCapture) SetReadDeadline(time.Time) error  { return nil }
func (*auditCapture) SetWriteDeadline(time.Time) error { return nil }
func TestUserSyncPreservesReplayProtection(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef"
	users := []User{{Name: "alice", SharedKey: key}}
	s, err := New(Config{Users: users, Morph: true, TLS: &tls.Config{}, Upstream: Direct{}})
	if err != nil {
		t.Fatal(err)
	}
	raw := &auditCapture{}
	client, err := morph.WrapTCPClient(raw, morph.Derive([]byte(key)))
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(client, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"nw3"}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	_ = tc.Handshake()
	flight := append([]byte(nil), raw.Bytes()...)
	if len(flight) < 76 {
		t.Fatal("missing client first flight")
	}
	accept := func() error {
		_, keys, _ := s.snapshotUsers()
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		_ = b.SetDeadline(time.Now().Add(time.Second))
		go func() { _, _ = a.Write(flight) }()
		_, err := morph.WrapTCPServerMulti(b, keys).Read(make([]byte, 1))
		return err
	}
	if err = accept(); err != nil {
		t.Fatal(err)
	}
	if err = accept(); !errors.Is(err, morph.ErrPreludeRejected) {
		t.Fatalf("replay not rejected: %v", err)
	}
	if err = s.UpdateUsers(users); err != nil {
		t.Fatal(err)
	}
	if err = accept(); !errors.Is(err, morph.ErrPreludeRejected) {
		t.Fatalf("replay accepted after user sync: %v", err)
	}
}

// UserCount 是控制端点 /health 的数据来源。写死 0 会让运维以为名单是空的，
// 所以三种模式（单密钥、多用户、空名单）都要如实报数。
func TestServerUserCount(t *testing.T) {
	cert := testCert(t)
	single, err := New(Config{SharedKey: keyAlice, TLS: &tls.Config{Certificates: []tls.Certificate{cert}}, Upstream: Direct{}})
	if err != nil {
		t.Fatal(err)
	}
	if got := single.UserCount(); got != 1 {
		t.Fatalf("单密钥模式应报 1 人，实际 %d", got)
	}

	multi, err := New(Config{
		Users:    []User{{Name: "alice", SharedKey: keyAlice}, {Name: "bob", SharedKey: keyBob}},
		TLS:      &tls.Config{Certificates: []tls.Certificate{cert}},
		Upstream: Direct{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := multi.UserCount(); got != 2 {
		t.Fatalf("多用户模式应报 2 人，实际 %d", got)
	}
	if err = multi.UpdateUsers([]User{{Name: "alice", SharedKey: keyAlice}}); err != nil {
		t.Fatal(err)
	}
	if got := multi.UserCount(); got != 1 {
		t.Fatalf("换名单后应报 1 人，实际 %d", got)
	}
	// 清空名单是合法操作（把人都摘掉），要报 0 而不是报错
	if err = multi.UpdateUsers(nil); err != nil {
		t.Fatal(err)
	}
	if got := multi.UserCount(); got != 0 {
		t.Fatalf("清空后应报 0 人，实际 %d", got)
	}

	var nilServer *Server
	if got := nilServer.UserCount(); got != 0 {
		t.Fatalf("nil Server 应报 0，实际 %d", got)
	}
}
