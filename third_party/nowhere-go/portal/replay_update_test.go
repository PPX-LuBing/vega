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
