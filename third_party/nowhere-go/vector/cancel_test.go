package vector

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/flowio"
	"github.com/ohmycggk/nowhere-go/wire"
)

func TestCancelDuringMorphAndSetup(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, morph := range []bool{true, false} {
		t.Run(map[bool]string{true: "morph", false: "setup"}[morph], func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			defer a.Close()
			reached := make(chan struct{})
			if morph {
				close(reached)
			} else {
				go func() {
					server := tls.Server(b, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, NextProtos: []string{wire.ALPN}})
					defer server.Close()
					server.SetDeadline(time.Now().Add(3 * time.Second))
					if err := server.Handshake(); err != nil {
						return
					}
					// Drain auth and request but deliberately never send SetupReady.
					buf := make([]byte, wire.AuthFrameLen)
					if _, err := io.ReadFull(server, buf); err != nil {
						return
					}
					if _, _, _, err := wire.ReadFlowRequest(server); err != nil {
						return
					}
					close(reached)
					server.Read(buf)
				}()
			}
			c, err := New(Config{SharedKey: "0123456789abcdef0123456789abcdef", Morph: morph, TLS: &tls.Config{InsecureSkipVerify: true}, DialTCP: func(context.Context, string) (net.Conn, error) { return a, nil }})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := c.OpenUDP(ctx, wire.Target{Host: "test.example", Port: 53}); done <- err }()
			select {
			case <-reached:
			case <-time.After(time.Second):
				t.Fatal("setup not reached")
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancel succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation left setup blocked")
			}
		})
	}
}

func TestCloseCancelsLimiterWait(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	limiter := flowio.NewMbps(1)
	if err := limiter.WaitN(context.Background(), 125000); err != nil {
		t.Fatal(err)
	}
	c := newLimitedConn(a, limiter, nil)
	defer c.Close()
	done := make(chan error, 1)
	go func() { _, err := c.Write(make([]byte, 65535)); done <- err }()
	c.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed write succeeded")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Close left limiter blocked")
	}
}
