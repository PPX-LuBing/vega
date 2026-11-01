package nowhere

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	singtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

// TestSingboxTLSConfigHandshake 验证「sing-box 的 TLS 配置能直接喂给
// portal 的 tls.Server」这个关键假设。
//
// 这个假设一旦不成立，portal 的握手会在 0.x 毫秒内失败，而日志里
// 什么都不会有——排查成本极高，所以钉成测试。
func TestSingboxTLSConfigHandshake(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t)
	ctx := context.Background()
	logger := log.NewNOPFactory().NewLogger("tls-test")

	serverTLS, err := singtls.NewServer(ctx, logger, option.InboundTLSOptions{
		Enabled:     true,
		Certificate: []string{certPEM},
		Key:         []string{keyPEM},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Start() 之前取一次：如果这时是空壳，说明必须等 Start 之后才能取。
	before, err := serverTLS.STDConfig()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Start 之前: certificates=%d getCertificate=%v nextProtos=%v",
		len(before.Certificates), before.GetCertificate != nil, before.NextProtos)

	if err = serverTLS.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverTLS.Close() })

	after, err := serverTLS.STDConfig()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Start 之后: certificates=%d getCertificate=%v getConfigForClient=%v nextProtos=%v",
		len(after.Certificates), after.GetCertificate != nil, after.GetConfigForClient != nil, after.NextProtos)

	// 修复前的样子：sing-box 的 GetConfigForClient 返回原始 config，
	// portal 在副本上设的 ALPN 会被绕过 —— 这里先钉住这个行为。
	unwrapped := after.Clone()
	unwrapped.MinVersion = tls.VersionTLS13
	unwrapped.MaxVersion = tls.VersionTLS13
	unwrapped.NextProtos = []string{"nw3"}
	if alpn := handshakeALPN(t, unwrapped); alpn != "" {
		t.Logf("注意：未包装时 ALPN 已经是 %q（上游行为可能已变）", alpn)
	} else {
		t.Logf("未包装时 ALPN 为空 —— 正是 wrapALPN 要修的问题")
	}

	// 修复后：走 portalTLS（内部会 wrapALPN）
	fixed, err := portalTLS(serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	fixedCfg := fixed.Clone()
	fixedCfg.MinVersion = tls.VersionTLS13
	fixedCfg.MaxVersion = tls.VersionTLS13
	fixedCfg.NextProtos = []string{"nw3"}
	fixedCfg.SessionTicketsDisabled = true
	if alpn := handshakeALPN(t, fixedCfg); alpn != "nw3" {
		t.Fatalf("wrapALPN 之后 ALPN 仍不对: %q", alpn)
	}
	t.Logf("wrapALPN 之后 ALPN 协商成功: nw3")
}

// handshakeALPN 起一个真实 TCP 监听做一次 TLS 握手，返回协商到的 ALPN。
func handshakeALPN(t *testing.T, serverCfg *tls.Config) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		raw, acceptErr := ln.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer raw.Close()
		conn := tls.Server(raw, serverCfg)
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if handshakeErr := conn.Handshake(); handshakeErr != nil {
			serverErr <- handshakeErr
			return
		}
		serverErr <- nil
	}()

	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	clientConn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"nw3"},
		MinVersion:         tls.VersionTLS13,
	})
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	if err = clientConn.Handshake(); err != nil {
		t.Fatalf("客户端握手失败: %v", err)
	}
	if err = <-serverErr; err != nil {
		t.Fatalf("服务端握手失败: %v", err)
	}
	return clientConn.ConnectionState().NegotiatedProtocol
}

// selfSignedPEM 生成一对自签证书，返回 PEM 文本。
func selfSignedPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "nowhere-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"nowhere-test"},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certPEM), string(keyPEM)
}
