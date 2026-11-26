package morph

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// 用 Go 标准库 TLS 客户端抓一个**真实**的 ClientHello，验证
// clientHelloWellFormed 不会把它挡掉。
//
// 复现「升级 3.4.0 后 nowhere 连不上」的回归：加固若比真实浏览器更严，
// 合法客户端会被静默丢弃 —— 服务端连日志都不留，极难排查。
func TestRealClientHelloAdmitted(t *testing.T) {
	cert := selfSignedCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	grabbed := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 8192)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := conn.Read(buf)
		if n > 0 {
			grabbed <- append([]byte(nil), buf[:n]...)
		}
		// 用完立刻把连接转给 TLS 服务端，让客户端不会先超时
		select {}
	}()

	go func() {
		conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         "example.com",
			NextProtos:         []string{"h2", "http/1.1"},
		})
		if err == nil {
			io.WriteString(conn, "x")
			conn.Close()
		}
	}()

	var record []byte
	select {
	case record = <-grabbed:
	case <-time.After(8 * time.Second):
		t.Fatal("没抓到 ClientHello")
	}
	_ = cert
	if len(record) < 6 {
		t.Fatalf("记录太短: %d", len(record))
	}
	message := record[5:]
	if !clientHelloWellFormed(message) {
		t.Fatalf("❌ 真实 ClientHello 被拒绝（消息 %d 字节 / 记录 %d 字节）—— 加固过严",
			len(message), len(record))
	}
	t.Logf("✅ 真实 ClientHello（消息 %d 字节）通过校验", len(message))
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost", "example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
