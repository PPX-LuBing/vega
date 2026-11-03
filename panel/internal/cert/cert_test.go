package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// selfSigned 造一份「私钥 PEM + 证书 PEM」，格式跟 autocert 写进缓存的一模一样。
func selfSigned(t *testing.T, domain string, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    notAfter.Add(-90 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return append(body, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
}

func newTestManager(t *testing.T, changes *[]Change) *Manager {
	t.Helper()
	dir := t.TempDir()
	manager, err := New(Config{
		Domain:   "hk.example.com",
		CacheDir: filepath.Join(dir, "acme"),
		CertDir:  filepath.Join(dir, "certs"),
		OnChange: func(change Change) {
			if changes != nil {
				*changes = append(*changes, change)
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestPutWritesStableFiles(t *testing.T) {
	var changes []Change
	manager := newTestManager(t, &changes)
	expiry := time.Now().Add(90 * 24 * time.Hour).Truncate(time.Second)

	if err := manager.cache.Put(context.Background(), "hk.example.com", selfSigned(t, "hk.example.com", expiry)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{manager.CertFile(), manager.KeyFile()} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s 没写出来: %v", path, err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s 权限是 %o，应该是 600", path, perm)
		}
	}
	status := manager.Status()
	if !status.Exists {
		t.Fatal("Status 说证书不存在")
	}
	if !status.NotAfter.Equal(expiry) {
		t.Errorf("到期时间 = %s，想要 %s", status.NotAfter, expiry)
	}
	if len(changes) != 1 {
		t.Fatalf("OnChange 调了 %d 次，想要 1 次", len(changes))
	}
	if !changes[0].NotAfter.Equal(expiry) {
		t.Errorf("OnChange 里的到期时间 = %s，想要 %s", changes[0].NotAfter, expiry)
	}
}

func TestPutIgnoresNonCertificateKeys(t *testing.T) {
	var changes []Change
	manager := newTestManager(t, &changes)
	ctx := context.Background()
	cert := selfSigned(t, "hk.example.com", time.Now().Add(90*24*time.Hour))

	for _, key := range []string{"acme_account+key", "acme_account.key", "hk.example.com+token", "other.example.com"} {
		if err := manager.cache.Put(ctx, key, cert); err != nil {
			t.Fatalf("Put(%q) 报错: %v", key, err)
		}
	}
	if _, err := os.Stat(manager.CertFile()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("非证书键不该写出稳定文件，实际 err=%v", err)
	}
	if len(changes) != 0 {
		t.Fatalf("非证书键触发了 %d 次 OnChange", len(changes))
	}
}

// RSA 那份（<域名>+rsa）不能写稳定文件：它和 EC 那份抢同一个路径，
// 谁最后签谁赢，内核会被反复重启。
func TestPutIgnoresRSAVariant(t *testing.T) {
	var changes []Change
	manager := newTestManager(t, &changes)
	ctx := context.Background()
	if err := manager.cache.Put(ctx, "hk.example.com", selfSigned(t, "hk.example.com", time.Now().Add(90*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	before := manager.Status().SHA256
	if err := manager.cache.Put(ctx, "hk.example.com+rsa", selfSigned(t, "hk.example.com", time.Now().Add(60*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if after := manager.Status().SHA256; after != before {
		t.Fatalf("+rsa 那份把稳定文件覆盖了: %s -> %s", before, after)
	}
	if len(changes) != 1 {
		t.Fatalf("OnChange 调了 %d 次，想要 1 次", len(changes))
	}
}

// 这条不变量是踩过坑的：autocert 的 supportsECDSA 在 hello.CipherSuites 里找
// ECDSA 套件，一个都没有就认为「客户端只支持 RSA」，于是去签一张 RSA 证书。
// 曾经这里传的是只填了 ServerName 的空 ClientHelloInfo，结果服务一启动就
// 向 Let's Encrypt 多签一张 RSA 证书，把刚迁移出来的 EC 证书覆盖掉。
func TestArmHelloAdvertisesECDSA(t *testing.T) {
	hello := armHello("hk.example.com")
	if hello.ServerName != "hk.example.com" {
		t.Fatalf("ServerName = %q", hello.ServerName)
	}
	ecdsaSuite := false
	for _, suite := range hello.CipherSuites {
		switch suite {
		case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
			ecdsaSuite = true
		}
	}
	if !ecdsaSuite {
		t.Fatal("ClientHello 里没有 ECDSA 套件，autocert 会误判成「只支持 RSA」并多签一张证书")
	}
	if len(hello.SupportedCurves) == 0 || len(hello.SignatureSchemes) == 0 {
		t.Fatal("ClientHello 缺 SupportedCurves / SignatureSchemes")
	}
	for _, proto := range hello.SupportedProtos {
		if proto == "acme-tls/1" {
			t.Fatal("不能宣告 acme-tls/1，否则会被当成 tls-alpn-01 挑战证书")
		}
	}
}

// 内容没变就不该回调：否则每次续期检查都会重启一遍内核。
func TestPutUnchangedDoesNotNotify(t *testing.T) {
	var changes []Change
	manager := newTestManager(t, &changes)
	ctx := context.Background()
	data := selfSigned(t, "hk.example.com", time.Now().Add(90*24*time.Hour))
	for i := 0; i < 3; i++ {
		if err := manager.cache.Put(ctx, "hk.example.com", data); err != nil {
			t.Fatal(err)
		}
	}
	if len(changes) != 1 {
		t.Fatalf("OnChange 调了 %d 次，想要 1 次", len(changes))
	}
}

// 升级场景：证书在 autocert 缓存里，稳定文件还没有。Sync 要能把它搬出来。
func TestSyncMaterializesExistingCache(t *testing.T) {
	var changes []Change
	manager := newTestManager(t, &changes)
	cache := autocert.DirCache(manager.cfg.CacheDir)
	expiry := time.Now().Add(60 * 24 * time.Hour).Truncate(time.Second)
	if err := cache.Put(context.Background(), "hk.example.com", selfSigned(t, "hk.example.com", expiry)); err != nil {
		t.Fatal(err)
	}
	changed, err := manager.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("Sync 说没变化，但稳定文件本来不存在")
	}
	if got := manager.Status().NotAfter; !got.Equal(expiry) {
		t.Fatalf("到期时间 = %s，想要 %s", got, expiry)
	}
	// 再同步一次就是幂等的
	changed, err = manager.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("第二次 Sync 不该有变化")
	}
	if len(changes) != 1 {
		t.Fatalf("OnChange 调了 %d 次，想要 1 次", len(changes))
	}
}

// 缓存里没有证书时 Sync 不是错误：第一次启动就是这样。
func TestSyncWithoutCacheIsNoop(t *testing.T) {
	manager := newTestManager(t, nil)
	changed, err := manager.Sync(context.Background())
	if err != nil {
		t.Fatalf("Sync 报错: %v", err)
	}
	if changed {
		t.Fatal("空缓存不该有变化")
	}
}

// 缓存里躺着别的域名的证书时不能往这个目录写。
func TestMaterializeRejectsWrongDomain(t *testing.T) {
	manager := newTestManager(t, nil)
	err := manager.cache.Put(context.Background(), "hk.example.com", selfSigned(t, "other.example.com", time.Now().Add(90*24*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(manager.CertFile()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("域名不匹配却写了稳定文件，err=%v", err)
	}
}

func TestStatusOfMissingFiles(t *testing.T) {
	dir := t.TempDir()
	status := StatusOf(dir, "hk.example.com")
	if status.Exists {
		t.Fatal("文件不存在时 Exists 应该是 false")
	}
	if !status.NeedsRenew() || !status.Expiring() {
		t.Fatal("文件不存在时应当算需要续期")
	}
}

func TestStatusWindows(t *testing.T) {
	cases := []struct {
		days          int
		needs, expire bool
	}{
		{60, false, false},
		{20, true, false},
		{10, true, true},
		{-1, true, true},
	}
	for _, tc := range cases {
		status := Status{Exists: true, NotAfter: time.Now().Add(time.Duration(tc.days) * 24 * time.Hour)}
		if got := status.NeedsRenew(); got != tc.needs {
			t.Errorf("还剩 %d 天: NeedsRenew=%t，想要 %t", tc.days, got, tc.needs)
		}
		if got := status.Expiring(); got != tc.expire {
			t.Errorf("还剩 %d 天: Expiring=%t，想要 %t", tc.days, got, tc.expire)
		}
	}
}

func TestDiscoverDomain(t *testing.T) {
	dir := t.TempDir()
	if _, err := DiscoverDomain(dir); err == nil {
		t.Fatal("空目录应该报错")
	}
	if err := os.MkdirAll(filepath.Join(dir, "a.example.com"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.example.com", "cert.pem"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	domain, err := DiscoverDomain(dir)
	if err != nil {
		t.Fatal(err)
	}
	if domain != "a.example.com" {
		t.Fatalf("推断出的域名 = %q", domain)
	}
	if err := os.MkdirAll(filepath.Join(dir, "b.example.com"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.example.com", "cert.pem"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := DiscoverDomain(dir); err == nil {
		t.Fatal("两个证书时应该报错让人显式指定")
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	dir := t.TempDir()
	for name, cfg := range map[string]Config{
		"空域名":   {CacheDir: dir, CertDir: dir},
		"域名带斜杠": {Domain: "a/b", CacheDir: dir, CertDir: dir},
		"域名是点点": {Domain: "..", CacheDir: dir, CertDir: dir},
		"缺缓存目录": {Domain: "a.example.com", CertDir: dir},
		"缺证书目录": {Domain: "a.example.com", CacheDir: dir},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: 应该报错", name)
		}
	}
}

func TestStatusRejectsMismatchedKey(t *testing.T) {
	manager := newTestManager(t, nil)
	ctx := context.Background()
	if err := manager.cache.Put(ctx, "hk.example.com", selfSigned(t, "hk.example.com", time.Now().Add(90*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	otherKey, _, err := splitPEM(selfSigned(t, "hk.example.com", time.Now().Add(90*24*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(manager.KeyFile(), otherKey, 0600); err != nil {
		t.Fatal(err)
	}
	if manager.Status().Exists {
		t.Fatal("mismatched key considered valid")
	}
	if _, err = manager.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if !manager.Status().Exists {
		t.Fatal("cache sync did not repair key")
	}
}
