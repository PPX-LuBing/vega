// Package cert 统一管理 ACME 证书，做到「一份证书两处用」。
//
// 背景：订阅服务用 autocert 自动签发证书，而 anytls/tuic/nowhere 这些节点需要
// certificate_path/key_path 指向 PEM 文件。两边各管各的话，就得手工从 autocert
// 缓存里拆文件，续期之后节点证书悄悄过期——订阅还能用，节点全挂。
//
// 做法：把 autocert 的 Cache 包一层，Put 时除了写它自己的缓存，再额外落一份稳定
// 的 PEM（<cert_dir>/<域名>/{cert.pem,key.pem}）。内核只读这份稳定文件，面板负责
// 在内容变化后重启内核（sing-box 只在启动时读证书，不重启不生效）。
//
// 不用 sing-box 自带的 certificate_provider：它用 certmagic 的私有目录结构
// （certificates/<ca>/<域名>/<域名>.crt），订阅服务读不了，做不到一份证书两处用。
package cert

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

const (
	// RenewWindow 是 autocert 自己的续期阈值：到期前 30 天（或证书寿命的 1/3，
	// 取小的那个，见 autocert/renewal.go 的 next）。这里跟它保持一致，
	// 免得两边口径不同，出现「面板说该续了、autocert 觉得还早」。
	RenewWindow = 30 * 24 * time.Hour
	// ForceWindow 是「autocert 明显没动静」的阈值。cert renew 只在这个窗口内才
	// 动手重启订阅服务，免得跟 autocert 自己的续期抢 :80 / :443。
	ForceWindow = 14 * 24 * time.Hour
)

// Change 描述一次稳定证书文件的更新。
type Change struct {
	Domain   string
	CertFile string
	KeyFile  string
	NotAfter time.Time
}

// Config 是证书管理的运行参数。
type Config struct {
	// Domain 是签发证书的域名，同时决定稳定文件放在 <CertDir>/<Domain>/。
	Domain string
	// Email 是 ACME 账号邮箱（Let's Encrypt 到期提醒用），可留空。
	Email string
	// CacheDir 是 autocert 自己的缓存目录；面板只经 Cache 接口碰它。
	CacheDir string
	// CertDir 是稳定 PEM 文件的根目录。
	CertDir string
	// OnChange 在稳定文件内容真的变了之后调用。它是同步调用：实现方如果要
	// 重启服务，自己丢 goroutine，别把 TLS 握手或续期协程堵住。
	OnChange func(Change)
}

// Manager 管一个域名的证书：autocert 负责签发续期，它负责把结果落成稳定文件。
type Manager struct {
	cfg   Config
	cache autocert.Cache
	auto  *autocert.Manager

	// writeMu 串行化稳定文件写入：autocert 可能并发写同一域名（ECDSA/RSA 两份，
	// 或签发与续期重叠），同时写会交叉覆盖。
	writeMu sync.Mutex
}

// New 建一个证书管理器。Domain/CacheDir/CertDir 都必填。
func New(cfg Config) (*Manager, error) {
	if err := checkDomain(cfg.Domain); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.CacheDir) == "" {
		return nil, errors.New("cert: 需要 acme 缓存目录")
	}
	if strings.TrimSpace(cfg.CertDir) == "" {
		return nil, errors.New("cert: 需要证书目录")
	}
	m := &Manager{cfg: cfg}
	m.cache = &stableCache{inner: autocert.DirCache(cfg.CacheDir), m: m}
	m.auto = &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cfg.Domain),
		Cache:      m.cache,
		Email:      cfg.Email,
	}
	return m, nil
}

// TLSConfig 给订阅服务用，支持 HTTP/2 与 tls-alpn-01。
func (m *Manager) TLSConfig() *tls.Config {
	config := m.auto.TLSConfig()
	config.MinVersion = tls.VersionTLS12
	return config
}

// HTTPHandler 应答 HTTP-01 挑战，其余请求交给 fallback（一般是跳 HTTPS）。
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	return m.auto.HTTPHandler(fallback)
}

// Domain 返回管理的域名。
func (m *Manager) Domain() string { return m.cfg.Domain }

// CertFile 返回该域名稳定证书文件的路径。
func (m *Manager) CertFile() string {
	certFile, _ := PEMPaths(m.cfg.CertDir, m.cfg.Domain)
	return certFile
}

// KeyFile 返回该域名稳定私钥文件的路径。
func (m *Manager) KeyFile() string {
	_, keyFile := PEMPaths(m.cfg.CertDir, m.cfg.Domain)
	return keyFile
}

// Sync 把 autocert 缓存里已有的证书落成稳定文件，返回内容是否真的变了。
//
// 升级场景需要它：证书是升级前签的，缓存里有、稳定文件没有。不主动搬一次，
// 内核就一直读不到证书。
func (m *Manager) Sync(ctx context.Context) (bool, error) {
	data, err := m.cache.Get(ctx, m.cfg.Domain)
	if errors.Is(err, autocert.ErrCacheMiss) {
		// 还没签过，等签发时 Put 落盘
		return false, nil
	}
	if err != nil {
		return false, err
	}
	m.writeMu.Lock()
	defer m.writeMu.Unlock()
	return m.materialize(data)
}

// Arm 让 autocert 走一遍「要证书」的流程：缓存命中时会顺带起续期定时器
// （到期自动续，续完经 Cache.Put 落成稳定文件），缓存缺失时会立刻签发。
//
// 必须在 ACME 挑战监听（:80 / :443）已经起来之后调用，否则签发一定失败。
// 它可能一直阻塞到签发完成（autocert 内部上限 5 分钟），调用方自己决定
// 要不要放 goroutine。
func (m *Manager) Arm() error {
	if _, err := m.auto.GetCertificate(armHello(m.cfg.Domain)); err != nil {
		return fmt.Errorf("获取 %s 的证书失败: %w", m.cfg.Domain, err)
	}
	return nil
}

// armHello 造一个「现代客户端」的 ClientHelloInfo 交给 autocert。
//
// 为什么不能只填 ServerName：autocert 的 supportsECDSA 会在 hello.CipherSuites
// 里找 ECDSA 套件，一个都找不到就认为「这客户端只支持 RSA」，转而去签一张 RSA
// 证书（缓存键变成 <域名>+rsa）。全空的 ClientHelloInfo 正好落进这个坑——实测
// 它会在服务启动时立刻向 Let's Encrypt 多签一张 RSA 证书，覆盖掉刚迁移出来的
// EC 证书，等于凭空消耗一次签发配额。
func armHello(domain string) *tls.ClientHelloInfo {
	return &tls.ClientHelloInfo{
		ServerName: domain,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256},
		SupportedCurves:   []tls.CurveID{tls.CurveP256},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
	}
}

// Status 报告稳定证书文件的现状。
func (m *Manager) Status() Status {
	return StatusOf(m.cfg.CertDir, m.cfg.Domain)
}

// materialize 把 autocert 缓存内容落成稳定文件，返回内容是否真的变了。
// 调用方必须持有 writeMu。
func (m *Manager) materialize(data []byte) (bool, error) {
	keyPEM, certPEM, err := splitPEM(data)
	if err != nil {
		return false, err
	}
	leaf, err := parseLeaf(certPEM)
	if err != nil {
		return false, err
	}
	// 缓存里可能躺着别的域名的证书（改过域名、或者手动塞过），
	// 落到这个目录就等于给内核发了张用不了的证书，宁可报错。
	if err := leaf.VerifyHostname(m.cfg.Domain); err != nil {
		return false, fmt.Errorf("缓存里的证书不匹配域名 %s: %w", m.cfg.Domain, err)
	}
	certFile, keyFile := m.CertFile(), m.KeyFile()
	changedKey, err := writeIfChanged(keyFile, keyPEM)
	if err != nil {
		return false, err
	}
	changedCert, err := writeIfChanged(certFile, certPEM)
	if err != nil {
		return false, err
	}
	if !changedKey && !changedCert {
		return false, nil
	}
	if m.cfg.OnChange != nil {
		m.cfg.OnChange(Change{Domain: m.cfg.Domain, CertFile: certFile, KeyFile: keyFile, NotAfter: leaf.NotAfter})
	}
	return true, nil
}

// PEMPaths 返回某个域名在 certDir 下的稳定证书文件路径。
//
// 内核侧生成节点配置时用同一套规则，两边必须一致，否则订阅用的证书和节点
// 用的证书会是两份，续期后节点必然失效。
func PEMPaths(certDir, domain string) (certFile, keyFile string) {
	dir := filepath.Join(certDir, domain)
	return filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
}

// Status 是一份证书的现状，给 CLI 和自检用。
type Status struct {
	Domain   string
	CertFile string
	KeyFile  string
	// Exists 表示证书和私钥两个文件都在、且证书能解析。
	Exists   bool
	NotAfter time.Time
	// DaysLeft 是距到期还有几天，已过期就是负数。
	DaysLeft int
	// SHA256 是 cert.pem 的内容指纹，用来判断「内核加载的是不是这一份」。
	SHA256 string
}

// NeedsRenew 报告是否已经进了 autocert 的续期窗口。
func (s Status) NeedsRenew() bool {
	return !s.Exists || time.Until(s.NotAfter) <= RenewWindow
}

// Expiring 报告是否该由人工介入了（autocert 早该续完却还没续）。
func (s Status) Expiring() bool {
	return !s.Exists || time.Until(s.NotAfter) <= ForceWindow
}

// StatusOf 只看文件，不建 Manager —— CLI 的 cert status 用它。
func StatusOf(certDir, domain string) Status {
	certFile, keyFile := PEMPaths(certDir, domain)
	status := Status{Domain: domain, CertFile: certFile, KeyFile: keyFile}
	if _, err := os.Stat(keyFile); err != nil {
		return status
	}
	data, err := os.ReadFile(certFile)
	if err != nil {
		return status
	}
	leaf, err := parseLeaf(data)
	if err != nil {
		return status
	}
	sum := sha256.Sum256(data)
	status.Exists = true
	status.NotAfter = leaf.NotAfter
	status.DaysLeft = int(time.Until(leaf.NotAfter).Hours() / 24)
	status.SHA256 = hex.EncodeToString(sum[:])
	return status
}

// DiscoverDomain 从证书目录里推断域名：只有一个子目录带 cert.pem 时就是它。
// CLI 的 cert 命令用它，免得让运维把域名再配一遍。
func DiscoverDomain(certDir string) (string, error) {
	entries, err := os.ReadDir(certDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("证书目录 %s 还不存在：订阅服务签发第一张证书后会自动创建", certDir)
		}
		return "", fmt.Errorf("读证书目录 %s 失败: %w", certDir, err)
	}
	var found []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(certDir, entry.Name(), "cert.pem")); err == nil {
			found = append(found, entry.Name())
		}
	}
	switch len(found) {
	case 0:
		return "", fmt.Errorf("%s 下还没有证书，用 --domain 指定域名", certDir)
	case 1:
		return found[0], nil
	default:
		return "", fmt.Errorf("%s 下有多个证书（%s），用 --domain 指定", certDir, strings.Join(found, ", "))
	}
}

// checkDomain 只允许能安全当目录名的域名：它会被拼进 <cert_dir>/<域名>/，
// 也会当 autocert 的 cache key（那边的限制是不能含 \/:*?"<>|）。
func checkDomain(domain string) error {
	if strings.TrimSpace(domain) == "" {
		return errors.New("cert: 需要域名")
	}
	if domain == "." || domain == ".." || strings.ContainsAny(domain, `/\:*?"<>|`) {
		return fmt.Errorf("cert: 域名 %q 不能当目录名用", domain)
	}
	return nil
}

// stableCache 包住 autocert 自己的缓存，在证书写入时额外落一份稳定 PEM。
type stableCache struct {
	inner autocert.Cache
	m     *Manager
}

func (c *stableCache) Get(ctx context.Context, key string) ([]byte, error) {
	return c.inner.Get(ctx, key)
}

func (c *stableCache) Delete(ctx context.Context, key string) error {
	return c.inner.Delete(ctx, key)
}

// Put 先按 autocert 的规矩存一份，再把本域名的证书落成稳定文件。
//
// 落盘失败**不**返回错误：autocert 会把 Cache.Put 的错误当成签发失败，
// 一次写盘故障不该把 HTTPS 也拖挂。但也不能装没看见，记日志。
func (c *stableCache) Put(ctx context.Context, key string, data []byte) error {
	if err := c.inner.Put(ctx, key, data); err != nil {
		return err
	}
	if !c.isDomainCert(key) {
		return nil
	}
	c.m.writeMu.Lock()
	defer c.m.writeMu.Unlock()
	if _, err := c.m.materialize(data); err != nil {
		log.Printf("cert: 写稳定证书文件失败（autocert 缓存已更新，内核可能还在用旧证书）: %v", err)
	}
	return nil
}

// isDomainCert 判断这个 cache key 是不是本域名的证书。
//
// autocert 的键（见 autocert.go 的 certKey.String 与 accountKey）：
// 证书是 <域名>（ECDSA）或 <域名>+rsa（客户端不支持 ECDSA 时签的那份），
// tls-alpn-01 的临时证书是 <域名>+token，账号密钥是 acme_account+key。
//
// 只认 <域名> 那一份。稳定文件只能有一份，EC 和 RSA 都往同一个路径写会互相
// 覆盖（谁最后签谁赢），内核就被反复重启。节点客户端是 sing-box 系，都支持
// ECDSA，EC 那份够用——原来的手工拆出来的也是 EC 那份，实测四个协议都通。
func (c *stableCache) isDomainCert(key string) bool {
	return key == c.m.cfg.Domain
}

// splitPEM 拆开 autocert 缓存里的 PEM：私钥一段、证书链一段。
// autocert 存的就是「私钥 PEM + 若干 CERTIFICATE PEM」（见它的 cachePut）。
func splitPEM(data []byte) (keyPEM, certPEM []byte, err error) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case strings.Contains(block.Type, "PRIVATE KEY"):
			keyPEM = pem.EncodeToMemory(block)
		case block.Type == "CERTIFICATE":
			certPEM = append(certPEM, pem.EncodeToMemory(block)...)
		}
	}
	if len(keyPEM) == 0 || len(certPEM) == 0 {
		return nil, nil, errors.New("证书缓存里没有私钥或证书")
	}
	return keyPEM, certPEM, nil
}

// parseLeaf 解析 PEM 里的第一张证书。
func parseLeaf(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("解析证书 PEM 失败")
	}
	return x509.ParseCertificate(block.Bytes)
}

// writeIfChanged 原子写文件；内容一样就什么都不做，避免无谓的内核重启。
func writeIfChanged(path string, data []byte) (bool, error) {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return false, nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	file, err := os.CreateTemp(dir, ".vega-cert-*")
	if err != nil {
		return false, err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if err = file.Chmod(0o600); err != nil {
		file.Close()
		return false, err
	}
	if _, err = file.Write(data); err != nil {
		file.Close()
		return false, err
	}
	if err = file.Close(); err != nil {
		return false, err
	}
	if err = os.Rename(tmp, path); err != nil {
		return false, err
	}
	return true, nil
}
