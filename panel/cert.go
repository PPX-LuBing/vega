package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/cert"
	"github.com/PPX-LuBing/vega/panel/internal/kernel"
)

// defaultSubService 是订阅服务名。cert renew 靠重启它来触发续期。
const defaultSubService = "vega-sub"

// runCert 管理面板统一签发的证书。
//
// 订阅服务和节点共用 <cert-dir>/<域名>/{cert.pem,key.pem} 这一份文件：
// 订阅服务负责签发和续期，节点只读（内核不重启不会重新加载）。
func runCert(paths kernel.Paths, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("用法: cert status | cert renew")
	}
	fs := flag.NewFlagSet("cert "+args[0], flag.ContinueOnError)
	domain := fs.String("domain", "", "证书域名；留空则从证书目录里推断")
	certDir := fs.String("cert-dir", paths.CertDir, "证书目录（默认取 SBX_PANEL_CERT_DIR）")
	wait := fs.Duration("wait", 3*time.Minute, "renew 等待续期完成的时长")
	if err := fs.Parse(reorderArgs(fs, args[1:])); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("用法: cert status | cert renew")
	}
	resolved, err := resolveCertDomain(*certDir, *domain)
	if err != nil {
		return err
	}
	switch args[0] {
	case "status":
		return certStatus(*certDir, resolved)
	case "renew":
		return certRenew(*certDir, resolved, *wait)
	default:
		return fmt.Errorf("未知子命令: cert %s（试 status / renew）", args[0])
	}
}

// certStatus 打印证书现状。文件不存在时返回错误，好让定时器能报警。
func certStatus(certDir, domain string) error {
	status := cert.StatusOf(certDir, domain)
	fmt.Printf("域名:  %s\n", status.Domain)
	fmt.Printf("证书:  %s\n", status.CertFile)
	fmt.Printf("私钥:  %s\n", status.KeyFile)
	if !status.Exists {
		return fmt.Errorf("还没有证书文件；订阅服务签发后会自动出现，先确认订阅服务在跑")
	}
	fmt.Printf("到期:  %s（还剩 %d 天）\n", status.NotAfter.Local().Format("2006-01-02 15:04:05"), status.DaysLeft)
	fmt.Printf("指纹:  sha256:%s\n", status.SHA256)
	if status.NeedsRenew() {
		fmt.Println("状态:  ⚠ 已进续期窗口（到期前 30 天），autocert 会自己续；一直没动静就跑 cert renew")
	} else {
		fmt.Println("状态:  ✓")
	}
	return nil
}

// certRenew 触发一次续期。
//
// 它自己不能签：ACME 的挑战端口（:80 / :8443）在订阅服务手里，另起进程抢不到
// 端口，签发必然失败。所以走「重启订阅服务」——服务启动时会重新走一遍 autocert
// 的取证书流程，快到期就立刻续，续完写稳定文件并重启内核。
//
// 只在 autocert 明显没动静时才动手（14 天内到期，或文件根本不在），免得跟它
// 自己的续期抢端口、把挑战打断。
func certRenew(certDir, domain string, wait time.Duration) error {
	before := cert.StatusOf(certDir, domain)
	if !before.Expiring() {
		fmt.Printf("证书还剩 %d 天，autocert 会自己续，不动它。\n", before.DaysLeft)
		return nil
	}
	service := strings.TrimSpace(os.Getenv("SBX_PANEL_SUB_SERVICE"))
	if service == "" {
		service = defaultSubService
	}
	if before.Exists {
		fmt.Printf("证书只剩 %d 天（%s 到期），重启订阅服务 %s 触发续期…\n",
			before.DaysLeft, before.NotAfter.Local().Format("2006-01-02"), service)
	} else {
		fmt.Printf("还没有证书文件，重启订阅服务 %s 触发签发…\n", service)
	}
	if err := exec.Command("systemctl", "restart", service).Run(); err != nil {
		return fmt.Errorf("重启 %s 失败: %w", service, err)
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Second)
		now := cert.StatusOf(certDir, domain)
		if now.Exists && (!before.Exists || now.NotAfter.After(before.NotAfter)) {
			fmt.Printf("续期成功：新证书 %s 到期（还剩 %d 天）。\n",
				now.NotAfter.Local().Format("2006-01-02 15:04"), now.DaysLeft)
			return nil
		}
	}
	return fmt.Errorf("等了 %s 还没看到新证书，看日志: journalctl -u %s -n 50", wait, service)
}

// resolveCertDomain 优先用显式给的域名，否则从证书目录里推断。
func resolveCertDomain(certDir, domain string) (string, error) {
	if trimmed := strings.TrimSpace(domain); trimmed != "" {
		return trimmed, nil
	}
	return cert.DiscoverDomain(certDir)
}
