package nowhere

import (
	"bytes"
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	singtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
)

func TestCertificateHotReload(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	before, key := selfSignedPEM(t)
	if err := os.WriteFile(certFile, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte(key), 0600); err != nil {
		t.Fatal(err)
	}
	conf, err := singtls.NewServer(context.Background(), log.NewNOPFactory().NewLogger("review"), option.InboundTLSOptions{Enabled: true, CertificatePath: certFile, KeyPath: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	if err = conf.Start(); err != nil {
		t.Fatal(err)
	}
	defer conf.Close()
	sharedConfig, err := conf.STDConfig()
	if err != nil {
		t.Fatal(err)
	}
	portalConfig, err := portalTLS(conf)
	if err != nil {
		t.Fatal(err)
	}
	if portalConfig == sharedConfig {
		t.Fatal("portal modified the shared TLS configuration")
	}
	after, newKey := selfSignedPEM(t)
	want, err := tls.X509KeyPair([]byte(after), []byte(newKey))
	if err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string]string{keyFile: newKey, certFile: after} {
		tmp := path + ".new"
		if err = os.WriteFile(tmp, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if err = os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		got, err := portalConfig.GetConfigForClient(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(got.Certificates[0].Certificate[0], want.Certificate[0]) {
			t.Log("new certificate observed through Nowhere portalTLS without restart")
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("new certificate not observed")
}
