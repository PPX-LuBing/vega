package sub

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/store"
	"gopkg.in/yaml.v3"
)

func TestAllSubscriptionProtocolsWithRealKernel(t *testing.T) {
	bin := os.Getenv("VEGA_TEST_KERNEL")
	if bin == "" {
		t.Skip("set VEGA_TEST_KERNEL for native config checks")
	}
	st := testStore(t)
	u := seed(t, st)
	body, _, err := Singbox(st, u)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "client.json")
	if err := os.WriteFile(file, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "check", "-c", file).CombinedOutput(); err != nil {
		t.Fatalf("check failed: %s %v", out, err)
	}
}

func TestClashStrictYAMLAndUniqueNames(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)
	for _, proto := range []string{store.ProtoVMess, store.ProtoTrojan} {
		n := store.Node{Tag: proto, Proto: proto, Port: 443, Enabled: true, TLSMode: "tls", SNI: "origin.example", EntrySNI: "entry.example", Transport: "ws", Path: "/proxy", Host: "ws.example", Remark: "PROXY"}
		if err := st.SaveNode(n); err != nil {
			t.Fatal(err)
		}
		if err := st.Grant(n.Tag, u.Name); err != nil {
			t.Fatal(err)
		}
	}
	body, _, err := Clash(st, u)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Proxies []map[string]any `yaml:"proxies"`
		Groups  []struct {
			Name    string   `yaml:"name"`
			Proxies []string `yaml:"proxies"`
		} `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("invalid YAML (including duplicate keys): %v", err)
	}
	used := map[string]bool{"DIRECT": true, "REJECT": true}
	for _, p := range cfg.Proxies {
		name := p["name"].(string)
		if used[name] {
			t.Fatalf("duplicate %s", name)
		}
		used[name] = true
		if p["type"] == store.ProtoVMess && p["servername"] != "entry.example" {
			t.Fatal("VMess TLS name not rendered")
		}
	}
	for _, g := range cfg.Groups {
		if used[g.Name] {
			t.Fatalf("duplicate group %s", g.Name)
		}
		used[g.Name] = true
	}
	for _, g := range cfg.Groups {
		members := map[string]bool{}
		for _, name := range g.Proxies {
			if !used[name] || members[name] {
				t.Fatalf("invalid member %s in %s", name, g.Name)
			}
			members[name] = true
		}
	}
}

func TestExplicitEntriesNeedNoSubHost(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)
	if err := st.SetSetting("sub_host", ""); err != nil {
		t.Fatal(err)
	}
	n, err := st.Node("hk-ss")
	if err != nil {
		t.Fatal(err)
	}
	n.EntryHost = "relay.example,2001:db8::1"
	n.EntryPort = 0
	if err := st.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	eps, _, err := Endpoints(st, u)
	if err != nil || len(eps) != 2 {
		t.Fatalf("entries %#v: %v", eps, err)
	}
	if eps[0].Port != n.Port || eps[1].Port != n.Port || eps[0].Name() == eps[1].Name() {
		t.Fatal("bad port or duplicate name")
	}
	body, _, err := Links(st, u, false)
	if err != nil || !strings.Contains(body, "@[2001:db8::1]:30002") {
		t.Fatalf("IPv6 link: %s %v", body, err)
	}
	encoded, _, err := Links(st, u, true)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || string(decoded) != body {
		t.Fatal("base64 differs")
	}
}

func TestNativeRuleAssetsAndRejectAction(t *testing.T) {
	sets := map[string]bool{}
	for _, raw := range singboxRuleSets() {
		s := raw.(map[string]any)
		sets[s["tag"].(string)] = true
		address := s["url"].(string)
		if strings.HasSuffix(address, ".mrs") || strings.Contains(address, "@meta/") {
			t.Fatalf("non-native asset %s", address)
		}
	}
	if !sets["cn_additional"] || len(sets) != len(presetProviders) {
		t.Fatal("missing native rule-set")
	}
	sawAds := false
	var check func(map[string]any)
	check = func(r map[string]any) {
		if names, ok := r["rule_set"].([]string); ok {
			for _, name := range names {
				if !sets[name] {
					t.Fatalf("missing set %s", name)
				}
				if name == "category-ads" {
					sawAds = r["action"] == "reject"
				}
			}
		}
		if nested, ok := r["rules"].([]any); ok {
			for _, child := range nested {
				check(child.(map[string]any))
			}
		}
	}
	for _, raw := range singboxRouteRules() {
		check(raw.(map[string]any))
	}
	if !sawAds {
		t.Fatal("ads are not rejected")
	}
}

func TestQUICPolicyMatchesCoreFixture(t *testing.T) {
	fixture, err := os.ReadFile("testdata/quic-rule.json")
	if err != nil {
		t.Fatal(err)
	}
	generated, err := json.Marshal(singboxQUICRule())
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err := json.Unmarshal(fixture, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(generated, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("QUIC policy differs from core matcher fixture: %s", generated)
	}
	rules, _ := singboxRules()
	count := 0
	for _, rule := range rules {
		if reflect.DeepEqual(rule, singboxQUICRule()) {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("QUIC policy included %d times", count)
	}
}

func TestVMessGRPCShareLink(t *testing.T) {
	e := endpoint{Node: store.Node{Tag: "vmess", Proto: store.ProtoVMess, TLSMode: "tls", Transport: "grpc", GRPCService: "service", EntrySNI: "entry.example"}, Host: "example.com", Port: 443, User: store.User{UUID: "11111111-2222-3333-4444-555555555555"}}
	link, err := shareLink(e)
	if err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(link, "vmess://"))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["path"] != "service" || fields["sni"] != "entry.example" {
		t.Fatalf("bad VMess link %v", fields)
	}
}

func TestClashSkipsIncompatibleTransports(t *testing.T) {
	for _, n := range []store.Node{
		{Proto: store.ProtoTrojan, TLSMode: "none"},
		{Proto: store.ProtoVLESS, TLSMode: "tls", Transport: "httpupgrade"},
	} {
		if _, ok := clashProxy(endpoint{Node: n, Host: "example.com", Port: 443}); ok {
			t.Fatalf("unsupported client settings accepted: %#v", n)
		}
	}
}

func TestSubscriptionNoStoreAndHEAD(t *testing.T) {
	st := testStore(t)
	u := seed(t, st)
	token, err := st.SubToken(u.Name)
	if err != nil {
		t.Fatal(err)
	}
	h := handler{st: st, cfg: Config{Interval: time.Hour}}
	for _, path := range []string{"/sub/invalid", "/sub/" + token + "/plain", "/sub/" + token + "/plain/extra"} {
		w := httptest.NewRecorder()
		h.subscription(w, httptest.NewRequest("HEAD", path, nil))
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable subscription")
		}
		if w.Code == 200 && w.Body.Len() != 0 {
			t.Fatal("HEAD returned credentials")
		}
	}
}

func TestRedirectIgnoresHostAndKeepsConfiguredPort(t *testing.T) {
	base, _ := url.Parse("https://sub.example:8443")
	w := httptest.NewRecorder()
	httpsRedirect(base).ServeHTTP(w, httptest.NewRequest("GET", "http://attacker.example/sub/token?x=1", nil))
	if got := w.Header().Get("Location"); got != "https://sub.example:8443/sub/token?x=1" {
		t.Fatal(got)
	}
}

func TestServeUsesTLSAddressAndStops(t *testing.T) {
	st := testStore(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour), DNSNames: []string{"sub.example"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pk}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"files", "acme"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := listener.Addr().String()
			listener.Close()
			cfg := Config{Listen: "invalid:address", ACMETLSAddr: addr, CertFile: certPath, KeyFile: keyPath}
			certDir := ""
			if mode == "acme" {
				cache := t.TempDir()
				certDir = t.TempDir()
				// Preload an ECDSA certificate; this tests autocert without contacting a CA.
				cached := append(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pk}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
				if err := os.WriteFile(filepath.Join(cache, "sub.example"), cached, 0600); err != nil {
					t.Fatal(err)
				}
				cfg = Config{Listen: "invalid:address", ACMETLSAddr: addr, ACMEHTTPAddr: "127.0.0.1:0", ACMEDomain: "sub.example", Base: "https://sub.example", ACMECacheDir: cache, ACMECertDir: certDir}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- Serve(ctx, st, cfg)
			}()
			pool := x509.NewCertPool()
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			pool.AddCert(cert)
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "sub.example", MinVersion: tls.VersionTLS12}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: time.Second}
			ready := false
			for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				resp, err := client.Get("https://" + addr + "/health")
				if err == nil {
					resp.Body.Close()
					ready = resp.StatusCode == 200
					break
				}
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("server did not stop")
			}
			if !ready {
				t.Fatal("TLS listener never ready")
			}
			if mode == "acme" {
				// 升级场景：证书本来只在 autocert 缓存里，服务起来后必须把它
				// 搬成稳定文件，否则节点读不到证书。
				stable := filepath.Join(certDir, "sub.example", "cert.pem")
				if _, err := os.Stat(stable); err != nil {
					t.Fatalf("稳定证书文件没写出来: %v", err)
				}
			}
		})
	}
}

func TestACMETLSBindFailureClosesChallengeListener(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	err = Serve(context.Background(), testStore(t), Config{ACMEDomain: "sub.example", Base: "https://sub.example", ACMECacheDir: t.TempDir(), ACMECertDir: t.TempDir(), ACMETLSAddr: occupied.Addr().String(), ACMEHTTPAddr: addr})
	if err == nil {
		t.Fatal("bind failure hidden")
	}
	reopened, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("challenge listener leaked: %v", err)
	}
	reopened.Close()
}
