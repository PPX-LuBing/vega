//go:build with_v2ray_api

package nowhere_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	singtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// Opt-in: use an independently built official 3.3.0 binary, not our Go CLI.
func TestOfficialRustInterop(t *testing.T) {
	binary := os.Getenv("VEGA_TEST_NOWHERE_RUST")
	if binary == "" {
		t.Skip("set VEGA_TEST_NOWHERE_RUST to official Nowhere 3.3.0")
	}
	version, err := exec.Command(binary, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "3.3.0") {
		t.Fatalf("official peer version: %q, %v", version, err)
	}
	for _, morph := range []bool{false, true} {
		for _, rustPortal := range []bool{false, true} {
			name := fmt.Sprintf("rust_portal=%t/morph=%t", rustPortal, morph)
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				key, cert, err := singtls.GenerateCertificate(nil, nil, time.Now, "localhost", time.Now().Add(time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				pair, err := tls.X509KeyPair(cert, key)
				if err != nil {
					t.Fatal(err)
				}
				pin := sha256.Sum256(pair.Certificate[0])
				certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
				for path, data := range map[string][]byte{certPath: cert, keyPath: key} {
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				portal, socksAddr := freeAddress(t), freeAddress(t)
				morphValue := "0"
				if morph {
					morphValue = "1"
				}
				if rustPortal {
					query := url.Values{"tls": {"2"}, "crt": {certPath}, "key": {keyPath}, "morph": {morphValue}}
					startOfficialPeer(t, binary, officialURL("portal", portal, query), portal)
					startInteropBox(t, map[string]any{
						"inbounds": []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": interopPort(socksAddr)}},
						"outbounds": []any{map[string]any{"type": "nowhere", "tag": "proxy", "server": "127.0.0.1", "server_port": interopPort(portal), "shared_key": integrationAlice, "morph": morph,
							"tls": map[string]any{"enabled": true, "server_name": "localhost", "certificate": []string{string(cert)}}}},
						"route": map[string]any{"final": "proxy"},
					})
				} else {
					startInteropBox(t, map[string]any{
						"inbounds": []any{map[string]any{"type": "nowhere", "listen": "127.0.0.1", "listen_port": interopPort(portal), "morph": morph, "control_addr": "off",
							"users": []any{map[string]any{"name": "bob", "shared_key": integrationBob}, map[string]any{"name": "alice", "shared_key": integrationAlice}},
							"tls":   map[string]any{"enabled": true, "certificate_path": certPath, "key_path": keyPath}}},
						"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"final": "direct"},
					})
					query := url.Values{"in": {socksAddr}, "sni": {"localhost"}, "pin": {hex.EncodeToString(pin[:])}, "morph": {morphValue}}
					startOfficialPeer(t, binary, officialURL("vector", portal, query), socksAddr)
				}
				client := socks.NewClient(N.SystemDialer, M.ParseSocksaddr(socksAddr), socks.Version5, "", "")
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				echo := tcpEcho(t)
				for i := 0; i < 2; i++ {
					if err := echoFlow(client.DialContext(ctx, "tcp", M.ParseSocksaddr(echo.Addr().String()))); err != nil {
						t.Fatal("TCP/reconnect: ", err)
					}
				}
				first, second := udpEcho(t), udpEcho(t)
				packet, err := client.ListenPacket(ctx, M.SocksaddrFromNet(first.LocalAddr()))
				if err != nil {
					t.Fatal(err)
				}
				defer packet.Close()
				if err := packet.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatal(err)
				}
				for _, peer := range []*net.UDPConn{first, second, first} {
					target := M.SocksaddrFromNet(peer.LocalAddr())
					if _, err := packet.WriteTo([]byte("udp-echo"), target); err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, 64)
					n, source, err := packet.ReadFrom(buf)
					if err != nil || string(buf[:n]) != "udp-echo" || M.SocksaddrFromNet(source) != target {
						t.Fatalf("UDP source/echo: %q %v %v", buf[:n], source, err)
					}
				}
			})
		}
	}
}

func interopPort(addr string) uint16 { return netip.MustParseAddrPort(addr).Port() }

func officialURL(role, addr string, query url.Values) string {
	ap := netip.MustParseAddrPort(addr)
	return fmt.Sprintf("%s://%s@%s/tcp:%d?%s", role, integrationAlice, ap.Addr(), ap.Port(), query.Encode())
}

func startInteropBox(t *testing.T, config map[string]any) {
	t.Helper()
	config["log"] = map[string]any{"level": "error"}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := include.Context(context.Background())
	var options option.Options
	if err = options.UnmarshalJSONContext(ctx, data); err != nil {
		t.Fatal(err)
	}
	b, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err = b.Start(); err != nil {
		t.Fatal(err)
	}
}

func startOfficialPeer(t *testing.T, binary, serviceURL, listen string) {
	t.Helper()
	dir := t.TempDir()
	output, err := os.Create(filepath.Join(dir, "peer.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = output.Close() })
	cmd := exec.Command(binary, serviceURL)
	cmd.Dir = dir
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "NOW_") && !strings.HasPrefix(value, "TMPDIR=") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "TMPDIR="+dir, "NOW_HANDSHAKE_TIMEOUT=2s", "NOW_FLOW_SETUP_TIMEOUT=3s")
	cmd.Stdout, cmd.Stderr = output, output
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-done
		if t.Failed() {
			data, _ := os.ReadFile(output.Name())
			t.Logf("official peer: %s", data)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", listen, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("official peer did not start")
}
