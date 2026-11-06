//go:build with_v2ray_api && with_quic

package nowhere_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	singtls "github.com/sagernet/sing-box/common/tls"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

func TestOfficialEgressInterop(t *testing.T) {
	binary := os.Getenv("VEGA_TEST_NOWHERE_RUST")
	if binary == "" {
		t.Skip("official Rust binary required")
	}
	for _, rustPortal := range []bool{false, true} {
		for _, morph := range []bool{false, true} {
			for _, vc := range []string{"tcp", "quic"} {
				for _, ec := range []string{"tcp", "quic"} {
					t.Run(fmt.Sprintf("rust_portal=%t/morph=%t/vector=%s/egress=%s", rustPortal, morph, vc, ec), func(t *testing.T) {
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
						mv := "0"
						if morph {
							mv = "1"
						}
						peerURL := func(role, carrier string, q url.Values) string {
							u := officialURL(role, portal, q)
							if carrier == "quic" {
								u = strings.Replace(u, "/tcp:", "/udp:", 1)
							}
							return u
						}
						tlsClient := map[string]any{"enabled": true, "server_name": "localhost", "certificate": []string{string(cert)}}
						if rustPortal {
							q := url.Values{"out": {"egress"}, "tls": {"2"}, "crt": {certPath}, "key": {keyPath}, "morph": {mv}}
							u := officialURL("portal", portal, q)
							u = strings.Replace(u, "?", fmt.Sprintf("/udp:%d?", interopPort(portal)), 1)
							startOfficialPeer(t, binary, u, portal)
							startInteropBox(t, map[string]any{
								"services":  []any{map[string]any{"type": "nowhere-egress", "tag": "exit", "carrier": ec, "server": "127.0.0.1", "server_port": interopPort(portal), "shared_key": integrationAlice, "morph": morph, "tls": tlsClient}},
								"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"final": "direct"},
							})
						} else {
							startInteropBox(t, map[string]any{
								"inbounds": []any{map[string]any{"type": "nowhere", "tag": "portal", "carrier": "both", "egress": true, "listen": "127.0.0.1", "listen_port": interopPort(portal), "morph": morph, "control_addr": "off",
									"users": []any{map[string]any{"name": "bob", "shared_key": integrationBob}, map[string]any{"name": "alice", "shared_key": integrationAlice}},
									"tls":   map[string]any{"enabled": true, "certificate_path": certPath, "key_path": keyPath}}},
								"outbounds": []any{map[string]any{"type": "nowhere-egress", "tag": "exit", "portal": "portal"}}, "route": map[string]any{"final": "exit"},
							})
							startOfficialPeer(t, binary, peerURL("egress", ec, url.Values{"sni": {"localhost"}, "pin": {hex.EncodeToString(pin[:])}, "morph": {mv}}), "")
						}
						startOfficialPeer(t, binary, peerURL("vector", vc, url.Values{"in": {socksAddr}, "sni": {"localhost"}, "pin": {hex.EncodeToString(pin[:])}, "morph": {mv}}), socksAddr)
						client := socks.NewClient(N.SystemDialer, M.ParseSocksaddr(socksAddr), socks.Version5, "", "")
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cancel()
						echo := tcpEcho(t)
						for i := 0; i < 3; i++ {
							if err := echoFlow(client.DialContext(ctx, "tcp", M.ParseSocksaddr(echo.Addr().String()))); err != nil {
								t.Fatal(err)
							}
						}
						udp := udpEcho(t)
						packet, err := client.ListenPacket(ctx, M.SocksaddrFromNet(udp.LocalAddr()))
						if err != nil {
							t.Fatal(err)
						}
						defer packet.Close()
						_ = packet.SetDeadline(time.Now().Add(4 * time.Second))
						for _, size := range []int{0, 8, 8192} {
							payload := bytes.Repeat([]byte{42}, size)
							if _, err := packet.WriteTo(payload, udp.LocalAddr()); err != nil {
								t.Fatal(err)
							}
							buf := make([]byte, 65535)
							n, _, err := packet.ReadFrom(buf)
							if err != nil || !bytes.Equal(buf[:n], payload) {
								t.Fatalf("UDP size=%d got=%d: %v", size, n, err)
							}
						}
					})
				}
			}
		}
	}
}
