//go:build with_v2ray_api && with_quic

package nowhere_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	singtls "github.com/sagernet/sing-box/common/tls"
	stats "github.com/sagernet/sing-box/experimental/v2rayapi"
	M "github.com/sagernet/sing/common/metadata"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestEgressPolicyAccountingAndConcurrentQUIC(t *testing.T) {
	for _, carrier := range []string{"tcp", "quic"} {
		t.Run(carrier, func(t *testing.T) {
			t.Setenv("NOW_FLOW_SETUP_TIMEOUT", "500ms")
			dir := t.TempDir()
			key, cert, err := singtls.GenerateCertificate(nil, nil, time.Now, "localhost", time.Now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
			for path, data := range map[string][]byte{cp: cert, kp: key} {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			portal, api := freeAddress(t), freeAddress(t)
			blocked := tcpEcho(t)
			startInteropBox(t, map[string]any{
				"inbounds":     []any{map[string]any{"type": "nowhere", "tag": "portal", "carrier": carrier, "egress": true, "listen": "127.0.0.1", "listen_port": interopPort(portal), "control_addr": "off", "users": []any{map[string]any{"name": "alice", "shared_key": integrationAlice}, map[string]any{"name": "bob", "shared_key": integrationBob}}, "tls": map[string]any{"enabled": true, "certificate_path": cp, "key_path": kp}}},
				"outbounds":    []any{map[string]any{"type": "nowhere-egress", "tag": "exit", "portal": "portal"}},
				"route":        map[string]any{"rules": []any{map[string]any{"port": []uint16{interopPort(blocked.Addr().String())}, "action": "reject"}}, "final": "exit"},
				"experimental": map[string]any{"v2ray_api": map[string]any{"listen": api, "stats": map[string]any{"enabled": true, "users": []string{"alice", "bob"}}}},
			})
			peer := func(key string) map[string]any {
				return map[string]any{"type": "nowhere", "tag": "proxy", "carrier": carrier, "server": "127.0.0.1", "server_port": interopPort(portal), "shared_key": key, "tls": map[string]any{"enabled": true, "server_name": "localhost", "certificate": []string{string(cert)}}}
			}
			exit := peer(integrationAlice)
			exit["type"] = "nowhere-egress"
			exit["tag"] = "remote"
			startInteropBox(t, map[string]any{"services": []any{exit}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}, "route": map[string]any{"final": "direct"}})
			aliceBox := startInteropBox(t, map[string]any{"outbounds": []any{peer(integrationAlice)}})
			bobBox := startInteropBox(t, map[string]any{"outbounds": []any{peer(integrationBob)}})
			alice, _ := aliceBox.Outbound().Outbound("proxy")
			bob, _ := bobBox.Outbound().Outbound("proxy")
			echo := tcpEcho(t)
			dest := M.ParseSocksaddr(echo.Addr().String())
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			if err := echoFlow(bob.DialContext(ctx, "tcp", dest)); err == nil {
				t.Fatal("bob consumed alice exit")
			}
			if err := echoFlow(alice.DialContext(ctx, "tcp", M.ParseSocksaddr(blocked.Addr().String()))); err == nil {
				t.Fatal("Egress bypassed reject rule")
			}
			var wg sync.WaitGroup
			errs := make(chan error, 16)
			for i := 0; i < 16; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					c, err := alice.DialContext(ctx, "tcp", dest)
					if err != nil {
						errs <- err
						return
					}
					defer c.Close()
					_ = c.SetDeadline(time.Now().Add(3 * time.Second))
					_, err = c.Write([]byte("ping"))
					if err == nil {
						b := make([]byte, 4)
						_, err = io.ReadFull(c, b)
						if string(b) != "ping" && err == nil {
							err = fmt.Errorf("corrupt reply")
						}
					}
					errs <- err
				}()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			g, err := grpc.NewClient(api, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			deadline := time.Now().Add(time.Second)
			for {
				response := &stats.QueryStatsResponse{}
				if err := g.Invoke(ctx, "/v2ray.core.app.stats.command.StatsService/QueryStats", &stats.QueryStatsRequest{}, response); err != nil {
					t.Fatal(err)
				}
				counts := map[string]int64{}
				for _, stat := range response.Stat {
					counts[stat.Name] = stat.Value
				}
				if counts["user>>>alice>>>traffic>>>uplink"] >= 64 && counts["user>>>alice>>>traffic>>>downlink"] >= 64 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("Egress not accounted: %v", counts)
				}
				time.Sleep(10 * time.Millisecond)
			}
			// Sending FIN must not discard the reply generated after the target EOF.
			half, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer half.Close()
			go func() {
				c, e := half.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				b, _ := io.ReadAll(c)
				_, _ = c.Write(b)
			}()
			c, err := alice.DialContext(ctx, "tcp", M.ParseSocksaddr(half.Addr().String()))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(time.Second))
			_, _ = c.Write([]byte("fin"))
			if err := c.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(c)
			if err != nil || string(b) != "fin" {
				t.Fatalf("half close %q: %v", b, err)
			}
		})
	}
}
