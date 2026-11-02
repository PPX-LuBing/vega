package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/kernel"
	"github.com/PPX-LuBing/vega/panel/internal/store"
	"github.com/PPX-LuBing/vega/panel/internal/sub"
)

func TestProbeNeverFallsBackToDirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("direct fallback reached target") }))
	defer target.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := probeThroughSOCKS(ctx, &url.URL{Scheme: "socks5", Host: address}, target.URL); err == nil {
		t.Fatal("unreachable proxy succeeded")
	}
}

// Opt-in integration test uses a real kernel, but only loopback fixtures.
func TestSelftestWithRealKernel(t *testing.T) {
	bin := os.Getenv("VEGA_TEST_KERNEL")
	if bin == "" {
		t.Skip("set VEGA_TEST_KERNEL to a core built with QUIC/uTLS/clash/v2ray tags")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer target.Close()
	for _, proto := range []string{store.ProtoVMess, store.ProtoVLESS, store.ProtoTrojan} {
		for _, transport := range []string{"tcp", "ws", "grpc", "httpupgrade"} {
			t.Run(proto+"/"+transport, func(t *testing.T) {
				dir := t.TempDir()
				db := filepath.Join(dir, "panel.db")
				st, err := store.Open(db)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = st.Close() })
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				port := listener.Addr().(*net.TCPAddr).Port
				listener.Close()
				n := store.Node{Tag: "test", Proto: proto, Port: port, Listen: "127.0.0.1", Enabled: true, TLSMode: "none", Transport: transport, Path: "/proxy", GRPCService: "probe", EntryHost: "127.0.0.1"}
				if err := store.PrepareNode(&n); err != nil {
					t.Fatal(err)
				}
				if err := st.SaveNode(n); err != nil {
					t.Fatal(err)
				}
				if err := st.SaveUser(store.User{Name: "tester", Enabled: true}); err != nil {
					t.Fatal(err)
				}
				if err := st.Grant(n.Tag, "tester"); err != nil {
					t.Fatal(err)
				}
				paths := kernel.DefaultPaths()
				paths.Bin = bin
				paths.Config = filepath.Join(dir, "server.json")
				cfg, err := kernel.BuildConfig(st, paths)
				if err != nil {
					t.Fatal(err)
				}
				delete(cfg, "experimental") // No fixed management listeners in this fixture.
				if err := kernel.WriteConfig(paths, cfg); err != nil {
					t.Fatal(err)
				}
				if err := doctor(st, paths); err != nil {
					t.Fatal(err)
				}
				u, err := st.User("tester")
				if err != nil {
					t.Fatal(err)
				}
				client, _, err := sub.Singbox(st, u)
				if err != nil {
					t.Fatal(err)
				}
				var parsed map[string]any
				if err := json.Unmarshal([]byte(client), &parsed); err != nil {
					t.Fatal(err)
				}
				clientFile := filepath.Join(dir, "subscription.json")
				if err := os.WriteFile(clientFile, []byte(client), 0600); err != nil {
					t.Fatal(err)
				}
				if out, err := exec.Command(bin, "check", "-c", clientFile).CombinedOutput(); err != nil {
					t.Fatalf("subscription check: %s %v", out, err)
				}
				st.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				cmd := exec.CommandContext(ctx, bin, "run", "-c", paths.Config)
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() { cancel(); _ = cmd.Wait() }()
				address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
				for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
					conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
					if err == nil {
						conn.Close()
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("fixture did not start")
					}
				}
				if err := runSelftest(db, paths, []string{"--user", "tester", "--node", "test", "--url", target.URL, "--timeout", "10s"}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
