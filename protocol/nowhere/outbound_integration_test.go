//go:build with_v2ray_api

package nowhere_test

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

func TestSocksUDPViaNowhereOutbound(t *testing.T) {
	_, portal, _, _ := startKernel(t, nil)
	in := freeAddress(t)
	cfg := map[string]any{
		"log":       map[string]any{"level": "error"},
		"inbounds":  []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": netip.MustParseAddrPort(in).Port()}},
		"outbounds": []any{map[string]any{"type": "nowhere", "tag": "proxy", "server": "127.0.0.1", "server_port": netip.MustParseAddrPort(portal).Port(), "shared_key": integrationAlice, "morph": false, "tls": map[string]any{"enabled": true, "insecure": true}}},
		"route":     map[string]any{"final": "proxy"},
	}
	raw, _ := json.Marshal(cfg)
	ctx := include.Context(context.Background())
	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, raw); err != nil {
		t.Fatal(err)
	}
	b, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err = b.Start(); err != nil {
		t.Fatal(err)
	}
	echo := udpEcho(t)
	target := M.SocksaddrFromNet(echo.LocalAddr())
	client := socks.NewClient(N.SystemDialer, M.ParseSocksaddr(in), socks.Version5, "", "")
	conn, err := client.ListenPacket(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err = conn.WriteTo([]byte("ping"), target); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("SOCKS5 -> Vega Nowhere outbound -> Vega Nowhere inbound -> UDP echo: no reply: %v", err)
	}
	if strings.TrimSpace(string(buf[:n])) != "ping" || M.SocksaddrFromNet(addr) != target {
		t.Fatalf("bad response %q source=%v, want=%v", buf[:n], addr, target)
	}
}
