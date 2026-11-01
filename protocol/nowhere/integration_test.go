//go:build with_v2ray_api

package nowhere_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/vector"
	"github.com/ohmycggk/nowhere-go/wire"
	box "github.com/sagernet/sing-box"
	stats "github.com/sagernet/sing-box/experimental/v2rayapi"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const integrationAlice = "0123456789abcdef0123456789abcdef"
const integrationBob = "fedcba9876543210fedcba9876543210"

func freeAddress(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func startKernel(t *testing.T, rules []any) (*box.Box, string, string, string) {
	t.Helper()
	proxy, control, api := freeAddress(t), freeAddress(t), freeAddress(t)
	port := netip.MustParseAddrPort(proxy).Port()
	config := map[string]any{
		"log": map[string]any{"disabled": true},
		"inbounds": []any{map[string]any{"type": "nowhere", "tag": "test-inbound", "listen": "127.0.0.1", "listen_port": port, "morph": false,
			"tls": map[string]any{"enabled": true, "insecure": true}, "users": []any{map[string]any{"name": "alice", "shared_key": integrationAlice}},
			"control_addr": control, "control_secret": "integration-secret"}},
		"outbounds":    []any{map[string]any{"type": "direct", "tag": "direct"}},
		"dns":          map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "local"}}},
		"route":        map[string]any{"rules": rules, "final": "direct"},
		"experimental": map[string]any{"v2ray_api": map[string]any{"listen": api, "stats": map[string]any{"enabled": true, "inbounds": []string{"test-inbound"}, "users": []string{"alice"}}}},
	}
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := include.Context(context.Background())
	var options option.Options
	if err = options.UnmarshalJSONContext(ctx, body); err != nil {
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
	return b, proxy, control, api
}

func vectorClient(t *testing.T, addr, key string) *vector.Client {
	t.Helper()
	c, err := vector.New(vector.Config{SharedKey: key, PortalAddr: addr, TLS: &tls.Config{InsecureSkipVerify: true}, DialTCP: func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func flowTarget(t *testing.T, addr string) wire.Target {
	t.Helper()
	ap := netip.MustParseAddrPort(addr)
	target, err := wire.NewIPTarget(ap.Addr(), ap.Port())
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func tcpEcho(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l
}

func udpEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = c.WriteToUDP(buf[:n], addr)
		}
	}()
	return c
}

func echoFlow(conn net.Conn, err error) error {
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err = conn.Write([]byte("ping")); err != nil {
		return err
	}
	body := make([]byte, 4)
	_, err = io.ReadFull(conn, body)
	if err == nil && string(body) != "ping" {
		return fmt.Errorf("unexpected echo %q", body)
	}
	return err
}

func TestNowhereRoutesTCPAndUDPAndClosesControl(t *testing.T) {
	b, proxy, control, _ := startKernel(t, []any{map[string]any{"inbound": []string{"test-inbound"}, "action": "reject"}})
	echo := tcpEcho(t)
	c := vectorClient(t, proxy, integrationAlice)
	if err := echoFlow(c.OpenTCP(context.Background(), flowTarget(t, echo.Addr().String()))); err == nil {
		t.Fatal("inbound reject bypassed")
	}
	udp := udpEcho(t)
	if err := echoFlow(c.OpenUDP(context.Background(), flowTarget(t, udp.LocalAddr().String()))); err == nil {
		t.Fatal("UDP reject bypassed")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if conn, err := net.DialTimeout("tcp", control, time.Second); err == nil {
		conn.Close()
		t.Fatal("control endpoint survived Box.Close")
	}
}

func TestNowhereUDPTransfersAndCountsDatagrams(t *testing.T) {
	_, proxy, _, api := startKernel(t, []any{})
	udp := udpEcho(t)
	c := vectorClient(t, proxy, integrationAlice)
	conn, err := c.OpenUDP(context.Background(), flowTarget(t, udp.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	var total int64
	for _, packet := range [][]byte{[]byte("ping"), nil, bytes.Repeat([]byte("z"), 8192)} {
		if _, err = conn.Write(packet); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 65535)
		n, err := conn.Read(got)
		if err != nil || !bytes.Equal(got[:n], packet) {
			t.Fatalf("UDP packet len %d/%d: %v", n, len(packet), err)
		}
		total += int64(len(packet))
	}
	g, err := grpc.NewClient(api, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for {
		response := &stats.QueryStatsResponse{}
		if err = g.Invoke(ctx, "/v2ray.core.app.stats.command.StatsService/QueryStats", &stats.QueryStatsRequest{}, response); err != nil {
			t.Fatal(err)
		}
		counts := map[string]int64{}
		for _, stat := range response.Stat {
			counts[stat.Name] = stat.Value
		}
		if counts["user>>>alice>>>traffic>>>uplink"] == total && counts["user>>>alice>>>traffic>>>downlink"] == total {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatalf("UDP not accounted: %v, want %d", counts, total)
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestNowhereRejectsResolvedLoopbackTargets(t *testing.T) {
	_, proxy, _, _ := startKernel(t, []any{
		map[string]any{"action": "resolve", "server": "local"},
		map[string]any{"ip_cidr": []string{"127.0.0.0/8", "::1/128"}, "action": "reject"},
	})
	echo := tcpEcho(t)
	c := vectorClient(t, proxy, integrationAlice)
	target, err := wire.NewDomainTarget("localhost", netip.MustParseAddrPort(echo.Addr().String()).Port())
	if err != nil {
		t.Fatal(err)
	}
	if err = echoFlow(c.OpenTCP(context.Background(), target)); err == nil {
		t.Fatal("domain target bypassed loopback policy")
	}
}

func TestNowhereHotUsersAreAuthenticatedAndCounted(t *testing.T) {
	_, proxy, control, api := startKernel(t, []any{})
	echo := tcpEcho(t)
	post := func(client *http.Client, token, body string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, "http://"+control+"/users", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	body := fmt.Sprintf(`{"inbound":"test-inbound","users":[{"name":"bob","shared_key":"%s"}]}`, integrationBob)
	client := &http.Client{Timeout: 3 * time.Second}
	if got := post(client, "integration-secret", body); got != http.StatusOK {
		t.Fatal(got)
	}
	c := vectorClient(t, proxy, integrationBob)
	if err := echoFlow(c.OpenTCP(context.Background(), flowTarget(t, echo.Addr().String()))); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return c.OpenTCP(ctx, flowTarget(t, control))
	}}
	defer transport.CloseIdleConnections()
	if got := post(&http.Client{Transport: transport, Timeout: 3 * time.Second}, "", body); got != http.StatusUnauthorized {
		t.Fatalf("proxy user replaced users: %d", got)
	}
	if got := post(client, "integration-secret", `{"inbound":"test-inbound"}`); got != http.StatusBadRequest {
		t.Fatalf("omitted users: %d", got)
	}
	g, err := grpc.NewClient(api, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response := &stats.QueryStatsResponse{}
	if err = g.Invoke(ctx, "/v2ray.core.app.stats.command.StatsService/QueryStats", &stats.QueryStatsRequest{}, response); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int64{}
	for _, stat := range response.Stat {
		counts[stat.Name] = stat.Value
	}
	for _, name := range []string{"user>>>bob>>>traffic>>>uplink", "user>>>bob>>>traffic>>>downlink", "inbound>>>test-inbound>>>traffic>>>uplink"} {
		if counts[name] < 4 {
			t.Fatalf("missing counter %s: %v", name, counts)
		}
	}
}

// startKernelFromConfig 用给定配置起一个内核。
func startKernelFromConfig(t *testing.T, config map[string]any) *box.Box {
	t.Helper()
	body, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := include.Context(context.Background())
	var options option.Options
	if err = options.UnmarshalJSONContext(ctx, body); err != nil {
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
	return b
}

// socksDial 做一次 SOCKS5 无认证握手，连到目标。
func socksDial(t *testing.T, proxy, target string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	// 问候：版本 5，一种方法（无认证）
	if _, err = conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err = io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if reply[0] != 5 || reply[1] != 0 {
		t.Fatalf("SOCKS 握手被拒: %v", reply)
	}
	// 请求：CONNECT 到 IPv4 目标
	ap := netip.MustParseAddrPort(target)
	req := []byte{5, 1, 0, 1}
	req = append(req, ap.Addr().AsSlice()...)
	req = append(req, byte(ap.Port()>>8), byte(ap.Port()))
	if _, err = conn.Write(req); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 10)
	if _, err = io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[1] != 0 {
		t.Fatalf("SOCKS CONNECT 失败，代码 %d", resp[1])
	}
	return conn
}

// nowhere 出站必须真的能把流量送到 Portal 后面的目标。
//
// 这里起两个内核：左边只有 nowhere 入站（扮演落地），右边用 nowhere 出站
// 经 SOCKS 入站转发。数据要穿过「SOCKS → 出站 → 载体 → 入站 → 直连 →
// echo」整条链路，才算证明出站可用。
func TestNowhereOutboundDialsThroughPortal(t *testing.T) {
	echo := tcpEcho(t)
	defer echo.Close()

	// 左：Portal（落地）
	portalAddr, portalControl := freeAddress(t), freeAddress(t)
	portalPort := netip.MustParseAddrPort(portalAddr).Port()
	startKernelFromConfig(t, map[string]any{
		"log": map[string]any{"disabled": true},
		"inbounds": []any{map[string]any{
			"type": "nowhere", "tag": "portal", "listen": "127.0.0.1", "listen_port": portalPort,
			"morph": false, "tls": map[string]any{"enabled": true, "insecure": true},
			"users":        []any{map[string]any{"name": "alice", "shared_key": integrationAlice}},
			"control_addr": portalControl, "control_secret": "integration-secret",
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":     map[string]any{"final": "direct"},
	})

	// 右：Vector 出站（客户端）
	socksAddr := freeAddress(t)
	socksPort := netip.MustParseAddrPort(socksAddr).Port()
	startKernelFromConfig(t, map[string]any{
		"log": map[string]any{"disabled": true},
		"inbounds": []any{map[string]any{
			"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": socksPort,
		}},
		"outbounds": []any{
			map[string]any{
				"type": "nowhere", "tag": "nw-out",
				"server": "127.0.0.1", "server_port": portalPort,
				"shared_key": integrationAlice, "morph": false,
				"tls": map[string]any{"enabled": true, "insecure": true},
			},
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{
			"rules": []any{map[string]any{"inbound": []string{"socks-in"}, "outbound": "nw-out"}},
			"final": "direct",
		},
	})

	conn := socksDial(t, socksAddr, echo.Addr().String())
	defer conn.Close()

	payload := []byte("through-the-vector")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("写出失败: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("读回失败: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("回声不一致: %q != %q", got, payload)
	}
}
