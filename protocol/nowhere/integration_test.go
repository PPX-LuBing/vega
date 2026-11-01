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
