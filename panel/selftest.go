package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/PPX-LuBing/vega/panel/internal/kernel"
	"github.com/PPX-LuBing/vega/panel/internal/store"
	"github.com/PPX-LuBing/vega/panel/internal/sub"
)

func runSelftest(dbPath string, paths kernel.Paths, args []string) error {
	fs := flag.NewFlagSet("selftest", flag.ContinueOnError)
	user := fs.String("user", "", "authorized user")
	node := fs.String("node", "", "node tag (tests its first published entry)")
	target := fs.String("url", "https://www.gstatic.com/generate_204", "HTTP(S) probe URL, accessed through the selected node")
	expect := fs.Int("expect", 204, "expected HTTP status")
	timeout := fs.Duration("timeout", 20*time.Second, "total timeout, 1s..2m")
	if err := fs.Parse(args); err != nil {
		return err
	}
	u, err := url.Parse(*target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("probe URL must be HTTP(S), without credentials")
	}
	if fs.NArg() != 0 || *user == "" || *node == "" || *timeout < time.Second || *timeout > 2*time.Minute || *expect < 100 || *expect > 599 {
		return fmt.Errorf("usage: selftest --user NAME --node TAG [--url URL --expect 204 --timeout 20s]")
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	member, err := st.User(*user)
	if err != nil {
		return err
	}
	up, down, err := st.Usage(member.Name)
	if err != nil {
		return err
	}
	if !kernel.Usable(member, up+down, time.Now()) {
		return fmt.Errorf("user is disabled, expired or over quota")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	cfg, err := sub.ClientConfig(st, member, *node, port)
	if err != nil {
		return err
	}
	password := store.NewSecret()
	cfg["inbounds"].([]any)[0].(map[string]any)["users"] = []any{map[string]any{"username": "probe", "password": password}}
	proxy := &url.URL{Scheme: "socks5", Host: address, User: url.UserPassword("probe", password)}
	dir, err := os.MkdirTemp("", "vega-selftest-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, "client.json")
	body, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(file, body, 0600); err != nil {
		return err
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, *timeout)
	defer cancel()
	check := exec.CommandContext(ctx, paths.Bin, "check", "-c", file)
	if err := check.Run(); err != nil {
		return fmt.Errorf("client configuration check failed: %w (verify kernel build tags)", err)
	}
	cmd := exec.CommandContext(ctx, paths.Bin, "run", "-c", file)
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() { cancel(); <-done }()
	// The OS-selected port can be taken between close and run; fail rather than
	// changing the configured proxy or ever falling back to a direct request.
	ready := false
	for !ready {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("client startup timed out or cancelled")
		case err := <-done:
			done <- err
			return fmt.Errorf("temporary client exited before probe: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	started := time.Now()
	status, err := probeThroughSOCKS(ctx, proxy, *target)
	if err != nil {
		return err
	}
	select {
	case err := <-done:
		done <- err
		return fmt.Errorf("temporary client exited during probe: %v", err)
	default:
	}
	if status != *expect {
		return fmt.Errorf("probe returned HTTP %d, expected %d", status, *expect)
	}
	fmt.Printf("OK %s: HTTP %d via selected entry, %s (temporary client stopped on exit)\n", *node, status, time.Since(started).Round(time.Millisecond))
	return nil
}

func probeThroughSOCKS(ctx context.Context, proxy *url.URL, target string) (int, error) {
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSHandshakeTimeout: 5 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, fmt.Errorf("invalid probe request")
	}
	response, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("proxy probe failed (check entry reachability, credentials, TLS and timeout)")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	return response.StatusCode, nil
}
