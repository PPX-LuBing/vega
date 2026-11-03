package nowhere

import (
	"context"
	"net"
	"testing"
	"time"
)

// ReadFrom 在还没有 flow 时必须**阻塞等待**，不能返回错误。
//
// 返回错误会让 sing-box 的 packet 下载循环直接 common.Close 掉整个 UDP 会话
// （route/conn.go 的 packetConnectionCopy），表现为 UDP 静默不通——这正是
// 修复前的行为：sing-box 的读循环立刻启动，第一次 ReadFrom 必然早于第一次
// WriteTo（WriteTo 才建 flow）。
func TestPacketConnReadWaitsForFirstFlow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conn := &packetConn{ctx: ctx, ready: make(chan struct{})}

	type result struct {
		buf string
		err error
	}
	done := make(chan result, 1)
	go func() {
		buf := make([]byte, 32)
		n, _, err := conn.ReadFrom(buf)
		done <- result{buf: string(buf[:n]), err: err}
	}()

	select {
	case got := <-done:
		t.Fatalf("没有 flow 时 ReadFrom 直接返回了（err=%v），应当阻塞等待", got.err)
	case <-time.After(150 * time.Millisecond):
	}

	// 假装第一条 flow 已经建好
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn.mu.Lock()
	conn.flows = map[string]net.Conn{"example.com:53": client}
	conn.order = []string{"example.com:53"}
	conn.readyDone = true
	close(conn.ready)
	conn.mu.Unlock()

	go func() { _, _ = server.Write([]byte("pong")) }()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("flow 建好之后 ReadFrom 仍然报错: %v", got.err)
		}
		if got.buf != "pong" {
			t.Fatalf("读到 %q，想要 %q", got.buf, "pong")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("flow 建好之后 ReadFrom 还是没返回")
	}
}

// ctx 结束时，正在等待的 ReadFrom 要能退出来，不能把下载循环永远挂住。
func TestPacketConnReadUnblocksOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	conn := &packetConn{ctx: ctx, ready: make(chan struct{})}

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		_, _, err := conn.ReadFrom(buf)
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("ctx 还没结束就返回了: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ctx 结束后应当返回错误")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ctx 结束后 ReadFrom 没有退出")
	}
}
