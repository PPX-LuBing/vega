package vector

import (
	"context"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/qio"
)

type recordingConn struct {
	qio.Conn
	closed bool
	reason string
}

func (c *recordingConn) CloseWithError(uint64, string) error {
	c.closed = true
	return nil
}

func (c *recordingConn) Context() context.Context { return context.Background() }

// 会话失效后，客户端必须回到「没有连接、可以重连」的干净状态。
//
// 上游 3.4.0 用单连接 + failSession()，没有我们旧版的 sessionState 隔离机制；
// 但「失效后状态清干净」这个语义仍然必须成立，否则下一次拨号会复用死连接。
func TestFailSessionClearsState(t *testing.T) {
	conn := &recordingConn{}
	cancelled := false
	c := &Client{
		quic:     conn,
		cancel:   func() { cancelled = true },
		used0:    true,
		draining: true,
	}

	c.failSession()

	if c.quic != nil || c.cancel != nil || c.router != nil {
		t.Fatalf("会话字段没清干净: quic=%v cancel=%v router=%v", c.quic, c.cancel, c.router)
	}
	if c.used0 || c.draining {
		t.Fatalf("状态标志没复位: used0=%v draining=%v", c.used0, c.draining)
	}
	if !cancelled {
		t.Fatal("没有取消 runCtx，router goroutine 会泄漏")
	}
	if !conn.closed {
		t.Fatal("旧连接没有关闭")
	}
}

// Close 可以重复调用，第二次不该 panic。
func TestCloseIsIdempotent(t *testing.T) {
	conn := &recordingConn{}
	c := &Client{quic: conn, cancel: func() {}}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !conn.closed {
		t.Fatal("Close 没关连接")
	}
}

// drainAndDrop 到期后必须回收会话。
func TestDrainAndDropReclaims(t *testing.T) {
	conn := &recordingConn{}
	c := &Client{quic: conn, cancel: func() {}}
	done := make(chan struct{})
	go func() {
		c.drainAndDrop(20 * time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drainAndDrop 没有在预期时间内返回")
	}
	if c.quic != nil {
		t.Fatal("drainAndDrop 之后会话应当已回收")
	}
	if !conn.closed {
		t.Fatal("drainAndDrop 之后旧连接应当关闭")
	}
}
