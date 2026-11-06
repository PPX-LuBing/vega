package vector

import (
	"context"
	"github.com/ohmycggk/nowhere-go/qio"
	"testing"
	"time"
)

type closedSessionConn struct {
	qio.Conn
	closed bool
}

func (c *closedSessionConn) CloseWithError(uint64, string) error { c.closed = true; return nil }

func TestFailedOldSessionDoesNotCloseReplacement(t *testing.T) {
	oldConn, newConn := &closedSessionConn{}, &closedSessionConn{}
	old := &quicSession{conn: oldConn, cancel: func() {}}
	replacement := &quicSession{conn: newConn, cancel: func() {}}
	c := &Client{sessionState: replacement}
	c.failSession(old)
	if c.sessionState != replacement || newConn.closed || !oldConn.closed {
		t.Fatal("old session failure closed replacement")
	}
}

func TestCloseCancelsPendingQUICDial(t *testing.T) {
	started := make(chan struct{})
	c, err := New(Config{SharedKey: "0123456789abcdef0123456789abcdef", DialQUIC: func(ctx context.Context) (qio.Conn, error) { close(started); <-ctx.Done(); return nil, ctx.Err() }})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := c.session(context.Background()); done <- err }()
	<-started
	closed := make(chan struct{})
	go func() { _ = c.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close blocked behind dial mutex")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("dial succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("dial was not canceled")
	}
}
