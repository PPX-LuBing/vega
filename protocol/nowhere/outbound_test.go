package nowhere

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/wire"
	M "github.com/sagernet/sing/common/metadata"
)

func echoPacketConn(t *testing.T) *packetConn {
	t.Helper()
	c := newPacketConn(context.Background(), M.ParseSocksaddr("fallback.example:53"), func(ctx context.Context, target wire.Target) (net.Conn, error) {
		a, b := net.Pipe()
		server := &datagramConn{Conn: b}
		go func() {
			defer server.Close()
			buffer := make([]byte, 65535)
			for {
				n, err := server.Read(buffer)
				if err != nil {
					return
				}
				if target.Host == "silent.example" {
					continue
				}
				if _, err = server.Write(buffer[:n]); err != nil {
					return
				}
			}
		}()
		return &datagramConn{Conn: a}, nil
	})
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestPacketReadBeforeWriteAndMultipleTargets(t *testing.T) {
	c := echoPacketConn(t)
	c.SetDeadline(time.Now().Add(3 * time.Second))
	type result struct {
		body string
		addr net.Addr
		err  error
	}
	done := make(chan result, 1)
	go func() { p := make([]byte, 32); n, addr, err := c.ReadFrom(p); done <- result{string(p[:n]), addr, err} }()
	select {
	case r := <-done:
		t.Fatalf("premature read: %+v", r)
	case <-time.After(20 * time.Millisecond):
	}
	if _, err := c.WriteTo([]byte("silent"), M.ParseSocksaddr("silent.example:53")); err != nil {
		t.Fatal(err)
	}
	target := M.ParseSocksaddr("reply.example:5353")
	if _, err := c.WriteTo([]byte("answer"), target); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil || r.body != "answer" || M.SocksaddrFromNet(r.addr) != target {
		t.Fatalf("reply: %+v", r)
	}
	for _, body := range [][]byte{nil, []byte("one"), make([]byte, 65535)} {
		if _, err := c.WriteTo(body, M.Socksaddr{}); err != nil {
			t.Fatal(err)
		}
		p := make([]byte, 8)
		n, addr, err := c.ReadFrom(p)
		if err != nil || n != min(len(body), len(p)) || M.SocksaddrFromNet(addr) != c.destination {
			t.Fatalf("datagram n=%d addr=%v err=%v", n, addr, err)
		}
	}
}

func TestPacketReadCloseCancelAndDeadline(t *testing.T) {
	for _, action := range []string{"close", "cancel", "deadline"} {
		t.Run(action, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := newPacketConn(ctx, M.Socksaddr{}, nil)
			defer c.Close()
			done := make(chan error, 1)
			go func() { _, _, err := c.ReadFrom(make([]byte, 8)); done <- err }()
			switch action {
			case "close":
				c.Close()
			case "cancel":
				cancel()
			case "deadline":
				c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("missing error")
				}
			case <-time.After(time.Second):
				t.Fatal("read remained blocked")
			}
			if action == "deadline" {
				c.SetReadDeadline(time.Time{})
				c.packets <- receivedPacket{data: []byte("ok"), source: M.ParseSocksaddr("192.0.2.1:53")}
				if _, _, err := c.ReadFrom(make([]byte, 8)); err != nil {
					t.Fatal(err)
				}
			} else if _, err := c.WriteTo(nil, M.ParseSocksaddr("192.0.2.1:53")); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("write after close: %v", err)
			}
		})
	}
}

func TestPacketWriteCancellationDuringOpen(t *testing.T) {
	for _, action := range []string{"close", "deadline"} {
		t.Run(action, func(t *testing.T) {
			started := make(chan struct{})
			c := newPacketConn(context.Background(), M.ParseSocksaddr("192.0.2.1:53"), func(ctx context.Context, _ wire.Target) (net.Conn, error) {
				close(started)
				<-ctx.Done()
				return nil, ctx.Err()
			})
			defer c.Close()
			done := make(chan error, 1)
			go func() { _, err := c.WriteTo([]byte("x"), M.Socksaddr{}); done <- err }()
			<-started
			var want error = net.ErrClosed
			if action == "close" {
				c.Close()
			} else {
				want = os.ErrDeadlineExceeded
				c.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatalf("got %v want %v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("write remained blocked")
			}
		})
	}
}

func TestPacketWriteDeadlineAndEviction(t *testing.T) {
	c := echoPacketConn(t)
	if _, err := c.WriteTo(make([]byte, 65536), c.destination); !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("oversized packet: %v", err)
	}
	c.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := c.WriteTo(nil, c.destination); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	c.SetWriteDeadline(time.Time{})
	for i := 0; i < maxCachedFlows+5; i++ {
		if _, err := c.WriteTo(nil, M.ParseSocksaddr(fmt.Sprintf("silent.example:%d", i+1))); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.flows) != maxCachedFlows || len(c.order) != maxCachedFlows {
		t.Fatal("flow cache unbounded")
	}
	if c.flows["silent.example:1"] != nil {
		t.Fatal("oldest flow not evicted")
	}
}

func TestPacketConcurrentWritesPreserveFrames(t *testing.T) {
	c := echoPacketConn(t)
	c.SetDeadline(time.Now().Add(3 * time.Second))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := c.WriteTo([]byte(fmt.Sprint(i)), c.destination); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	seen := map[string]bool{}
	for i := 0; i < 16; i++ {
		p := make([]byte, 16)
		n, _, err := c.ReadFrom(p)
		if err != nil {
			t.Fatal(err)
		}
		seen[string(p[:n])] = true
	}
	if len(seen) != 16 {
		t.Fatalf("corrupted frames: %v", seen)
	}
}

func TestPacketBlockedWriteDeadlineCanBeReset(t *testing.T) {
	var peer net.Conn
	c := newPacketConn(context.Background(), M.ParseSocksaddr("192.0.2.1:53"), func(context.Context, wire.Target) (net.Conn, error) { a, b := net.Pipe(); peer = b; return a, nil })
	defer c.Close()
	done := make(chan error, 1)
	c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	go func() { _, err := c.WriteTo([]byte("blocked"), c.destination); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked write ignored deadline")
	}
	peer.Close()
	c.SetWriteDeadline(time.Time{})
	c.mu.Lock()
	count := len(c.flows)
	c.mu.Unlock()
	if count != 0 {
		t.Fatal("partial framed flow reused")
	}
}

func TestPacketReadDeadlineExtension(t *testing.T) {
	c := echoPacketConn(t)
	c.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	done := make(chan error, 1)
	go func() { _, _, err := c.ReadFrom(make([]byte, 8)); done <- err }()
	c.SetReadDeadline(time.Now().Add(time.Second))
	select {
	case err := <-done:
		t.Fatalf("old deadline fired: %v", err)
	case <-time.After(60 * time.Millisecond):
	}
	c.WriteTo([]byte("ok"), c.destination)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("deadline extension blocked receive")
	}
}
