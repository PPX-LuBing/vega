package nowhere

import (
	"context"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/ohmycggk/nowhere-go/wire"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/pipe"
)

const maxCachedFlows = 64

type packetFlow struct {
	net.Conn
	destination M.Socksaddr
	done        chan struct{}
}

type receivedPacket struct {
	data   []byte
	source M.Socksaddr
}

// Each nw3 flow has one target. Fan replies into a bounded queue without
// changing the wire protocol or blocking other targets on the oldest flow.
type packetConn struct {
	ctx         context.Context
	cancel      context.CancelFunc
	destination M.Socksaddr
	open        func(context.Context, wire.Target) (net.Conn, error)
	packets     chan receivedPacket
	writer      chan struct{}
	readLimit   pipe.Deadline
	writeLimit  pipe.Deadline

	mu     sync.Mutex
	closed bool
	flows  map[string]*packetFlow
	order  []string
}

func newPacketConn(ctx context.Context, destination M.Socksaddr, open func(context.Context, wire.Target) (net.Conn, error)) *packetConn {
	ctx, cancel := context.WithCancel(ctx)
	c := &packetConn{
		ctx: ctx, cancel: cancel, destination: destination, open: open,
		packets: make(chan receivedPacket, 64), writer: make(chan struct{}, 1),
		readLimit: pipe.MakeDeadline(), writeLimit: pipe.MakeDeadline(),
		flows: make(map[string]*packetFlow),
	}
	context.AfterFunc(ctx, func() { _ = c.Close() })
	return c
}

// Called with mu held. Close also wakes a reader blocked on the reply queue.
func (c *packetConn) removeFlow(key string, flow *packetFlow) {
	if c.flows[key] != flow {
		return
	}
	delete(c.flows, key)
	c.order = slices.DeleteFunc(c.order, func(item string) bool { return item == key })
	close(flow.done)
	_ = flow.Close()
}

func (c *packetConn) flowFor(ctx context.Context, destination M.Socksaddr) (*packetFlow, error) {
	key := destination.String()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, net.ErrClosed
	}
	flow := c.flows[key]
	c.mu.Unlock()
	if flow != nil {
		return flow, nil
	}
	// Writes are serialized, but never hold mu while dialing: Close must be
	// able to cancel a stalled TLS/auth/setup exchange.
	conn, err := c.open(ctx, wireTarget(destination))
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || ctx.Err() != nil {
		_ = conn.Close()
		return nil, net.ErrClosed
	}
	if len(c.order) == maxCachedFlows {
		oldest := c.order[0]
		c.removeFlow(oldest, c.flows[oldest])
	}
	flow = &packetFlow{Conn: conn, destination: destination, done: make(chan struct{})}
	c.flows[key] = flow
	c.order = append(c.order, key)
	go c.readFlow(key, flow)
	return flow, nil
}

func (c *packetConn) readFlow(key string, flow *packetFlow) {
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		c.removeFlow(key, flow)
	}()
	buffer := make([]byte, 65535)
	for {
		n, err := flow.Read(buffer)
		if err != nil {
			return
		}
		packet := receivedPacket{data: slices.Clone(buffer[:n]), source: flow.destination}
		select {
		case c.packets <- packet:
		case <-flow.done:
			return
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *packetConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.ctx.Err() != nil {
		return 0, nil, net.ErrClosed
	}
	deadline := c.readLimit.Wait()
	select {
	case <-deadline:
		return 0, nil, os.ErrDeadlineExceeded
	default:
	}
	select {
	case packet := <-c.packets:
		return copy(p, packet.data), packet.source, nil
	case <-c.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-deadline:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *packetConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > 65535 {
		return 0, &net.OpError{Op: "write", Net: "nowhere", Err: os.ErrInvalid}
	}
	destination := M.SocksaddrFromNet(addr)
	if !destination.IsValid() {
		destination = c.destination
	}
	if !destination.IsValid() {
		return 0, &net.AddrError{Err: "missing UDP target", Addr: destination.String()}
	}
	deadline := c.writeLimit.Wait()
	select {
	case c.writer <- struct{}{}:
		defer func() { <-c.writer }()
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	case <-deadline:
		return 0, os.ErrDeadlineExceeded
	}
	select {
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	case <-deadline:
		return 0, os.ErrDeadlineExceeded
	default:
	}
	ctx, cancel := context.WithCancel(c.ctx)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		select {
		case <-deadline:
			cancel()
		case <-ctx.Done():
		}
	}()
	defer func() { cancel(); <-finished }()
	flow, err := c.flowFor(ctx, destination)
	if err == nil {
		// A timed-out framed write may be partial. Retire that flow rather
		// than reuse a stream with a truncated UoT frame.
		stopped := make(chan struct{})
		stop := context.AfterFunc(ctx, func() { _ = flow.Close(); close(stopped) })
		var n int
		n, err = flow.Write(p)
		if !stop() {
			<-stopped
		}
		if err == nil {
			return n, nil
		}
		c.mu.Lock()
		c.removeFlow(destination.String(), flow)
		c.mu.Unlock()
	}
	select {
	case <-deadline:
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if c.ctx.Err() != nil {
		return 0, net.ErrClosed
	}
	return 0, err
}

func (c *packetConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		c.cancel()
		c.readLimit.Set(time.Time{})
		c.writeLimit.Set(time.Time{})
		for key, flow := range c.flows {
			c.removeFlow(key, flow)
		}
	}
	return nil
}

func (c *packetConn) LocalAddr() net.Addr { return M.Socksaddr{} }

func (c *packetConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.readLimit.Set(t)
	c.writeLimit.Set(t)
	return nil
}

func (c *packetConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.readLimit.Set(t)
	return nil
}

func (c *packetConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return net.ErrClosed
	}
	c.writeLimit.Set(t)
	return nil
}
