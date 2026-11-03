package nowhere

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/portal"
	"github.com/ohmycggk/nowhere-go/wire"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

type morphEcho struct{}

func (morphEcho) DialTCP(context.Context, wire.Target) (net.Conn, error) {
	a, b := net.Pipe()
	go func() { defer b.Close(); io.Copy(b, b) }()
	return a, nil
}
func (morphEcho) DialUDP(ctx context.Context, target wire.Target) (net.Conn, error) {
	return morphEcho{}.DialTCP(ctx, target)
}
func TestMorphOmitted(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t)
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := portal.New(portal.Config{SharedKey: morphTestKey, Morph: true, TLS: &tls.Config{Certificates: []tls.Certificate{pair}}, Upstream: morphEcho{}})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer ln.Close()
	go srv.Serve(ctx, ln)
	for _, explicit := range []bool{true, false} {
		t.Run(map[bool]string{true: "explicit_true", false: "omitted"}[explicit], func(t *testing.T) {
			var morph *bool
			if explicit {
				v := true
				morph = &v
			}
			out, err := NewOutbound(context.Background(), nil, log.NewNOPFactory().NewLogger("review"), "review", option.NowhereOutboundOptions{ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: uint16(ln.Addr().(*net.TCPAddr).Port)}, OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{Enabled: true, Insecure: true}}, SharedKey: morphTestKey, Morph: morph})
			if err != nil {
				t.Fatal(err)
			}
			defer out.(*Outbound).client.Close()
			dialCtx, stop := context.WithTimeout(ctx, 3*time.Second)
			defer stop()
			c, err := out.DialContext(dialCtx, "tcp", M.ParseSocksaddr("192.0.2.1:80"))
			if err != nil {
				t.Fatalf("default inbound has Morph=true but outbound connection fails: %v", err)
			}
			defer c.Close()
			// The dial context must no longer own a successfully opened flow.
			stop()
			if err := c.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Write([]byte("ok")); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 2)
			if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ok" {
				t.Fatalf("flow after dial cancellation: %q, %v", buf, err)
			}
		})
	}
}

const morphTestKey = "0123456789abcdef0123456789abcdef"
