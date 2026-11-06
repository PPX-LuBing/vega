package nowhere

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/ohmycggk/nowhere-go/morph"
	"github.com/ohmycggk/nowhere-go/qio"
)

func carrier(value string, inbound bool) (string, error) {
	if value == "" {
		return "tcp", nil
	}
	if value == "tcp" || value == "quic" || (inbound && value == "both") {
		return value, nil
	}
	return "", fmt.Errorf("nowhere: invalid carrier %q", value)
}

type quicDialFunc func(context.Context, net.PacketConn, net.Addr, *tls.Config, string, bool) (qio.Conn, error)
type quicListenFunc func(net.PacketConn, *tls.Config, string, bool, func() []morph.Keys) (qio.Listener, error)

var dialQUIC quicDialFunc = func(context.Context, net.PacketConn, net.Addr, *tls.Config, string, bool) (qio.Conn, error) {
	return nil, fmt.Errorf("nowhere: QUIC requires build tag with_quic")
}
var listenQUIC quicListenFunc = func(net.PacketConn, *tls.Config, string, bool, func() []morph.Keys) (qio.Listener, error) {
	return nil, fmt.Errorf("nowhere: QUIC requires build tag with_quic")
}
var quicAvailable bool
