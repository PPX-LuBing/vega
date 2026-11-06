//go:build !with_quic

package nowhere

import (
	"context"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"strings"
	"testing"
)

func TestQUICRequiresBuildTag(t *testing.T) {
	logger := log.NewNOPFactory().NewLogger("test")
	_, err := NewInbound(context.Background(), nil, logger, "test", option.NowhereInboundOptions{Carrier: "quic"})
	if err == nil || !strings.Contains(err.Error(), "with_quic") {
		t.Fatalf("inbound: %v", err)
	}
	_, err = NewOutbound(context.Background(), nil, logger, "test", option.NowhereOutboundOptions{Carrier: "quic"})
	if err == nil || !strings.Contains(err.Error(), "with_quic") {
		t.Fatalf("outbound: %v", err)
	}
	_, err = newEgressService(context.Background(), logger, "test", option.NowhereEgressServiceOptions{NowhereOutboundOptions: option.NowhereOutboundOptions{Carrier: "quic"}})
	if err == nil || !strings.Contains(err.Error(), "with_quic") {
		t.Fatalf("service: %v", err)
	}
}
