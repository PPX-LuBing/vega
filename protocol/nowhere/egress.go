package nowhere

import (
	"context"
	"fmt"
	"net"

	"github.com/ohmycggk/nowhere-go/egress"
	"github.com/ohmycggk/nowhere-go/portal"
	"github.com/ohmycggk/nowhere-go/qio"
	nruntime "github.com/ohmycggk/nowhere-go/runtime"
	"github.com/ohmycggk/nowhere-go/wire"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/common/dialer"
	singtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

const egressType = "nowhere-egress"

func RegisterEgressOutbound(registry *outbound.Registry) {
	outbound.Register[option.NowhereEgressOutboundOptions](registry, egressType, newEgressOutbound)
}
func RegisterEgressService(registry *boxservice.Registry) {
	boxservice.Register[option.NowhereEgressServiceOptions](registry, egressType, newEgressService)
}

type egressOutbound struct {
	outbound.Adapter
	manager adapter.InboundManager
	portal  string
}

func newEgressOutbound(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options option.NowhereEgressOutboundOptions) (adapter.Outbound, error) {
	if options.Portal == "" {
		return nil, fmt.Errorf("nowhere-egress: portal inbound tag required")
	}
	o := &egressOutbound{outbound.NewAdapter(egressType, tag, []string{"tcp", "udp"}, nil), service.FromContext[adapter.InboundManager](ctx), options.Portal}
	if _, err := o.portalInbound(); err != nil {
		return nil, err
	}
	return o, nil
}
func (o *egressOutbound) portalInbound() (*Inbound, error) {
	if o.manager == nil {
		return nil, fmt.Errorf("nowhere-egress: inbound manager unavailable")
	}
	in, ok := o.manager.Get(o.portal)
	if !ok {
		return nil, fmt.Errorf("nowhere-egress: portal %q not found", o.portal)
	}
	p, ok := in.(*Inbound)
	if !ok || !p.options.Egress {
		return nil, fmt.Errorf("nowhere-egress: referenced inbound must enable egress")
	}
	return p, nil
}
func (o *egressOutbound) portalServer() (*portal.Server, error) {
	p, err := o.portalInbound()
	if err != nil {
		return nil, err
	}
	if p.server == nil {
		return nil, fmt.Errorf("nowhere-egress: portal not started")
	}
	return p.server, nil
}
func (o *egressOutbound) Start(stage adapter.StartStage, _ *adapter.Scope) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	_, err := o.portalServer()
	return err
}
func (o *egressOutbound) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	p, err := o.portalServer()
	if err != nil {
		return nil, err
	}
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil || metadata.Inbound != o.portal {
		return nil, fmt.Errorf("nowhere-egress: only the referenced authenticated inbound may use this exit")
	}
	kind := wire.FlowTCP
	if network == "udp" {
		kind = wire.FlowUDP
	} else if network != "tcp" {
		return nil, fmt.Errorf("unsupported network %s", network)
	}
	return p.DialEgress(ctx, metadata.User, kind, wireTarget(dest))
}
func (o *egressOutbound) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = o.Tag()
	metadata.Destination = dest
	return newPacketConn(ctx, dest, func(ctx context.Context, target wire.Target) (net.Conn, error) {
		return o.DialContext(ctx, "udp", targetSocksaddr(target))
	}), nil
}

type egressService struct {
	boxservice.Adapter
	config egress.Config
	logger log.ContextLogger
	route  *upstream
	user   string
}

func newEgressService(ctx context.Context, logger log.ContextLogger, tag string, options option.NowhereEgressServiceOptions) (adapter.Service, error) {
	transport, err := carrier(options.Carrier, false)
	if err != nil {
		return nil, err
	}
	if transport == "quic" && !quicAvailable {
		return nil, fmt.Errorf("nowhere: QUIC requires with_quic")
	}
	if err := wire.ValidateServiceKey(options.SharedKey); err != nil {
		return nil, err
	}
	masked := options.Morph == nil || *options.Morph
	if _, err := nruntime.Load(options.SharedKey, masked && transport == "quic"); err != nil {
		return nil, err
	}
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, fmt.Errorf("nowhere-egress: TLS required")
	}
	tlsConfig, err := singtls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	config, err := tlsConfig.STDConfig()
	if err != nil {
		return nil, err
	}
	d, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	router := service.FromContext[adapter.Router](ctx)
	s := &egressService{Adapter: boxservice.NewAdapter(egressType, tag), logger: logger, user: options.User,
		route: &upstream{ctx: ctx, router: uot.NewRouter(router, logger), tag: tag}}
	s.config = egress.Config{SharedKey: options.SharedKey, Morph: masked, PortalAddr: options.ServerOptions.Build().String(), TLS: config,
		Upstream: s.route, UploadMbps: options.UploadMbps, DownloadMbps: options.DownloadMbps}
	if transport == "tcp" {
		s.config.DialTCP = func(ctx context.Context, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", options.ServerOptions.Build())
		}
	} else {
		s.config.DialQUIC = func(ctx context.Context) (qio.Conn, error) {
			conn, err := d.DialContext(ctx, "udp", options.ServerOptions.Build())
			if err != nil {
				return nil, err
			}
			return dialQUIC(ctx, bufio.NewUnbindPacketConn(conn), conn.RemoteAddr(), config, options.SharedKey, masked)
		}
		if masked {
			s.config.DatagramOverhead = 12
		}
	}
	return s, nil
}
func (s *egressService) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStatePostStart {
		return nil
	}
	ctx := portal.ContextWithUser(scope.Context(), s.user)
	s.route.ctx = ctx
	done := make(chan struct{})
	scope.Add(func() error { <-done; return nil })
	go func() {
		defer close(done)
		if err := egress.Run(ctx, s.config); err != nil && ctx.Err() == nil {
			s.logger.Error(err)
		}
	}()
	return nil
}
