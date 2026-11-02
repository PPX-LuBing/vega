package rule

import (
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

// The panel test pins its generated rule to this same fixture. Evaluate it with
// the real core matcher so a valid JSON document cannot hide a scope regression.
func TestVegaQUICPolicy(t *testing.T) {
	ctx := addressFilterContext(t, map[string]string{
		"cn_additional": `{"version":3,"rules":[{"domain_suffix":["domestic.example"]}]}`,
		"cn_ip":         `{"version":3,"rules":[{"ip_cidr":["192.0.2.0/24","2001:db8:1::/48"]}]}`,
	})
	body, err := os.ReadFile("../../panel/internal/sub/testdata/quic-rule.json")
	require.NoError(t, err)
	var options option.Rule
	require.NoError(t, json.UnmarshalContext(ctx, body, &options))
	generated, err := NewRule(ctx, log.NewNOPFactory().Logger(), options, false)
	require.NoError(t, err)
	require.NoError(t, generated.Start())
	t.Cleanup(func() { require.NoError(t, generated.Close()) })
	for _, network := range []string{"tcp", "udp"} {
		for _, port := range []uint16{53, 443, 8443} {
			for _, address := range []struct {
				ip     string
				exempt bool
			}{
				{"192.0.2.10", true}, {"198.51.100.10", false},
				{"2001:db8:1::10", true}, {"2001:db8:2::10", false},
			} {
				for _, domain := range []struct {
					name   string
					exempt bool
				}{
					{"", false}, {"foreign.example", false}, {"domestic.example", true}, {"sub.domestic.example", true},
				} {
					t.Run(fmt.Sprintf("%s/%d/%s/%s", network, port, address.ip, domain.name), func(t *testing.T) {
						metadata := adapter.InboundContext{Network: network, Domain: domain.name, Destination: M.ParseSocksaddrHostPort(address.ip, port)}
						want := network == "udp" && port == 443 && !address.exempt && !domain.exempt
						require.Equal(t, want, generated.Match(&metadata))
					})
				}
			}
		}
	}
	metadata := adapter.InboundContext{Network: "udp", Domain: "foreign.example", Destination: M.ParseSocksaddrHostPort("foreign.example", 443), DestinationAddresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}}
	require.False(t, generated.Match(&metadata), "already resolved domestic IP must be exempt")
}
