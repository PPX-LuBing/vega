package sub

import (
	"strings"
	"testing"

	"github.com/PPX-LuBing/vega/panel/internal/store"
)

func TestNowhereCarrierSubscriptions(t *testing.T) {
	for _, carrier := range []string{"", "tcp", "quic", "both"} {
		e := endpoint{Host: "node.example", Port: 8446, Node: store.Node{Tag: "nw", Proto: store.ProtoNowhere, TLSMode: "tls", SNI: "node.example", Morph: true, NowhereCarrier: carrier}, User: store.User{SharedKey: "0123456789abcdef0123456789abcdef"}}
		ob, ok := singboxOutbound(e)
		if !ok || ob["carrier"] != e.Node.NowhereClientCarrier() {
			t.Fatalf("singbox %q: %v", carrier, ob)
		}
		a, err := ajsonProxy(e)
		if err != nil {
			t.Fatal(err)
		}
		want := "tcp"
		if carrier == "quic" {
			want = "udp"
		}
		if a["network"] != want {
			t.Fatalf("AJSON: %v", a)
		}
		uri, err := nowhereURI(e)
		if err != nil || strings.Contains(uri, "/udp:8446") != (carrier == "quic") {
			t.Fatalf("URI %s: %v", uri, err)
		}
	}
}
