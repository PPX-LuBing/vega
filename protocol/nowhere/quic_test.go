//go:build with_quic

package nowhere

import "testing"

func TestMorphCID(t *testing.T) {
	g := &morphCIDGenerator{secret: [32]byte{1}}
	id, err := g.GenerateConnectionID()
	if err != nil {
		t.Fatal(err)
	}
	b := id.Bytes()
	if !g.valid(b) {
		t.Fatal("generated CID rejected")
	}
	b[0] ^= 1
	if g.valid(b) || g.valid(nil) {
		t.Fatal("forged CID accepted")
	}
}
