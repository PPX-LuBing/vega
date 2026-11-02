package store

import "testing"

func TestPrepareNodeTLSAndReality(t *testing.T) {
	for _, proto := range []string{ProtoNowhere, ProtoAnyTLS, ProtoHysteria2, ProtoVLESS, ProtoVMess, ProtoTrojan} {
		n := Node{Tag: "test", Proto: proto, Port: 443, TLSMode: "tls"}
		if err := PrepareNode(&n); err == nil {
			t.Fatalf("%s accepted missing certificate", proto)
		}
		n.CertPath, n.KeyPath = "cert.pem", "key.pem"
		if err := PrepareNode(&n); err != nil {
			t.Fatal(err)
		}
	}
	n := Node{Tag: "reality", Proto: ProtoVLESS, Port: 443, TLSMode: "reality", SNI: "example.com", Dest: "example.com:443"}
	if err := PrepareNode(&n); err != nil {
		t.Fatal(err)
	}
	key, pub, id := n.PrivKey, n.PubKey, n.ShortID
	if err := PrepareNode(&n); err != nil || n.PrivKey != key || n.PubKey != pub || n.ShortID != id {
		t.Fatal("editing rotated keys")
	}
	n.Transport = "ws"
	if err := PrepareNode(&n); err == nil {
		t.Fatal("REALITY WS accepted")
	}
	n = Node{Tag: "ss", Proto: ProtoShadowsocks, Port: 1234}
	if err := PrepareNode(&n); err != nil || n.TLSMode != "none" || n.SSPassword == "" {
		t.Fatalf("SS defaults: %v", err)
	}
}
