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

// 不给 cert_path 表示「用面板自己签的证书」，这时 SNI 必须能给（内核按它找目录）。
func TestPrepareNodeManagedCertificate(t *testing.T) {
	n := Node{Tag: "managed", Proto: ProtoAnyTLS, Port: 8444, TLSMode: "tls", SNI: "hk.example.com"}
	if err := PrepareNode(&n); err != nil {
		t.Fatalf("有 SNI 就该接受省略证书路径: %v", err)
	}
	// 只给一半的路径是写错了，不能当成「用面板证书」
	n = Node{Tag: "half", Proto: ProtoAnyTLS, Port: 8444, TLSMode: "tls", SNI: "hk.example.com", CertPath: "cert.pem"}
	if err := PrepareNode(&n); err == nil {
		t.Fatal("只给 cert_path 不给 key_path 应当报错")
	}
	// SNI 会被拼成目录名，"." 和 ".." 能跳出证书目录
	n = Node{Tag: "dotdot", Proto: ProtoAnyTLS, Port: 8444, TLSMode: "tls", SNI: ".."}
	if err := PrepareNode(&n); err == nil {
		t.Fatal("SNI 是 .. 应当报错")
	}
}
