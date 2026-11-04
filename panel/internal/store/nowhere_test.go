package store

import (
	"path/filepath"
	"testing"
)

func TestNowhereOptionsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	n := Node{Tag: "nw", Proto: ProtoNowhere, Port: 8446, TLSMode: "tls", SNI: "node.example", Enabled: true, NowhereCarrier: "both", NowhereEgress: true, Morph: true}
	if err := PrepareNode(&n); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveNode(n); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Node(n.Tag)
	if err != nil || got.NowhereCarrier != "both" || !got.NowhereEgress {
		t.Fatalf("%+v: %v", got, err)
	}
	for _, bad := range []Node{{Tag: "bad", Proto: ProtoAnyTLS, Port: 443, NowhereCarrier: "quic"}, {Tag: "bad", Proto: ProtoNowhere, Port: 443, NowhereCarrier: "udp"}, {Tag: "bad", Proto: ProtoNowhere, Port: 443, NowhereCarrier: "quic", Fingerprint: "chrome"}} {
		if err := s.SaveNode(bad); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}

func TestOldNodeSchemaMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "panel.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveNode(Node{Tag: "old", Proto: ProtoNowhere, Port: 8446, Morph: true}); err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"nowhere_carrier", "nowhere_egress"} {
		if _, err := s.db.Exec("ALTER TABLE nodes DROP COLUMN " + column); err != nil {
			t.Fatal(err)
		}
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	n, err := s.Node("old")
	if err != nil || n.NowhereCarrier != "" || n.NowhereEgress || !n.Morph {
		t.Fatalf("migration changed old node: %+v, %v", n, err)
	}
}
