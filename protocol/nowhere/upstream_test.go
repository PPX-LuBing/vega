package nowhere

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func TestStreamPairHalfClose(t *testing.T) {
	client, server := streamPair()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	go func() {
		body, err := io.ReadAll(server)
		if err == nil {
			_, _ = server.Write(append([]byte("ACK:"), body...))
		}
		_ = server.(*streamConn).CloseWrite()
	}()
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := client.(*streamConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(client)
	if err != nil || string(body) != "ACK:ping" {
		t.Fatalf("%q %v", body, err)
	}
}

func TestDatagramBridgePreservesPackets(t *testing.T) {
	left, right := streamPair()
	defer left.Close()
	defer right.Close()
	client, server := &datagramConn{Conn: left}, &datagramConn{Conn: right}
	_ = client.SetDeadline(time.Now().Add(time.Second))
	packets := [][]byte{nil, []byte("a"), bytes.Repeat([]byte("z"), 8192)}
	go func() {
		for _, p := range packets {
			_, _ = server.Write(p)
		}
	}()
	for _, want := range packets {
		got := make([]byte, 65535)
		n, err := client.Read(got)
		if err != nil || !bytes.Equal(got[:n], want) {
			t.Fatalf("packet len %d/%d: %v", n, len(want), err)
		}
	}
}
