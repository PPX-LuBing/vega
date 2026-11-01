package nowhere

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/wire"
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

// 缓冲区装不下整个报文时必须截断，不能报错。
//
// ReadUoT 已经把包从流里读完了，此时返回 io.ErrShortBuffer 等于把这份
// 报文静默丢掉；调用方看到错误通常会重试，重试拿到的却是下一个包，
// 数据就串位了。截断是 UDP 的常规语义。
func TestDatagramConnTruncatesOversizedPacket(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payload := make([]byte, 512)
	for i := range payload {
		payload[i] = byte(i)
	}
	go func() {
		_ = wire.WriteUoT(server, payload)
	}()

	conn := &datagramConn{Conn: client}
	small := make([]byte, 64)
	n, err := conn.Read(small)
	if err != nil {
		t.Fatalf("装不下时应截断而不是报错，实际 %v", err)
	}
	if n != len(small) {
		t.Fatalf("应返回缓冲区长度 %d，实际 %d", len(small), n)
	}
	for i := range small {
		if small[i] != payload[i] {
			t.Fatalf("截断内容不对，第 %d 字节: %d != %d", i, small[i], payload[i])
		}
	}

	// 装得下时要完整返回
	go func() {
		_ = wire.WriteUoT(server, payload)
	}()
	full := make([]byte, 1024)
	n, err = conn.Read(full)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(payload) {
		t.Fatalf("装得下时应返回 %d 字节，实际 %d", len(payload), n)
	}
}
