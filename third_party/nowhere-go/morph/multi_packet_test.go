package morph

import (
	"bytes"
	"testing"
)

func TestMultiKeyPacketAdmission(t *testing.T) {
	cid := bytes.Repeat([]byte{42}, 16)
	c := &multiPacketConn{validCID: func(b []byte) bool { return bytes.Equal(b, cid) }}
	short := append([]byte{0x40}, cid...)
	if !c.validPacket(short) {
		t.Fatal("known CID rejected")
	}
	short[1] ^= 1
	if c.validPacket(short) {
		t.Fatal("random short header admitted")
	}
	initial := make([]byte, 1200)
	copy(initial, []byte{0xc0, 0, 0, 0, 1, 8})
	initial[14] = 8
	if !c.validPacket(initial) {
		t.Fatal("Initial rejected")
	}
	initial[4] = 2
	if c.validPacket(initial) {
		t.Fatal("unknown version admitted")
	}
	initial[4] = 1
	initial[5] = 255
	if c.validPacket(initial) {
		t.Fatal("invalid CID admitted")
	}
	for n := 0; n < 25; n++ {
		_ = c.validPacket(make([]byte, n))
	}
}
