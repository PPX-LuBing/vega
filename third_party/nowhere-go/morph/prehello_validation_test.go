package morph

import "testing"

func TestAcceptorAdmission(t *testing.T) {
	valid := minimalClientHello()[5:]
	if !clientHelloWellFormed(valid) {
		t.Fatal("valid ClientHello rejected")
	}
	badCompression := append([]byte{}, valid...)
	badCompression[44] = 1
	if clientHelloWellFormed(badCompression) {
		t.Fatal("non-null compression admitted")
	}
	// 显式构造「没有 signature_algorithms」的握手：把它那个扩展整段删掉，
	// 而不是靠改末尾字节碰运气（样本里扩展顺序变了测试就会失真）。
	missingSignature := dropExtension(valid, 13)
	if clientHelloWellFormed(missingSignature) {
		t.Fatal("missing signature algorithms admitted")
	}
	for _, tc := range []struct {
		typ   uint16
		value []byte
		want  bool
	}{
		{13, []byte{0, 2, 8, 4}, true}, {13, []byte{0, 0}, false}, {13, []byte{0, 1, 8}, false},
		{16, []byte{0, 2, 1, 'x'}, true}, {16, []byte{0, 1, 0}, false}, {16, []byte{0, 0}, false},
		{51, []byte{0, 5, 0, 29, 0, 1, 1}, true}, {51, []byte{0, 4, 0, 29, 0, 0}, false},
		{0, []byte{0, 6, 0, 0, 3, 'a', '.', 'b'}, true}, {0, []byte{0, 4, 0, 0, 1, '*'}, false},
		{0xfe0d, []byte{1}, true}, {0xfe0d, []byte{1, 1}, false}, {0xfe0d, nil, false},
		{23, nil, true}, {23, []byte{0}, false}, {65534, []byte{1, 2, 3}, true},
	} {
		if got := validClientExtension(tc.typ, tc.value); got != tc.want {
			t.Errorf("extension %x/%x = %t", tc.typ, tc.value, got)
		}
	}
	for _, name := range []string{"localhost", "example.com", "a_b.example", "example.com.", "127.0.0.1", "::1"} {
		if !validServerName(name) {
			t.Errorf("valid SNI %q rejected", name)
		}
	}
	for _, name := range []string{"", "a..b", "-a.example", "a-.example", "*.example", "abc.123", "a/b"} {
		if validServerName(name) {
			t.Errorf("invalid SNI %q admitted", name)
		}
	}
}

func FuzzAcceptorAdmission(f *testing.F) {
	f.Add(minimalClientHello()[5:])
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = clientHelloWellFormed(b)
		if len(b) > 1 {
			_ = validClientExtension(uint16(b[0])<<8|uint16(b[1]), b[2:])
		}
	})
}

// dropExtension 从 ClientHello 消息体里摘掉指定类型的扩展，并修正各层长度。
func dropExtension(message []byte, drop uint16) []byte {
	body := append([]byte{}, message[4:]...)
	pos := 34 // legacy_version + random
	sessionLen := int(body[pos])
	pos += 1 + sessionLen
	suiteLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2 + suiteLen
	compLen := int(body[pos])
	pos += 1 + compLen
	if pos+2 > len(body) {
		return message
	}
	extStart := pos + 2
	var kept []byte
	rest := body[extStart:]
	for len(rest) >= 4 {
		typ := uint16(rest[0])<<8 | uint16(rest[1])
		size := int(rest[2])<<8 | int(rest[3])
		if len(rest) < 4+size {
			break
		}
		if typ != drop {
			kept = append(kept, rest[:4+size]...)
		}
		rest = rest[4+size:]
	}
	out := append([]byte{}, body[:pos]...)
	out = append(out, byte(len(kept)>>8), byte(len(kept)))
	out = append(out, kept...)
	msg := []byte{tlsClientHello, byte(len(out) >> 16), byte(len(out) >> 8), byte(len(out))}
	return append(msg, out...)
}
