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
	missingSignature := append([]byte{}, valid...)
	missingSignature[len(missingSignature)-7] = 99
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
