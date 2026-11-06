//go:build with_v2ray_api

package nowhere_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ohmycggk/nowhere-go/morph"
	singtls "github.com/sagernet/sing-box/common/tls"
)

func prehelloRecord(compression byte, extensions []byte) []byte {
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 1, 1, compression)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	message := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{22, 3, 1, byte(len(message) >> 8), byte(len(message))}, message...)
}

type captureHello struct {
	net.Conn
	bytes.Buffer
}

func (c *captureHello) Write(b []byte) (int, error) { return c.Buffer.Write(b) }
func (c *captureHello) Read(b []byte) (int, error)  { return c.Buffer.Read(b) }

// The independent Rust executable is the oracle for both silent admission and
// the later, non-silent TLS phase. Never suppress every TLS alert to pass this.
func TestOfficialSilentPreHello(t *testing.T) {
	binaryPath := os.Getenv("VEGA_TEST_NOWHERE_RUST")
	if binaryPath == "" {
		t.Skip("official Rust binary required")
	}
	dir := t.TempDir()
	key, cert, err := singtls.GenerateCertificate(nil, nil, time.Now, "localhost", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cp, kp := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	for path, data := range map[string][]byte{cp: cert, kp: key} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	addresses := []string{freeAddress(t), freeAddress(t)}
	startOfficialPeer(t, binaryPath, officialURL("portal", addresses[0], url.Values{"morph": {"1"}, "tls": {"2"}, "crt": {cp}, "key": {kp}}), addresses[0])
	startInteropBox(t, map[string]any{"inbounds": []any{map[string]any{"type": "nowhere", "shared_key": integrationAlice, "morph": true, "control_addr": "off", "listen": "127.0.0.1", "listen_port": interopPort(addresses[1]), "tls": map[string]any{"enabled": true, "certificate_path": cp, "key_path": kp}}}, "outbounds": []any{map[string]any{"type": "direct"}}})
	versions := []byte{0, 43, 0, 3, 2, 3, 4}
	signatures := []byte{0, 13, 0, 4, 0, 2, 8, 4}
	validExt := append(append([]byte{}, versions...), signatures...)
	add := func(ext []byte) []byte { return append(append([]byte{}, validExt...), ext...) }
	trailing := append(prehelloRecord(0, validExt), 0)
	binary.BigEndian.PutUint16(trailing[3:5], uint16(len(trailing)-5))
	badVersion := prehelloRecord(0, validExt)
	badVersion[1] = 2
	cases := []struct {
		name   string
		hello  []byte
		silent bool
	}{
		{"missing-signatures", prehelloRecord(0, versions), true},
		{"empty-signatures", prehelloRecord(0, append(append([]byte{}, versions...), 0, 13, 0, 2, 0, 0)), true},
		{"compression", prehelloRecord(1, validExt), true},
		{"invalid-sni", prehelloRecord(0, add([]byte{0, 0, 0, 6, 0, 4, 0, 0, 1, '*'})), true},
		{"empty-alpn", prehelloRecord(0, add([]byte{0, 16, 0, 2, 0, 0})), true},
		{"truncated-keyshare", prehelloRecord(0, add([]byte{0, 51, 0, 5, 0, 3, 0, 29, 0})), true},
		{"duplicate-extension", prehelloRecord(0, add(signatures)), true},
		{"trailing-handshake", trailing, true},
		{"record-version", badVersion, true},
		{"empty-record", append([]byte{22, 3, 1, 0, 0}, prehelloRecord(0, validExt)...), true},
		{"config-dependent-missing-keyshare", prehelloRecord(0, validExt), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for i, addr := range addresses {
				conn, err := net.DialTimeout("tcp", addr, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				wrapped, err := morph.WrapTCPClient(conn, morph.Derive([]byte(integrationAlice)))
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.SetDeadline(time.Now().Add(400 * time.Millisecond))
				if _, err = wrapped.Write(tc.hello); err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 128)
				n, _ := wrapped.Read(b)
				_ = conn.Close()
				if (n == 0) != tc.silent {
					t.Fatalf("peer=%d response bytes=%d silent=%v", i, n, tc.silent)
				}
			}
		})
	}
	// Reject a semantically invalid hello, then repair it using the same valid
	// authenticated prelude/counter. Rejection must not consume the replay slot.
	for i, addr := range addresses {
		t.Run([]string{"rust-replay", "vega-replay"}[i], func(t *testing.T) {
			capture := &captureHello{}
			wrapped, err := morph.WrapTCPClient(capture, morph.Derive([]byte(integrationAlice)))
			if err != nil {
				t.Fatal(err)
			}
			hello := prehelloRecord(0, validExt)
			if _, err = wrapped.Write(hello); err != nil {
				t.Fatal(err)
			}
			good := append([]byte{}, capture.Bytes()...)
			bad := append([]byte{}, good...)
			offset := len(good) - len(hello) + len(hello) - len(signatures) + 1
			bad[offset] ^= 13 ^ 99
			for attempt, payload := range [][]byte{bad, good, good} {
				conn, err := net.DialTimeout("tcp", addr, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.SetDeadline(time.Now().Add(400 * time.Millisecond))
				_, err = conn.Write(payload)
				if err != nil {
					t.Fatal(err)
				}
				b := make([]byte, 128)
				n, _ := conn.Read(b)
				_ = conn.Close()
				if (n > 0) != (attempt == 1) {
					t.Fatalf("attempt %d response bytes=%d", attempt, n)
				}
			}
		})
	}
}
