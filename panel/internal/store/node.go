package store

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// PrepareNode is shared by interactive and command-line writes. Low-level
// persistence still accepts incomplete legacy records so they can be repaired.
func PrepareNode(n *Node) error {
	if n.Proto == ProtoShadowsocks {
		n.TLSMode = "none"
		if n.SSMethod == "" {
			n.SSMethod = "2022-blake3-aes-128-gcm"
		}
		if n.SSPassword == "" {
			n.SSPassword = NewSecret()
		}
	}
	if n.TLSMode == "" {
		n.TLSMode = "tls"
	}
	if n.TLSMode == "reality" {
		if n.PrivKey == "" {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			n.PrivKey = base64.RawURLEncoding.EncodeToString(key.Bytes())
			n.PubKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
		} else {
			raw, err := base64.RawURLEncoding.DecodeString(n.PrivKey)
			if err != nil {
				return fmt.Errorf("invalid REALITY private key")
			}
			key, err := ecdh.X25519().NewPrivateKey(raw)
			if err != nil {
				return err
			}
			n.PubKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
		}
		if n.ShortID == "" {
			n.ShortID = NewNowhereKey()[:16]
		}
	}
	return ValidateNode(*n)
}

func ValidateNode(n Node) error {
	if err := validateNowhere(n); err != nil {
		return err
	}
	if !ValidProto(n.Proto) || n.Port < 1 || n.Port > 65535 || strings.TrimSpace(n.Tag) == "" {
		return fmt.Errorf("invalid node protocol, tag or port")
	}
	if n.EntryPort < 0 || n.EntryPort > 65535 {
		return fmt.Errorf("invalid entry port")
	}
	if n.EntryPort > 0 && strings.TrimSpace(n.EntryHost) == "" {
		return fmt.Errorf("entry port requires entry host")
	}
	switch n.Transport {
	case "", "tcp":
	case "ws", "grpc", "httpupgrade":
		if n.Proto != ProtoVMess && n.Proto != ProtoVLESS && n.Proto != ProtoTrojan {
			return fmt.Errorf("transport requires VMess, VLESS or Trojan")
		}
	default:
		return fmt.Errorf("unsupported transport")
	}
	if n.UpMbps < 0 || n.DownMbps < 0 {
		return fmt.Errorf("bandwidth cannot be negative")
	}
	if n.Fingerprint != "" && n.Proto == ProtoHysteria2 {
		return fmt.Errorf("Hysteria2 uses QUIC TLS, not a TCP uTLS fingerprint")
	}
	for _, name := range []string{n.SNI, n.EntrySNI} {
		if strings.ContainsAny(name, ", /\\\t\r\n") {
			return fmt.Errorf("SNI must be a single hostname or IP")
		}
		// SNI 会被拼成 <cert_dir>/<SNI>/，"." 和 ".." 能跳出目录
		if name == "." || name == ".." {
			return fmt.Errorf("invalid SNI")
		}
	}
	for _, host := range strings.Split(n.EntryHost, ",") {
		host = strings.TrimSpace(host)
		if n.EntryHost != "" && host == "" {
			return fmt.Errorf("empty entry host")
		}
		if host != "" && net.ParseIP(host) == nil && strings.ContainsAny(host, " /\\:\t\r\n") {
			return fmt.Errorf("invalid entry host")
		}
	}
	if n.TLSMode == "none" {
		if n.Proto == ProtoNowhere || n.Proto == ProtoAnyTLS || n.Proto == ProtoHysteria2 {
			return fmt.Errorf("%s requires TLS in panel-managed configurations", n.Proto)
		}
	} else if n.TLSMode == "reality" {
		if n.Proto != ProtoVLESS || (n.Transport != "" && n.Transport != "tcp") {
			return fmt.Errorf("REALITY requires VLESS over TCP")
		}
		if n.PrivKey == "" || n.PubKey == "" || n.Dest == "" || n.SNI == "" {
			return fmt.Errorf("REALITY requires keys, dest and SNI")
		}
		private, err := base64.RawURLEncoding.DecodeString(n.PrivKey)
		if err != nil {
			return fmt.Errorf("invalid REALITY private key")
		}
		key, err := ecdh.X25519().NewPrivateKey(private)
		if err != nil || base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()) != n.PubKey {
			return fmt.Errorf("invalid or mismatched REALITY keypair")
		}
		host, port, err := net.SplitHostPort(n.Dest)
		p, portErr := strconv.Atoi(port)
		if err != nil || host == "" || portErr != nil || p < 1 || p > 65535 {
			return fmt.Errorf("REALITY dest must be host:port")
		}
		if b, err := hex.DecodeString(n.ShortID); err != nil || len(b) == 0 || len(b) > 8 {
			return fmt.Errorf("invalid REALITY short ID")
		}
	} else if n.TLSMode == "tls" {
		if (n.CertPath == "") != (n.KeyPath == "") {
			return fmt.Errorf("TLS requires both certificate and key paths")
		}
		// 不给 cert_path 表示「用面板自己签的证书」：内核会按 SNI 去
		// <cert_dir>/<SNI>/ 找（见 kernel.buildTLS），所以 SNI 必须能给。
		if n.CertPath == "" && strings.TrimSpace(n.SNI) == "" {
			return fmt.Errorf("TLS without explicit cert/key requires SNI")
		}
	} else {
		return fmt.Errorf("TLS mode must be tls/reality/none")
	}
	if n.Proto == ProtoShadowsocks {
		if n.TLSMode != "none" {
			return fmt.Errorf("managed Shadowsocks does not use TLS")
		}
		if n.SSMethod != "2022-blake3-aes-128-gcm" {
			return fmt.Errorf("panel multi-user Shadowsocks currently requires 2022-blake3-aes-128-gcm")
		}
		key, err := base64.StdEncoding.DecodeString(n.SSPassword)
		if err != nil || len(key) != 16 {
			return fmt.Errorf("SS2022 requires a 16-byte base64 server key")
		}
	}
	return nil
}

func (n Node) TransportConfig() map[string]any {
	switch n.Transport {
	case "ws":
		m := map[string]any{"type": "ws", "path": n.Path}
		if n.Host != "" {
			m["headers"] = map[string]string{"Host": n.Host}
		}
		return m
	case "httpupgrade":
		return map[string]any{"type": "httpupgrade", "path": n.Path, "host": n.Host}
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": n.GRPCService}
	default:
		return nil
	}
}

func validateNowhere(n Node) error {
	if n.Proto != ProtoNowhere {
		if n.NowhereCarrier != "" || n.NowhereEgress {
			return fmt.Errorf("Nowhere options require a Nowhere node")
		}
		return nil
	}
	switch n.NowhereCarrier {
	case "", "tcp", "quic", "both":
	default:
		return fmt.Errorf("Nowhere carrier must be tcp/quic/both")
	}
	if n.Fingerprint != "" {
		return fmt.Errorf("Nowhere uses standard TLS 1.3 and does not support a uTLS fingerprint")
	}
	return nil
}

// Both listeners advertise TCP by default; use a QUIC-only node to publish UDP.
func (n Node) NowhereClientCarrier() string {
	if n.NowhereCarrier == "quic" {
		return "quic"
	}
	return "tcp"
}
