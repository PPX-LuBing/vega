package morph

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
)

const (
	tlsRecordHeader = 5
	tlsHandshake    = 22
	tlsClientHello  = 1
	tlsMaxCipher    = 16384 + 2048
	tlsMaxHandshake = 65536
	tlsMaxRecords   = 64
)

// readClientHello buffers one structurally complete ClientHello from the
// decrypted Morph stream. The returned bytes include every TLS record consumed
// and are later replayed to crypto/tls unchanged.
//
// This is not a rustls Acceptor. A structurally valid ClientHello is handed to
// crypto/tls, which can still emit an alert for a semantic failure such as an
// unsupported version, an empty cipher overlap, or ALPN. Nowhere suppresses
// those alerts when rustls rejects them inside Acceptor, before ServerConfig is
// applied. Incomplete or structurally malformed input returns before any byte
// reaches crypto/tls, so this stack does not emit a PreHello alert for it.
func (c *tcpConn) readClientHello() ([]byte, error) {
	var buf []byte
	var handshake []byte
	messageLen := -1
	consumed := 0
	for records := 0; records < tlsMaxRecords; records++ {
		if messageLen >= 0 && len(handshake) >= 4+messageLen {
			break
		}
		var err error
		buf, err = c.readPlainUntil(buf, consumed+tlsRecordHeader)
		if err != nil {
			return nil, err
		}
		header := buf[consumed : consumed+tlsRecordHeader]
		if header[0] == 0x80 || header[0] != tlsHandshake {
			return nil, ErrClientHello
		}
		// TLS 记录层版本：主版本必须是 3（SSL 3.0 / TLS 1.x）。真实浏览器
		// 首条记录用 0x0301，后续可能用 0x0303；其它值一律不是 TLS。
		if header[1] != 3 {
			return nil, ErrClientHello
		}
		if records == 0 && binary.BigEndian.Uint16(header[1:3]) >= 0x1000 {
			return nil, ErrClientHello
		}
		recordLen := int(binary.BigEndian.Uint16(header[3:5]))
		// 空记录是合法的 TLS 心跳/占位，但作为 ClientHello 的首条或中间记录
		// 出现就不是浏览器行为（官方实现对空记录静默丢弃）。
		if recordLen == 0 || recordLen > tlsMaxCipher {
			return nil, ErrClientHello
		}
		total := consumed + tlsRecordHeader + recordLen
		if total > tlsMaxHandshake+tlsMaxRecords*tlsRecordHeader {
			return nil, ErrClientHello
		}
		buf, err = c.readPlainUntil(buf, total)
		if err != nil {
			return nil, err
		}
		handshake = append(handshake, buf[consumed+tlsRecordHeader:total]...)
		consumed = total
		if len(handshake) >= 4 && messageLen < 0 {
			if handshake[0] != tlsClientHello {
				return nil, ErrClientHello
			}
			messageLen = int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if messageLen > tlsMaxHandshake {
				return nil, ErrClientHello
			}
		}
		if messageLen >= 0 && len(handshake) >= 4+messageLen {
			// ClientHello 可以跨多条记录，但**拼起来必须恰好等于握手长度**。
			// 多出来的字节说明这条记录里塞了 ClientHello 之外的东西——官方
			// 实现对此静默丢弃（TestOfficialSilentPreHello/trailing-handshake）。
			//
			// 注意：不能要求「每条记录都对齐」，那会把分片发送的合法客户端拒掉；
			// 只能要求「累加总量对齐」。
			if len(handshake) != 4+messageLen {
				return nil, ErrClientHello
			}
			if !clientHelloWellFormed(handshake[:4+messageLen]) {
				return nil, ErrClientHello
			}
			return buf, nil
		}
	}
	return nil, ErrClientHello
}

func (c *tcpConn) readPlainUntil(buf []byte, n int) ([]byte, error) {
	for len(buf) < n {
		need := n - len(buf)
		if c.readCipher.remaining(c.readOff) < uint64(need) {
			return nil, c.readCipher.exhaustedErr()
		}
		next := make([]byte, need)
		if _, err := io.ReadFull(c.Conn, next); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				return nil, ErrClientHello
			}
			return nil, err
		}
		c.readCipher.xorKeyStream(next, next)
		c.readOff += uint64(len(next))
		buf = append(buf, next...)
	}
	return buf, nil
}

func clientHelloWellFormed(message []byte) bool {
	if len(message) < 4 || message[0] != tlsClientHello {
		return false
	}
	n := int(message[1])<<16 | int(message[2])<<8 | int(message[3])
	if n != len(message)-4 {
		return false
	}
	body := message[4:]
	if len(body) < 35 {
		return false
	}
	body = body[34:]
	sessionLen := int(body[0])
	body = body[1:]
	if sessionLen > 32 || len(body) < sessionLen+2 {
		return false
	}
	body = body[sessionLen:]
	suiteLen := int(body[0])<<8 | int(body[1])
	body = body[2:]
	if suiteLen < 2 || suiteLen%2 != 0 || len(body) < suiteLen+1 {
		return false
	}
	body = body[suiteLen:]
	compLen := int(body[0])
	body = body[1:]
	if compLen < 1 || len(body) < compLen {
		return false
	}
	// TLS 1.3 只允许 null 压缩（0x00）。带其它值的是老式或畸形握手，
	// 真实浏览器不会发，探测工具常这么写。
	for _, m := range body[:compLen] {
		if m != 0 {
			return false
		}
	}
	body = body[compLen:]
	if len(body) == 0 {
		return true
	}
	if len(body) < 2 {
		return false
	}
	extLen := int(body[0])<<8 | int(body[1])
	body = body[2:]
	if extLen != len(body) {
		return false
	}
	seen := make(map[uint16]struct{})
	for len(body) > 0 {
		if len(body) < 4 {
			return false
		}
		extType := binary.BigEndian.Uint16(body[:2])
		size := int(binary.BigEndian.Uint16(body[2:4]))
		body = body[4:]
		if _, ok := seen[extType]; ok || len(body) < size {
			return false
		}
		seen[extType] = struct{}{}
		// 逐项校验扩展本身，不只是长度对齐——这是 prehello 加固的核心：
		// 形状对但内容非法的 ClientHello 不该被当成合法浏览器握手放行。
		if !validClientExtension(extType, body[:size]) {
			return false
		}
		body = body[size:]
	}
	// TLS 1.3 强制要求 signature_algorithms；缺了它真实客户端不会这么发。
	if _, ok := seen[13]; !ok {
		return false
	}
	return true
}

// validClientExtension 校验单个 TLS 扩展的结构是否合法。
//
// 只做「形状」检查，不做密码学验证：目的是让 prehello 看起来像一次真实的
// 浏览器握手，并且挡住明显畸形的探测包（空 SNI、通配符、非法 ALPN 列表等）。
func validClientExtension(typ uint16, v []byte) bool {
	switch typ {
	case 13: // signature_algorithms：必须是偶数个 2 字节算法
		if len(v) < 2 || len(v)%2 != 0 {
			return false
		}
		n := int(v[0])<<8 | int(v[1])
		return n > 0 && n == len(v)-2 && n%2 == 0
	case 16: // application_layer_protocol_negotiation：每个条目长度必须自洽
		if len(v) < 2 {
			return false
		}
		n := int(v[0])<<8 | int(v[1])
		if n != len(v)-2 || n < 1 {
			return false
		}
		rest := v[2:]
		for len(rest) > 0 {
			if len(rest) < 1 {
				return false
			}
			l := int(rest[0])
			if l == 0 || len(rest) < 1+l {
				return false
			}
			rest = rest[1+l:]
		}
		return true
	case 51: // key_share：至少一个条目，且每条目长度自洽
		if len(v) < 2 {
			return false
		}
		n := int(v[0])<<8 | int(v[1])
		if n != len(v)-2 || n < 1 {
			return false
		}
		rest := v[2:]
		for len(rest) > 0 {
			if len(rest) < 4 {
				return false
			}
			l := int(rest[2])<<8 | int(rest[3])
			// 密钥长度必须非零：0004 001d 0000 这种「有组但没密钥」是畸形包。
			if l == 0 || len(rest) < 4+l {
				return false
			}
			rest = rest[4+l:]
		}
		return true
	case 0: // server_name：必须恰好一个 host_name，且主机名合法
		if len(v) < 2 {
			return false
		}
		n := int(v[0])<<8 | int(v[1])
		if n != len(v)-2 || n < 1 {
			return false
		}
		rest := v[2:]
		for len(rest) > 0 {
			if len(rest) < 3 {
				return false
			}
			if rest[0] != 0 {
				return false
			}
			l := int(rest[1])<<8 | int(rest[2])
			if len(rest) < 3+l {
				return false
			}
			if !validServerName(string(rest[3 : 3+l])) {
				return false
			}
			rest = rest[3+l:]
		}
		return true
	case 0xfe0d: // encrypted_client_hello
		// 按 draft-ietf-tls-esni 的 ECHClientHello 结构校验：
		//
		//   struct {
		//       ECHClientHelloType type;   // 1 字节
		//       select (type) {
		//           case outer:
		//               HpkeSymmetricCipherSuite cipher_suite;  // 4 字节
		//               uint8 config_id;                        // 1 字节
		//               opaque enc<0..2^16-1>;                  // 2+N
		//               opaque payload<1..2^16-1>;              // 2+N
		//           case inner: Empty;
		//       }
		//   } ECHClientHello;
		//
		// 只验形状，不做密码学校验。**不能要求恰好 1 字节** —— 真实 ECH
		// 扩展有上百字节（enc + payload），那样会把开启 ECH 的合法客户端全部拒掉。
		if len(v) < 1 {
			return false
		}
		switch v[0] {
		case 0: // outer：cipher_suite(4) + config_id(1) + enc + payload
			if len(v) < 1+4+1+2+2 {
				return false
			}
			// 布局：[0]=type [1..4]=cipher_suite [5]=config_id
			//       [6..7]=enc_len [8..]=enc [..]=payload_len [..]=payload
			encLen := int(v[6])<<8 | int(v[7])
			encEnd := 8 + encLen
			if encEnd+2 > len(v) {
				return false
			}
			payLen := int(v[encEnd])<<8 | int(v[encEnd+1])
			if payLen < 1 || encEnd+2+payLen != len(v) {
				return false
			}
			return true
		case 1: // inner：必须为空
			return len(v) == 1
		default:
			return false
		}
	case 23: // extended_master_secret：必须是零长度
		return len(v) == 0
	}
	return true
}

// validServerName 判断 SNI 是否是合法的 DNS 主机名。
//
// 拒绝通配符、空标签、首尾连字符、非法字符——这些在真实浏览器握手里不会出现，
// 却是探测工具常见的特征。
func validServerName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return false
	}
	// IP 字面量不是合法 SNI
	if net.ParseIP(name) != nil {
		return true
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			switch {
			// 下划线在真实 SNI 里会出现（内部主机名），不当成非法。
			case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9',
				ch == '-', ch == '_':
			default:
				return false
			}
		}
	}
	// 顶级域不能是纯数字（那不是域名，是 IP 片段或畸形值）。
	labels := strings.Split(name, ".")
	if tld := labels[len(labels)-1]; tld != "" {
		allDigits := true
		for i := 0; i < len(tld); i++ {
			if tld[i] < '0' || tld[i] > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return false
		}
	}
	return true
}

func setLinger(conn net.Conn, seconds int) error {
	type linger interface {
		SetLinger(int) error
	}
	if conn, ok := conn.(linger); ok {
		return conn.SetLinger(seconds)
	}
	return nil
}