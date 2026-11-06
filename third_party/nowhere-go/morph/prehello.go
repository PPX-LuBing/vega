package morph

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"

	"github.com/ohmycggk/nowhere-go/internal/chacha20"
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
// Admission mirrors the configuration-independent rustls 0.23.46 Acceptor
// checks. Cipher/version/ALPN negotiation stays with crypto/tls after admission;
// these configuration-dependent failures are not Silent PreHello failures.
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
		if header[1] != 3 {
			return nil, ErrClientHello
		}
		recordLen := int(binary.BigEndian.Uint16(header[3:5]))
		if header[0] != tlsHandshake || recordLen == 0 || recordLen >= tlsMaxCipher {
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
			if len(handshake) != 4+messageLen || !clientHelloWellFormed(handshake) {
				return nil, ErrClientHello
			}
			return buf, nil
		}
	}
	return nil, ErrClientHello
}

func (c *tcpConn) readPlainUntil(buf []byte, n int) ([]byte, error) {
	for len(buf) < n {
		if err := checkLimit(c.readOff, n-len(buf)); err != nil {
			return nil, err
		}
		next := make([]byte, n-len(buf))
		if _, err := io.ReadFull(c.Conn, next); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				return nil, ErrClientHello
			}
			return nil, err
		}
		chacha20.XORKeyStreamAt(next, next, &c.readKey, &c.nonce, c.readOff)
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
	if compLen < 1 || len(body) < compLen || !bytes.Contains(body[:compLen], []byte{0}) {
		return false
	}
	body = body[compLen:]
	if len(body) == 0 {
		return false
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
		if !validClientExtension(extType, body[:size]) {
			return false
		}
		seen[extType] = struct{}{}
		body = body[size:]
	}
	_, signatures := seen[13]
	return signatures
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

// vec consumes a TLS length-prefixed vector without allocating.
func vec(b *[]byte, width int, nonempty bool) ([]byte, bool) {
	if len(*b) < width {
		return nil, false
	}
	n := int((*b)[0])
	if width == 2 {
		n = int(binary.BigEndian.Uint16(*b))
	}
	*b = (*b)[width:]
	if n > len(*b) || nonempty && n == 0 {
		return nil, false
	}
	v := (*b)[:n]
	*b = (*b)[n:]
	return v, true
}
func validClientExtension(typ uint16, b []byte) bool {
	list := func(width, unit int, nonempty bool) bool {
		v, ok := vec(&b, width, nonempty)
		return ok && len(b) == 0 && len(v)%unit == 0
	}
	switch typ {
	case 0:
		names, ok := vec(&b, 2, false)
		if !ok || len(b) != 0 {
			return false
		}
		found := false
		for len(names) > 0 {
			kind := names[0]
			names = names[1:]
			if kind != 0 {
				break
			}
			name, ok := vec(&names, 2, true)
			if !ok || found || !validServerName(string(name)) {
				return false
			}
			found = true
		}
		return found
	case 10, 13:
		return list(2, 2, true)
	case 11, 19, 20, 45:
		return list(1, 1, true)
	case 27, 43, 0xfd00:
		return list(1, 2, true)
	case 23, 42:
		return len(b) == 0
	case 44:
		return list(2, 1, true)
	case 0xff01:
		return list(1, 1, false)
	case 16:
		names, ok := vec(&b, 2, true)
		if !ok || len(b) != 0 {
			return false
		}
		for len(names) > 0 {
			if _, ok := vec(&names, 1, true); !ok {
				return false
			}
		}
		return true
	case 51, 47:
		entries, ok := vec(&b, 2, false)
		if !ok || len(b) != 0 {
			return false
		}
		for len(entries) > 0 {
			if typ == 51 {
				if len(entries) < 2 {
					return false
				}
				entries = entries[2:]
			}
			if _, ok := vec(&entries, 2, true); !ok {
				return false
			}
		}
		return true
	case 41:
		identities, ok := vec(&b, 2, true)
		if !ok {
			return false
		}
		for len(identities) > 0 {
			if _, ok := vec(&identities, 2, true); !ok || len(identities) < 4 {
				return false
			}
			identities = identities[4:]
		}
		binders, ok := vec(&b, 2, true)
		if !ok || len(b) != 0 {
			return false
		}
		for len(binders) > 0 {
			if _, ok := vec(&binders, 1, true); !ok {
				return false
			}
		}
		return true
	case 5:
		if len(b) == 0 {
			return false
		}
		kind := b[0]
		b = b[1:]
		if kind != 1 {
			return true
		}
		ids, ok := vec(&b, 2, false)
		if !ok {
			return false
		}
		for len(ids) > 0 {
			if _, ok := vec(&ids, 2, false); !ok {
				return false
			}
		}
		_, ok = vec(&b, 2, false)
		return ok && len(b) == 0
	case 58:
		return len(b) == 2
	case 0xfe0d:
		if len(b) == 0 {
			return false
		}
		if b[0] == 1 {
			return len(b) == 1
		}
		if b[0] != 0 || len(b) < 6 {
			return false
		}
		b = b[6:]
		if _, ok := vec(&b, 2, false); !ok {
			return false
		}
		_, ok := vec(&b, 2, true)
		return ok && len(b) == 0
	default:
		return true
	}
}
func validServerName(name string) bool {
	if net.ParseIP(name) != nil {
		return true
	}
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		numeric := true
		for _, c := range []byte(label) {
			if c < '0' || c > '9' {
				numeric = false
			}
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return false
			}
		}
		if i == len(labels)-1 && numeric {
			return false
		}
	}
	return true
}
