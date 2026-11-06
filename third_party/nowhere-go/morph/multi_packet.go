package morph

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// Multi-key UDP admission has no new wire bytes. An Initial or a host-validated
// server CID selects the key; QUIC AEAD and AuthFrame still authenticate peers.
// The bounded address map is only used for reply masking, not authentication.
func WrapPacketConnMulti(pc net.PacketConn, keys func() []Keys, validCID func([]byte) bool) net.PacketConn {
	return &multiPacketConn{PacketConn: pc, keys: keys, peers: make(map[string]udpPeer), validCID: validCID}
}

type udpPeer struct {
	key  Keys
	seen time.Time
}
type multiPacketConn struct {
	net.PacketConn
	keys     func() []Keys
	validCID func([]byte) bool
	mu       sync.Mutex
	peers    map[string]udpPeer
}

func (c *multiPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, len(p)+nonceLen)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if n <= nonceLen {
			continue
		}
		now := time.Now()
		c.mu.Lock()
		peer, known := c.peers[addr.String()]
		c.mu.Unlock()
		keys := c.keys()
		// Existing sessions may drain after revocation. New connections still
		// authenticate against current users, never this reply-masking cache.
		if known && now.Sub(peer.seen) < 10*time.Minute {
			present := false
			for _, key := range keys {
				if key.UDPC2S == peer.key.UDPC2S {
					present = true
					break
				}
			}
			if !present {
				keys = append(keys, peer.key)
			}
		}
		for _, key := range keys {
			copyBuf := append([]byte(nil), buf[:n]...)
			size, ok := unmaskDatagram(p, copyBuf, &key.UDPC2S, true)
			if !ok || !c.validPacket(p[:size]) {
				continue
			}
			c.mu.Lock()
			for source, peer := range c.peers {
				if now.Sub(peer.seen) >= 10*time.Minute {
					delete(c.peers, source)
				}
			}
			if len(c.peers) >= 4096 && !known {
				c.mu.Unlock()
				break
			}
			c.peers[addr.String()] = udpPeer{key, now}
			c.mu.Unlock()
			return size, addr, nil
		}
	}
}
func (c *multiPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	peer, ok := c.peers[addr.String()]
	c.mu.Unlock()
	if !ok {
		return 0, &net.AddrError{Err: "unknown Morph peer", Addr: addr.String()}
	}
	return writeMasked(c.PacketConn, p, addr, &peer.key.UDPS2C)
}

// CIDs are opaque QUIC routing identifiers, not a Nowhere wire extension.
// A self-authenticating server CID lets us recognize a short header after NAT
// rebinding without guessing a key from unauthenticated random header bits.
func (c *multiPacketConn) validPacket(p []byte) bool {
	if len(p) < 17 || p[0]&0x40 == 0 {
		return false
	}
	if p[0]&0x80 == 0 {
		return c.validCID != nil && c.validCID(p[1:17])
	}
	if len(p) < 7 || binary.BigEndian.Uint32(p[1:5]) != 1 {
		return false
	}
	n := int(p[5])
	if n < 8 || n > 20 || len(p) < 7+n {
		return false
	}
	if p[0]&0x30 == 0 && len(p) >= 1200 {
		return p[6+n] <= 20 && len(p) >= 7+n+int(p[6+n])
	}
	return n == 16 && c.validCID != nil && c.validCID(p[6:22])
}
