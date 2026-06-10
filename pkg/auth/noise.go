// Ligolo-ng
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package auth implements the Ligolo agent<->server authentication handshake.
//
// It uses the Noise framework's IKpsk2 pattern (the same construction WireGuard
// uses): Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s. This fits a reverse-connecting
// agent perfectly:
//
//   - IK   the agent (initiator) already knows the server's static public key,
//     baked into the agent build, and the server learns the agent's
//     identity in the first message.
//   - psk2 an optional per-deployment pre-shared key mixed in at message two,
//     giving an extra authentication factor and post-quantum hedge.
//
// The handshake provides mutual authentication, forward secrecy and identity
// pinning without any PKI/CA machinery, and is independent of the transport TLS
// (so the same handshake authenticates QUIC, TLS+mux or a plaintext fallback).
// The resulting CipherStates also let the channel encrypt application data, so
// the control plane is confidential even over an untrusted transport.
package auth

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

// cipherSuite is Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s.
var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// maxRecord bounds a single encrypted record. Noise messages are limited to
// 65535 bytes including the 16-byte AEAD tag.
const maxRecord = 65535 - 16

// Identity is a node's long-term static keypair.
type Identity struct {
	keypair noise.DHKey
}

// GenerateIdentity creates a fresh static keypair.
func GenerateIdentity() (Identity, error) {
	kp, err := cipherSuite.GenerateKeypair(rand.Reader)
	if err != nil {
		return Identity{}, err
	}
	return Identity{keypair: kp}, nil
}

// IdentityFromPrivate rebuilds an Identity from a 32-byte X25519 private key,
// deriving the matching public key. This lets the server load a stable identity
// from disk across restarts.
func IdentityFromPrivate(priv []byte) (Identity, error) {
	if len(priv) != 32 {
		return Identity{}, errors.New("auth: private key must be 32 bytes")
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return Identity{}, fmt.Errorf("auth: derive public key: %w", err)
	}
	return Identity{keypair: noise.DHKey{Private: append([]byte(nil), priv...), Public: pub}}, nil
}

// Public returns the static public key.
func (i Identity) Public() []byte { return i.keypair.Public }

// Private returns the static private key. Persist this securely for a stable
// server identity across restarts.
func (i Identity) Private() []byte { return i.keypair.Private }

// PublicHex returns the hex-encoded public key, used for pinning.
func (i Identity) PublicHex() string { return hex.EncodeToString(i.keypair.Public) }

// SecureConn is an authenticated, encrypted stream produced by a successful
// handshake. It satisfies net.Conn by delegating addresses/deadlines to the
// underlying transport stream.
type SecureConn struct {
	raw     net.Conn
	enc     *noise.CipherState
	dec     *noise.CipherState
	peerKey []byte // peer's static public key (for identity/authorization)

	readBuf []byte // leftover plaintext from the last decrypted record
}

// PeerKey returns the authenticated static public key of the remote peer.
func (c *SecureConn) PeerKey() []byte { return c.peerKey }

// PeerKeyHex returns the hex-encoded peer static public key.
func (c *SecureConn) PeerKeyHex() string { return hex.EncodeToString(c.peerKey) }

func (c *SecureConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxRecord {
			chunk = chunk[:maxRecord]
		}
		ct, err := c.enc.Encrypt(nil, nil, chunk)
		if err != nil {
			return written, err
		}
		var hdr [2]byte
		binary.BigEndian.PutUint16(hdr[:], uint16(len(ct)))
		if _, err := c.raw.Write(hdr[:]); err != nil {
			return written, err
		}
		if _, err := c.raw.Write(ct); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (c *SecureConn) Read(p []byte) (int, error) {
	if len(c.readBuf) == 0 {
		var hdr [2]byte
		if _, err := io.ReadFull(c.raw, hdr[:]); err != nil {
			return 0, err
		}
		n := binary.BigEndian.Uint16(hdr[:])
		ct := make([]byte, n)
		if _, err := io.ReadFull(c.raw, ct); err != nil {
			return 0, err
		}
		pt, err := c.dec.Decrypt(nil, nil, ct)
		if err != nil {
			return 0, fmt.Errorf("auth: record decrypt failed: %w", err)
		}
		c.readBuf = pt
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

func (c *SecureConn) Close() error                       { return c.raw.Close() }
func (c *SecureConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *SecureConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *SecureConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *SecureConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *SecureConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

func writeHandshake(conn net.Conn, msg []byte) error {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := conn.Write(msg)
	return err
}

func readHandshake(conn net.Conn) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func newHandshakeConfig(local Identity, psk []byte, initiator bool, serverStatic []byte) noise.Config {
	cfg := noise.Config{
		CipherSuite:   cipherSuite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     initiator,
		StaticKeypair: local.keypair,
	}
	if len(psk) > 0 {
		cfg.PresharedKey = psk
		cfg.PresharedKeyPlacement = 2 // IKpsk2
	}
	if initiator {
		cfg.PeerStatic = serverStatic // IK: initiator knows responder's static key
	}
	return cfg
}

// HandshakeInitiator runs the agent side of the IKpsk2 handshake. serverStatic
// is the pinned server public key; psk is an optional pre-shared key.
func HandshakeInitiator(conn net.Conn, local Identity, serverStatic, psk []byte) (*SecureConn, error) {
	if len(serverStatic) != 32 {
		return nil, errors.New("auth: server static key must be 32 bytes")
	}
	hs, err := noise.NewHandshakeState(newHandshakeConfig(local, psk, true, serverStatic))
	if err != nil {
		return nil, err
	}
	// -> e, es, s, ss
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	if err := writeHandshake(conn, msg1); err != nil {
		return nil, err
	}
	// <- e, ee, se
	in, err := readHandshake(conn)
	if err != nil {
		return nil, err
	}
	_, csOut, csIn, err := hs.ReadMessage(nil, in)
	if err != nil {
		return nil, fmt.Errorf("auth: handshake failed (bad server key or psk?): %w", err)
	}
	if csOut == nil || csIn == nil {
		return nil, errors.New("auth: handshake did not complete")
	}
	return &SecureConn{raw: conn, enc: csOut, dec: csIn, peerKey: serverStatic}, nil
}

// HandshakeResponder runs the server side of the IKpsk2 handshake. It returns
// the SecureConn and the authenticated static public key of the agent so the
// caller can authorize it.
func HandshakeResponder(conn net.Conn, local Identity, psk []byte) (*SecureConn, error) {
	hs, err := noise.NewHandshakeState(newHandshakeConfig(local, psk, false, nil))
	if err != nil {
		return nil, err
	}
	in, err := readHandshake(conn)
	if err != nil {
		return nil, err
	}
	// <- e, es, s, ss
	if _, _, _, err := hs.ReadMessage(nil, in); err != nil {
		return nil, fmt.Errorf("auth: handshake read failed: %w", err)
	}
	// -> e, ee, se
	msg2, csOut, csIn, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	if err := writeHandshake(conn, msg2); err != nil {
		return nil, err
	}
	if csOut == nil || csIn == nil {
		return nil, errors.New("auth: handshake did not complete")
	}
	// flynn/noise always returns the CipherStates in the order
	// (initiator-sends, responder-sends). The responder therefore encrypts with
	// the second state and decrypts with the first.
	return &SecureConn{raw: conn, enc: csIn, dec: csOut, peerKey: hs.PeerStatic()}, nil
}
