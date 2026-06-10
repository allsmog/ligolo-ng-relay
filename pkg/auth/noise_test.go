package auth

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// handshakePair runs initiator and responder concurrently over a net.Pipe and
// returns both secured connections.
func handshakePair(t *testing.T, serverKey, agentKey Identity, agentPSK, serverPSK []byte) (*SecureConn, *SecureConn, error) {
	t.Helper()
	c1, c2 := net.Pipe()

	type res struct {
		conn *SecureConn
		err  error
	}
	srvCh := make(chan res, 1)
	go func() {
		conn, err := HandshakeResponder(c2, serverKey, serverPSK)
		srvCh <- res{conn, err}
	}()

	agentConn, agentErr := HandshakeInitiator(c1, agentKey, serverKey.Public(), agentPSK)
	srvRes := <-srvCh
	if agentErr != nil {
		return nil, nil, agentErr
	}
	if srvRes.err != nil {
		return nil, nil, srvRes.err
	}
	return agentConn, srvRes.conn, nil
}

func TestNoiseHandshakeAndEncryption(t *testing.T) {
	serverKey, _ := GenerateIdentity()
	agentKey, _ := GenerateIdentity()
	psk := []byte("a-shared-secret-of-some-length!!")

	agentConn, srvConn, err := handshakePair(t, serverKey, agentKey, psk, psk)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	// The server learns the agent's authenticated static key.
	if !bytes.Equal(srvConn.PeerKey(), agentKey.Public()) {
		t.Error("server did not learn the correct agent public key")
	}
	// The agent's peer key is the (pinned) server key.
	if !bytes.Equal(agentConn.PeerKey(), serverKey.Public()) {
		t.Error("agent peer key mismatch")
	}

	// Encrypted data round-trips both directions.
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 5)
		_, err := readFull(srvConn, buf)
		if err != nil {
			done <- err
			return
		}
		_, err = srvConn.Write([]byte("world"))
		done <- err
	}()

	if _, err := agentConn.Write([]byte("hello")); err != nil {
		t.Fatalf("agent write: %v", err)
	}
	reply := make([]byte, 5)
	if _, err := readFull(agentConn, reply); err != nil {
		t.Fatalf("agent read: %v", err)
	}
	if string(reply) != "world" {
		t.Errorf("got %q, want %q", reply, "world")
	}
	if err := <-done; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

func TestNoiseRejectsWrongPSK(t *testing.T) {
	serverKey, _ := GenerateIdentity()
	agentKey, _ := GenerateIdentity()
	_, _, err := handshakePair(t, serverKey, agentKey,
		[]byte("client-psk-which-is-32-bytes!!!!"),
		[]byte("server-psk-which-is-32-bytes!!!!"))
	if err == nil {
		t.Fatal("expected handshake to fail with mismatched PSK")
	}
}

func TestIdentityFromPrivateDerivesPublic(t *testing.T) {
	id, _ := GenerateIdentity()
	restored, err := IdentityFromPrivate(id.Private())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored.Public(), id.Public()) {
		t.Error("derived public key does not match original")
	}
}

// readFull reads len(buf) bytes, retrying short reads (the SecureConn returns
// per-record chunks).
func readFull(c *SecureConn, buf []byte) (int, error) {
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
