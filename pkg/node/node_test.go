package node_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/nicocha30/ligolo-ng/pkg/auth"
	"github.com/nicocha30/ligolo-ng/pkg/node"
	"github.com/nicocha30/ligolo-ng/pkg/session"
	"github.com/nicocha30/ligolo-ng/pkg/tlsutils"
	"github.com/nicocha30/ligolo-ng/pkg/transport"
	"github.com/nicocha30/ligolo-ng/pkg/transport/muxtransport"
	"github.com/nicocha30/ligolo-ng/pkg/transport/quictransport"
	"github.com/nicocha30/ligolo-ng/pkg/wire"
)

// startEcho starts a TCP echo server and returns its port.
func startEcho(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(c, c); c.Close() }(c)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(portStr)
	return uint16(p)
}

func serverTLS(t *testing.T) *tls.Config {
	t.Helper()
	crt, err := tlsutils.NewSelfCert(nil).GetCertificate("ligolo-test")
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{*crt}}
}

// runEndToEnd exercises agent<->server over the given transport: handshake,
// capability negotiation, then a server-driven connect relayed to an echo
// target.
func runEndToEnd(t *testing.T, ln transport.Listener, dialer transport.Dialer, serverID, agentID auth.Identity) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	echoPort := startEcho(t)

	gotSession := make(chan *session.Session, 1)
	srv := node.NewServer(node.ServerConfig{
		Identity:          serverID,
		Version:           "test",
		HeartbeatInterval: time.Second,
		OnConnect:         func(s *session.Session) { gotSession <- s },
	})
	go srv.Serve(ctx, ln)

	agent := node.NewAgent(node.AgentConfig{
		Identity:   agentID,
		ServerKey:  serverID.Public(),
		Version:    "test",
		ServerAddr: ln.Addr().String(),
	})
	go agent.Serve(ctx, dialer)

	var sess *session.Session
	select {
	case sess = <-gotSession:
	case <-ctx.Done():
		t.Fatal("agent never connected")
	}

	if sess.Name == "" {
		t.Error("hello did not populate session name")
	}
	if !wire.Has(sess.Caps, wire.CapTCP) {
		t.Errorf("expected negotiated CapTCP, got %#x", sess.Caps)
	}

	stream, reset, err := srv.OpenConnect(ctx, sess, wire.ConnectRequest{
		Net:       wire.NetworkV4,
		Transport: wire.TransportTCP,
		Address:   "127.0.0.1",
		Port:      echoPort,
	})
	if err != nil {
		t.Fatalf("OpenConnect failed (reset=%v): %v", reset, err)
	}
	defer stream.Close()

	stream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := stream.Write([]byte("ligolo")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 6)
	if _, err := io.ReadFull(stream, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ligolo" {
		t.Errorf("echo mismatch: got %q", buf)
	}
}

func TestEndToEndQUIC(t *testing.T) {
	serverID, _ := auth.GenerateIdentity()
	agentID, _ := auth.GenerateIdentity()
	ln, err := quictransport.Listen("127.0.0.1:0", serverTLS(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dialer := quictransport.NewDialer(&tls.Config{InsecureSkipVerify: true})
	runEndToEnd(t, ln, dialer, serverID, agentID)
}

func TestEndToEndTLSMux(t *testing.T) {
	serverID, _ := auth.GenerateIdentity()
	agentID, _ := auth.GenerateIdentity()
	ln, err := muxtransport.Listen("127.0.0.1:0", serverTLS(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dialer := muxtransport.NewDialer(&tls.Config{InsecureSkipVerify: true})
	runEndToEnd(t, ln, dialer, serverID, agentID)
}

func TestRejectWrongServerKey(t *testing.T) {
	serverID, _ := auth.GenerateIdentity()
	wrongID, _ := auth.GenerateIdentity()
	agentID, _ := auth.GenerateIdentity()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	ln, err := quictransport.Listen("127.0.0.1:0", serverTLS(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	connected := make(chan *session.Session, 1)
	srv := node.NewServer(node.ServerConfig{Identity: serverID, OnConnect: func(s *session.Session) { connected <- s }})
	go srv.Serve(ctx, ln)

	// Agent pins the WRONG server key; the Noise handshake must fail.
	agent := node.NewAgent(node.AgentConfig{
		Identity:   agentID,
		ServerKey:  wrongID.Public(),
		ServerAddr: ln.Addr().String(),
	})
	errCh := make(chan error, 1)
	go func() { errCh <- agent.Serve(ctx, quictransport.NewDialer(&tls.Config{InsecureSkipVerify: true})) }()

	select {
	case <-connected:
		t.Fatal("server accepted an agent that pinned the wrong key")
	case err := <-errCh:
		if err == nil {
			t.Fatal("agent.Serve returned nil; expected handshake failure")
		}
	case <-time.After(6 * time.Second):
		// Acceptable: both sides hung up without a successful session.
	}
}
