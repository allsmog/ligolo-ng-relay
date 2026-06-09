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
	"github.com/nicocha30/ligolo-ng/pkg/transport/wstransport"
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
func runEndToEnd(t *testing.T, ln transport.Listener, dialer transport.Dialer, serverAddr string, serverID, agentID auth.Identity) {
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
		ServerAddr: serverAddr,
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

// freePort returns a currently-free TCP port on loopback.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, p, _ := net.SplitHostPort(l.Addr().String())
	n, _ := strconv.Atoi(p)
	return n
}

func TestReverseListenerQUIC(t *testing.T) {
	serverID, _ := auth.GenerateIdentity()
	agentID, _ := auth.GenerateIdentity()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	echoPort := startEcho(t)
	bindPort := freePort(t)

	ln, err := quictransport.Listen("127.0.0.1:0", serverTLS(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	gotSession := make(chan *session.Session, 1)
	srv := node.NewServer(node.ServerConfig{
		Identity:          serverID,
		HeartbeatInterval: time.Second,
		OnConnect:         func(s *session.Session) { gotSession <- s },
	})
	go srv.Serve(ctx, ln)

	agent := node.NewAgent(node.AgentConfig{Identity: agentID, ServerKey: serverID.Public(), ServerAddr: ln.Addr().String()})
	go agent.Serve(ctx, quictransport.NewDialer(&tls.Config{InsecureSkipVerify: true}))

	var sess *session.Session
	select {
	case sess = <-gotSession:
	case <-ctx.Done():
		t.Fatal("agent never connected")
	}

	bindAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(bindPort))
	toAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(echoPort)))
	rl, err := srv.AddListener(ctx, sess, "tcp", bindAddr, toAddr)
	if err != nil {
		t.Fatalf("AddListener: %v", err)
	}

	// Give the agent a moment to bind, then connect to the agent-side port.
	var conn net.Conn
	for i := 0; i < 50; i++ {
		conn, err = net.Dial("tcp", bindAddr)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial reverse listener: %v", err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("reverse")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 7)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo through reverse listener: %v", err)
	}
	if string(buf) != "reverse" {
		t.Errorf("got %q, want %q", buf, "reverse")
	}
	conn.Close()

	if err := rl.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	// After close the agent-side port should stop accepting.
	time.Sleep(200 * time.Millisecond)
	closed := false
	for i := 0; i < 20; i++ {
		c, derr := net.Dial("tcp", bindAddr)
		if derr != nil {
			closed = true
			break
		}
		c.Close()
		time.Sleep(50 * time.Millisecond)
	}
	if !closed {
		t.Error("reverse listener still accepting after Stop")
	}
}

func TestSessionResumption(t *testing.T) {
	serverID, _ := auth.GenerateIdentity()
	agentID, _ := auth.GenerateIdentity()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	ln, err := quictransport.Listen("127.0.0.1:0", serverTLS(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	connects := make(chan *session.Session, 4)
	srv := node.NewServer(node.ServerConfig{
		Identity:          serverID,
		HeartbeatInterval: 500 * time.Millisecond,
		ResumeGrace:       30 * time.Second,
		OnConnect:         func(s *session.Session) { connects <- s },
	})
	go srv.Serve(ctx, ln)

	agent := node.NewAgent(node.AgentConfig{Identity: agentID, ServerKey: serverID.Public(), ServerAddr: ln.Addr().String()})
	dialer := quictransport.NewDialer(&tls.Config{InsecureSkipVerify: true})

	// First connection.
	runCtx1, stop1 := context.WithCancel(ctx)
	done1 := make(chan struct{})
	go func() { agent.Serve(runCtx1, dialer); close(done1) }()

	var first *session.Session
	select {
	case first = <-connects:
	case <-ctx.Done():
		t.Fatal("agent never connected")
	}

	// Drop the first connection.
	stop1()
	<-done1

	// Reconnect: the agent re-presents its stored session id + resume token.
	go agent.Serve(ctx, dialer)

	select {
	case second := <-connects:
		if second.ID != first.ID {
			t.Errorf("resume produced a new session: first=%s second=%s", first.ID, second.ID)
		}
	case <-ctx.Done():
		t.Fatal("agent never reconnected")
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
	runEndToEnd(t, ln, dialer, ln.Addr().String(), serverID, agentID)
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
	runEndToEnd(t, ln, dialer, ln.Addr().String(), serverID, agentID)
}

func TestEndToEndWebsocket(t *testing.T) {
	serverID, _ := auth.GenerateIdentity()
	agentID, _ := auth.GenerateIdentity()
	ln, err := wstransport.Listen("127.0.0.1:0", nil) // plain ws; Noise still authenticates
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dialer := wstransport.NewDialer(nil)
	runEndToEnd(t, ln, dialer, "ws://"+ln.Addr().String(), serverID, agentID)
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
