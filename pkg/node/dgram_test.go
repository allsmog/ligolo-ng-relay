package node

// Internal test for the UDP-over-QUIC-datagram data path. It lives in package
// node so it can reach the unexported datagram hub.

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/nicocha30/ligolo-ng/pkg/auth"
	"github.com/nicocha30/ligolo-ng/pkg/session"
	"github.com/nicocha30/ligolo-ng/pkg/tlsutils"
	"github.com/nicocha30/ligolo-ng/pkg/transport/quictransport"
	"github.com/nicocha30/ligolo-ng/pkg/wire"
)

func udpEchoPort(t *testing.T) uint16 {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], addr)
		}
	}()
	_, p, _ := net.SplitHostPort(pc.LocalAddr().String())
	n, _ := strconv.Atoi(p)
	return uint16(n)
}

func selfCert(t *testing.T) *tls.Config {
	t.Helper()
	crt, err := tlsutils.NewSelfCert(nil).GetCertificate("dg")
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{*crt}}
}

func TestUDPDatagramFlow(t *testing.T) {
	serverID, _ := auth.GenerateIdentity()
	agentID, _ := auth.GenerateIdentity()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	echoPort := udpEchoPort(t)

	ln, err := quictransport.Listen("127.0.0.1:0", selfCert(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	gotSession := make(chan *session.Session, 1)
	srv := NewServer(ServerConfig{
		Identity:          serverID,
		HeartbeatInterval: time.Second,
		OnConnect:         func(s *session.Session) { gotSession <- s },
	})
	go srv.Serve(ctx, ln)

	agent := NewAgent(AgentConfig{Identity: agentID, ServerKey: serverID.Public(), ServerAddr: ln.Addr().String()})
	go agent.Serve(ctx, quictransport.NewDialer(&tls.Config{InsecureSkipVerify: true}))

	var sess *session.Session
	select {
	case sess = <-gotSession:
	case <-ctx.Done():
		t.Fatal("agent never connected")
	}

	if !wire.Has(sess.Caps, wire.CapDatagramUDP) {
		t.Fatalf("CapDatagramUDP not negotiated; caps=%#x", sess.Caps)
	}

	// Wait for the server-side datagram hub to come up.
	var hub *dgramHub
	for i := 0; i < 100 && hub == nil; i++ {
		hub = srv.dgramHubFor(sess.ID)
		time.Sleep(20 * time.Millisecond)
	}
	if hub == nil {
		t.Fatal("datagram hub never created")
	}

	setup, fc, _, err := srv.OpenDatagramFlow(ctx, sess, hub, wire.ConnectRequest{
		Net:       wire.NetworkV4,
		Transport: wire.TransportUDP,
		Address:   "127.0.0.1",
		Port:      echoPort,
	})
	if err != nil {
		t.Fatalf("OpenDatagramFlow: %v", err)
	}
	defer setup.Close()
	defer fc.Close()

	fc.SetReadDeadline(time.Now().Add(2 * time.Second))
	for i := 0; i < 5; i++ { // datagrams are lossy; retry
		if _, err := fc.Write([]byte("dgram-udp")); err != nil {
			t.Fatalf("write datagram: %v", err)
		}
		buf := make([]byte, 64)
		n, err := fc.Read(buf)
		if err == nil && string(buf[:n]) == "dgram-udp" {
			return // success
		}
		fc.SetReadDeadline(time.Now().Add(2 * time.Second))
	}
	t.Fatal("did not receive echoed datagram")
}
