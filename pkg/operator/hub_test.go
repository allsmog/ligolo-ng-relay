package operator_test

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/nicocha30/ligolo-ng/pkg/auth"
	"github.com/nicocha30/ligolo-ng/pkg/node"
	"github.com/nicocha30/ligolo-ng/pkg/operator"
	"github.com/nicocha30/ligolo-ng/pkg/session"
	"github.com/nicocha30/ligolo-ng/pkg/tlsutils"
	"github.com/nicocha30/ligolo-ng/pkg/transport/quictransport"
)

// startStack brings up a node.Server with a connected agent over QUIC and an
// operator Hub over mTLS, returning the hub address, CA and a cleanup.
func startStack(t *testing.T) (hubAddr string, ca *operator.CA, srv *node.Server, cancel context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())

	serverID, _ := auth.GenerateIdentity()
	agentID, _ := auth.GenerateIdentity()

	crt, err := tlsutils.NewSelfCert(nil).GetCertificate("ligolo-test")
	if err != nil {
		t.Fatal(err)
	}
	agentLn, err := quictransport.Listen("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*crt}})
	if err != nil {
		t.Fatal(err)
	}

	online := make(chan *session.Session, 1)
	srv = node.NewServer(node.ServerConfig{
		Identity:          serverID,
		HeartbeatInterval: 500 * time.Millisecond,
		OnConnect:         func(s *session.Session) { online <- s },
	})
	go srv.Serve(ctx, agentLn)

	agent := node.NewAgent(node.AgentConfig{Identity: agentID, ServerKey: serverID.Public(), ServerAddr: agentLn.Addr().String()})
	go agent.Serve(ctx, quictransport.NewDialer(&tls.Config{InsecureSkipVerify: true}))

	select {
	case <-online:
	case <-time.After(10 * time.Second):
		cancel()
		t.Fatal("agent never connected")
	}

	// Operator hub over mTLS.
	ca, err = operator.NewCA()
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := ca.IssueServer("ligolo-hub")
	if err != nil {
		t.Fatal(err)
	}
	hubLn, err := tls.Listen("tcp", "127.0.0.1:0", ca.HubTLSConfig(serverCert))
	if err != nil {
		t.Fatal(err)
	}
	hub := operator.NewHub(srv)
	go hub.Serve(ctx, hubLn)

	t.Cleanup(func() { cancel(); agentLn.Close(); hubLn.Close() })
	return hubLn.Addr().String(), ca, srv, cancel
}

func operatorClientTLS(t *testing.T, ca *operator.CA, name string) *tls.Config {
	t.Helper()
	cert, err := ca.IssueOperator(name)
	if err != nil {
		t.Fatal(err)
	}
	return ca.ClientTLSConfig(cert, "ligolo-hub")
}

func TestHubListAgentsAndAddListener(t *testing.T) {
	hubAddr, ca, _, _ := startStack(t)

	cli, err := operator.Dial(hubAddr, operatorClientTLS(t, ca, "alice"))
	if err != nil {
		t.Fatalf("operator dial: %v", err)
	}
	defer cli.Close()

	agents, err := cli.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent, got %d", len(agents))
	}
	if !agents[0].Online {
		t.Error("agent should be online")
	}
	agentID := agents[0].ID

	// Add a reverse listener through the operator API.
	bindAddr := freeAddr(t)
	listenerID, err := cli.AddListener(agentID, "tcp", bindAddr, "127.0.0.1:9")
	if err != nil {
		t.Fatalf("AddListener: %v", err)
	}

	// It should now show up in the agent's listener list.
	agents, _ = cli.ListAgents()
	if len(agents[0].Listeners) != 1 || agents[0].Listeners[0].ID != listenerID {
		t.Errorf("listener not reflected in agent info: %+v", agents[0].Listeners)
	}

	if err := cli.StopListener(agentID, listenerID); err != nil {
		t.Fatalf("StopListener: %v", err)
	}
}

func TestHubEventStream(t *testing.T) {
	hubAddr, ca, srv, _ := startStack(t)

	events, stop, err := operator.Subscribe(hubAddr, operatorClientTLS(t, ca, "bob"))
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer stop()

	// Allow the hub to register the subscription before we trigger an event.
	time.Sleep(300 * time.Millisecond)

	// Drop the agent's transport to trigger a disconnect event.
	agents := srv.Registry.List()
	if len(agents) != 1 {
		t.Fatalf("expected 1 agent")
	}
	agents[0].Transport().Close()

	select {
	case ev := <-events:
		if ev.Kind != "disconnect" {
			t.Errorf("expected disconnect event, got %q", ev.Kind)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no disconnect event received")
	}
}

func TestHubRejectsUnauthenticatedOperator(t *testing.T) {
	hubAddr, _, _, _ := startStack(t)

	// No client certificate: the mTLS handshake must fail.
	conn, err := tls.Dial("tcp", hubAddr, &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		// Some stacks defer the error to the first read.
		c := operator.NewCodec(conn)
		err = c.Encode(operator.ListAgentsRequest{})
		if err == nil {
			err = c.Decode()
		}
		conn.Close()
	}
	if err == nil {
		t.Fatal("hub accepted an operator with no client certificate")
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}
