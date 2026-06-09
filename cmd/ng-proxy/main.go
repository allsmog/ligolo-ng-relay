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

// Command ng-proxy is the server/relay for the refactored Ligolo architecture.
//
// It demonstrates the full stack end to end: a pluggable transport listener
// (QUIC by default, TLS+mux fallback), Noise-authenticated sessions, and a
// gVisor userland network stack bound to a TUN interface. Transport TLS uses an
// ephemeral self-signed certificate on purpose — the real mutual authentication
// and server-key pinning come from the Noise IKpsk2 handshake, so the throwaway
// cert needs no PKI.
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/nicocha30/ligolo-ng/pkg/auth"
	"github.com/nicocha30/ligolo-ng/pkg/node"
	"github.com/nicocha30/ligolo-ng/pkg/operator"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netstack"
	"github.com/nicocha30/ligolo-ng/pkg/session"
	"github.com/nicocha30/ligolo-ng/pkg/tlsutils"
	"github.com/nicocha30/ligolo-ng/pkg/transport"
	"github.com/nicocha30/ligolo-ng/pkg/transport/muxtransport"
	"github.com/nicocha30/ligolo-ng/pkg/transport/quictransport"
	"github.com/nicocha30/ligolo-ng/pkg/transport/wstransport"
	"github.com/sirupsen/logrus"
)

func main() {
	listenAddr := flag.String("listen", "quic://0.0.0.0:11601", "listen URL: quic://, tls://, ws:// or wss://host:port")
	tunName := flag.String("tun", "ligolo", "TUN interface name for the userland network stack")
	keyHex := flag.String("key", "", "server static private key (hex); generated if empty")
	pskStr := flag.String("psk", "", "optional pre-shared key (IKpsk2)")
	operatorListen := flag.String("operator-listen", "", "operator hub mTLS listen addr (host:port); empty disables the hub")
	operatorDir := flag.String("operator-config", "ligolo-operator", "directory to write the operator config bundle")
	console := flag.Bool("console", false, "run an interactive console instead of auto-routing the first agent")
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	identity := loadOrGenerateIdentity(*keyHex)
	logrus.Infof("server static public key (pin this in the agent): %s", identity.PublicHex())

	scheme, host := splitURL(*listenAddr)

	// Ephemeral self-signed transport certificate; security is from Noise.
	tlsConfig := selfSignedTLS()

	var ln transport.Listener
	var err error
	switch scheme {
	case "quic":
		ln, err = quictransport.Listen(host, tlsConfig)
	case "tls":
		ln, err = muxtransport.Listen(host, tlsConfig)
	case "ws":
		ln, err = wstransport.Listen(host, nil)
	case "wss":
		ln, err = wstransport.Listen(host, tlsConfig)
	default:
		logrus.Fatalf("unknown transport scheme %q (use quic://, tls://, ws:// or wss://)", scheme)
	}
	if err != nil {
		logrus.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ctx := context.Background()
	var tun *tunnelManager

	srv := node.NewServer(node.ServerConfig{
		Identity: identity,
		PSK:      []byte(*pskStr),
		Version:  "ng",
		OnConnect: func(s *session.Session) {
			logrus.Infof("operator view: agent %q (%s) is now available", s.Name, s.ID)
			if !*console {
				// Non-console: auto-route each agent on its own interface.
				if ifName, err := tun.start(s, ""); err != nil {
					logrus.Errorf("auto-route %s failed (need root + TUN): %v", s.ID, err)
				} else {
					logrus.Infof("routing %s through %s", s.ID, ifName)
				}
			}
		},
		OnDisconnect: func(s *session.Session) {
			logrus.Infof("operator view: agent %q (%s) disconnected", s.Name, s.ID)
			tun.stop(s.ID)
		},
	})
	tun = newTunnelManager(srv, *tunName)

	if *operatorListen != "" {
		startOperatorHub(ctx, srv, *operatorListen, *operatorDir)
	}

	logrus.Infof("assign the tunnel an address and route, e.g.: sudo ip addr add 240.0.0.1/4 dev %s && sudo ip link set %s up", *tunName, *tunName)

	go func() {
		if err := srv.Serve(ctx, ln); err != nil && ctx.Err() == nil {
			logrus.Fatalf("serve: %v", err)
		}
	}()

	if *console {
		runConsole(srv, tun)
		return
	}
	select {} // block forever; agents auto-route via OnConnect
}

// startOperatorHub provisions an operator PKI, writes an operator config bundle
// and serves the multi-operator hub over mutual TLS.
func startOperatorHub(ctx context.Context, srv *node.Server, addr, configDir string) {
	ca, err := operator.NewCA()
	if err != nil {
		logrus.Fatalf("operator CA: %v", err)
	}
	serverCert, err := ca.IssueServer(operator.ServerName())
	if err != nil {
		logrus.Fatalf("operator server cert: %v", err)
	}
	if err := operator.WriteOperatorBundle(ca, configDir, "admin"); err != nil {
		logrus.Fatalf("write operator bundle: %v", err)
	}
	hubLn, err := tls.Listen("tcp", addr, ca.HubTLSConfig(serverCert))
	if err != nil {
		logrus.Fatalf("operator listen: %v", err)
	}
	hub := operator.NewHub(srv)
	go func() {
		if err := hub.Serve(ctx, hubLn); err != nil && ctx.Err() == nil {
			logrus.Errorf("operator hub: %v", err)
		}
	}()
	logrus.Infof("operator hub listening on %s; operator bundle written to %s/", addr, configDir)
}

// agentTunnel is one routed agent: its own gVisor stack bound to its own TUN
// interface, fed by its own connection pool.
type agentTunnel struct {
	ifName string
	sess   *session.Session
	stack  *netstack.NetStack
	pool   *netstack.ConnPool
}

// tunnelManager routes any number of agents simultaneously, each through a
// distinct TUN interface and gVisor stack. This replaces the earlier single
// active-tunnel model and matches the legacy "one interface per tunnel" design.
type tunnelManager struct {
	srv         *node.Server
	defaultName string

	mu      sync.Mutex
	tunnels map[string]*agentTunnel // sessionID -> tunnel
}

func newTunnelManager(srv *node.Server, defaultName string) *tunnelManager {
	return &tunnelManager{srv: srv, defaultName: defaultName, tunnels: make(map[string]*agentTunnel)}
}

// start routes an agent through its own TUN interface; ifName=="" auto-allocates
// the next free name (ligolo, ligolo1, ...). Returns the interface name.
func (m *tunnelManager) start(s *session.Session, ifName string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if at, ok := m.tunnels[s.ID]; ok {
		return at.ifName, nil // already routed
	}
	if ifName == "" {
		ifName = m.allocNameLocked()
	} else if m.nameInUseLocked(ifName) {
		return "", fmt.Errorf("interface %s is already in use", ifName)
	}
	ns, err := netstack.NewStack(netstack.StackSettings{TunName: ifName, MaxInflight: 4096}, nil)
	if err != nil {
		return "", err
	}
	pool := netstack.NewConnPool(4096)
	ns.SetConnPool(&pool)
	at := &agentTunnel{ifName: ifName, sess: s, stack: ns, pool: &pool}
	m.tunnels[s.ID] = at
	go m.run(at)
	return ifName, nil
}

func (m *tunnelManager) run(at *agentTunnel) {
	for {
		tc, err := at.pool.Get()
		if err != nil {
			return
		}
		go node.HandlePacket(m.srv, at.sess, at.stack.GetStack(), tc)
	}
}

// stop tears down an agent's tunnel and removes its TUN interface.
func (m *tunnelManager) stop(sessionID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	at, ok := m.tunnels[sessionID]
	if !ok {
		return false
	}
	at.pool.Close()
	at.stack.Close()
	delete(m.tunnels, sessionID)
	return true
}

func (m *tunnelManager) ifNameFor(sessionID string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if at, ok := m.tunnels[sessionID]; ok {
		return at.ifName
	}
	return ""
}

func (m *tunnelManager) list() []*agentTunnel {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*agentTunnel, 0, len(m.tunnels))
	for _, at := range m.tunnels {
		out = append(out, at)
	}
	return out
}

func (m *tunnelManager) allocNameLocked() string {
	for i := 0; ; i++ {
		name := m.defaultName
		if i > 0 {
			name = fmt.Sprintf("%s%d", m.defaultName, i)
		}
		if !m.nameInUseLocked(name) {
			return name
		}
	}
}

func (m *tunnelManager) nameInUseLocked(name string) bool {
	for _, at := range m.tunnels {
		if at.ifName == name {
			return true
		}
	}
	return false
}

func loadOrGenerateIdentity(keyHex string) auth.Identity {
	if keyHex != "" {
		raw, err := hex.DecodeString(keyHex)
		if err != nil {
			logrus.Fatalf("invalid -key hex: %v", err)
		}
		id, err := auth.IdentityFromPrivate(raw)
		if err != nil {
			logrus.Fatalf("invalid server key: %v", err)
		}
		return id
	}
	id, err := auth.GenerateIdentity()
	if err != nil {
		logrus.Fatalf("generate identity: %v", err)
	}
	logrus.Warnf("no -key given; generated an ephemeral server key (private: %s)", hex.EncodeToString(id.Private()))
	return id
}

func selfSignedTLS() *tls.Config {
	sc := tlsutils.NewSelfCert(nil)
	crt, err := sc.GetCertificate("ligolo")
	if err != nil {
		logrus.Fatalf("self-signed cert: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{*crt}}
}

func splitURL(u string) (scheme, host string) {
	if i := strings.Index(u, "://"); i >= 0 {
		return u[:i], u[i+3:]
	}
	if _, err := os.Stat(u); err == nil {
		return "tls", u
	}
	return "quic", u
}
