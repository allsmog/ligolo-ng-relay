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
	"net"
	"os"
	"strings"
	"sync"

	"github.com/nicocha30/ligolo-ng/pkg/auth"
	"github.com/nicocha30/ligolo-ng/pkg/ngconfig"
	"github.com/nicocha30/ligolo-ng/pkg/node"
	"github.com/nicocha30/ligolo-ng/pkg/operator"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netstack"
	"github.com/nicocha30/ligolo-ng/pkg/session"
	"github.com/nicocha30/ligolo-ng/pkg/tlsutils"
	"github.com/nicocha30/ligolo-ng/pkg/transport"
	"github.com/nicocha30/ligolo-ng/pkg/transport/muxtransport"
	"github.com/nicocha30/ligolo-ng/pkg/transport/quictransport"
	"github.com/nicocha30/ligolo-ng/pkg/transport/wstransport"
	"github.com/nicocha30/ligolo-ng/pkg/webui"
	"github.com/nicocha30/ligolo-ng/pkg/wire"
	"github.com/sirupsen/logrus"
)

func main() {
	listenAddr := flag.String("listen", "quic://0.0.0.0:11601", "listen URL: quic://, tls://, ws:// or wss://host:port")
	tunName := flag.String("tun", "ligolo", "TUN interface name for the userland network stack")
	keyHex := flag.String("key", "", "server static private key (hex); generated if empty")
	pskStr := flag.String("psk", "", "optional pre-shared key (IKpsk2)")
	operatorListen := flag.String("operator-listen", "", "operator hub mTLS listen addr (host:port); empty disables the hub")
	operatorDir := flag.String("operator-config", "ligolo-operator", "directory to write the operator config bundle")
	configPath := flag.String("config", "", "config file for stable identity + autobind (daemon mode); created if missing")
	console := flag.Bool("console", false, "run an interactive console instead of auto-routing agents")
	autoroute := flag.Bool("autoroute", false, "auto-install routes for each agent's advertised networks")
	webListen := flag.String("web-listen", "", "web UI listen addr (host:port); empty disables it")
	webToken := flag.String("web-token", "", "web UI access token; generated if empty")
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}

	// Config-backed daemon mode: a config file gives a stable server identity
	// across restarts and persists per-agent autobind rules.
	var cfg *ngconfig.Config
	if *configPath != "" {
		cfg = loadOrInitConfig(*configPath, *listenAddr, *pskStr, *operatorListen, *operatorDir)
		*listenAddr = cfg.Listen
		*pskStr = cfg.PSK
		if cfg.OperatorListen != "" {
			*operatorListen = cfg.OperatorListen
		}
		if cfg.OperatorConfigDir != "" {
			*operatorDir = cfg.OperatorConfigDir
		}
		*keyHex = cfg.ServerKeyHex
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
	var srv *node.Server

	srv = node.NewServer(node.ServerConfig{
		Identity: identity,
		PSK:      []byte(*pskStr),
		Version:  "ng",
		OnConnect: func(s *session.Session) {
			logrus.Infof("operator view: agent %q (%s) is now available", s.Name, s.ID)
			// Config autobind takes precedence: restore the agent's tunnel and
			// reverse listeners from the saved rule.
			if cfg != nil {
				if rule, ok := cfg.AutobindFor(s.PeerKeyHex); ok {
					applyAutobind(tun, srv, s, rule)
					return
				}
			}
			if !*console {
				// Non-console without a rule: auto-route on its own interface.
				if ifName, err := tun.start(s, ""); err != nil {
					logrus.Errorf("auto-route %s failed (need root + TUN): %v", s.ID, err)
				} else {
					logrus.Infof("routing %s through %s", s.ID, ifName)
					if *autoroute {
						applyAutoroute(ifName, s)
					}
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

	if *webListen != "" {
		web := webui.New(newWebController(srv, tun), *webToken)
		go func() {
			if err := web.Serve(*webListen, "", ""); err != nil {
				logrus.Errorf("web UI: %v", err)
			}
		}()
		logrus.Infof("web UI on http://%s  (token: %s)", *webListen, web.Token())
	}

	logrus.Infof("assign the tunnel an address and route, e.g.: sudo ip addr add 240.0.0.1/4 dev %s && sudo ip link set %s up", *tunName, *tunName)

	go func() {
		if err := srv.Serve(ctx, ln); err != nil && ctx.Err() == nil {
			logrus.Fatalf("serve: %v", err)
		}
	}()

	if *console {
		runConsole(srv, tun, cfg)
		return
	}
	logrus.Info("running headless; agents auto-route via OnConnect / autobind")
	select {} // block forever
}

// loadOrInitConfig loads the config at path, or creates one (generating a stable
// server key) seeded from the CLI flags.
func loadOrInitConfig(path, listen, psk, operatorListen, operatorDir string) *ngconfig.Config {
	if ngconfig.Exists(path) {
		cfg, err := ngconfig.Load(path)
		if err != nil {
			logrus.Fatalf("load config %s: %v", path, err)
		}
		logrus.Infof("loaded config from %s", path)
		return cfg
	}
	id, err := auth.GenerateIdentity()
	if err != nil {
		logrus.Fatalf("generate identity: %v", err)
	}
	cfg := ngconfig.New(path)
	cfg.Listen = listen
	cfg.PSK = psk
	cfg.OperatorListen = operatorListen
	cfg.OperatorConfigDir = operatorDir
	cfg.ServerKeyHex = hex.EncodeToString(id.Private())
	if err := cfg.Save(); err != nil {
		logrus.Fatalf("write config %s: %v", path, err)
	}
	logrus.Infof("created config %s with a fresh server identity", path)
	return cfg
}

// applyAutobind restores an agent's tunnel, autoroutes and reverse listeners
// from a saved rule when the agent reconnects.
func applyAutobind(tun *tunnelManager, srv *node.Server, s *session.Session, rule ngconfig.Autobind) {
	if rule.Route {
		ifName, err := tun.start(s, rule.Interface)
		if err != nil {
			logrus.Errorf("autobind route %s failed: %v", s.ID, err)
		} else {
			logrus.Infof("autobind: routing %s through %s", s.Name, ifName)
			if rule.AutoRoute {
				applyAutoroute(ifName, s)
			}
		}
	}
	for _, l := range rule.Listeners {
		if _, err := srv.AddListener(context.Background(), s, l.Network, l.Bind, l.To); err != nil {
			logrus.Errorf("autobind listener %s->%s failed: %v", l.Bind, l.To, err)
		} else {
			logrus.Infof("autobind: listener %s/%s -> %s on %s", l.Bind, l.Network, l.To, s.Name)
		}
	}
}

// applyAutoroute installs routes for the agent's advertised networks via ifName,
// so the operator can reach those networks without manual `ip route` commands.
func applyAutoroute(ifName string, s *session.Session) []string {
	var added []string
	for _, subnet := range agentSubnets(s.Interfaces) {
		if err := addRoute(ifName, subnet); err != nil {
			logrus.Debugf("autoroute %s via %s: %v", subnet, ifName, err)
			continue
		}
		added = append(added, subnet)
		logrus.Infof("autoroute: %s via %s", subnet, ifName)
	}
	return added
}

// agentSubnets derives routable network CIDRs from an agent's interface
// addresses, skipping loopback and link-local ranges.
func agentSubnets(ifaces []wire.NetInterface) []string {
	var out []string
	seen := map[string]bool{}
	for _, iface := range ifaces {
		for _, addr := range iface.Addresses {
			ip, ipnet, err := net.ParseCIDR(addr)
			if err != nil {
				continue
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
				continue
			}
			cidr := ipnet.String()
			if !seen[cidr] {
				seen[cidr] = true
				out = append(out, cidr)
			}
		}
	}
	return out
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
	// Create the TUN interface before the gVisor stack opens it (Linux opens an
	// existing device by name; other platforms create it in tun.New).
	if err := createTUN(ifName); err != nil {
		return "", fmt.Errorf("create interface %s: %w", ifName, err)
	}
	ns, err := netstack.NewStack(netstack.StackSettings{TunName: ifName, MaxInflight: 4096}, nil)
	if err != nil {
		deleteTUN(ifName)
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
	deleteTUN(at.ifName)
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
