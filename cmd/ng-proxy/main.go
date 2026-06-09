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
	"os"
	"strings"
	"sync"

	"github.com/nicocha30/ligolo-ng/pkg/auth"
	"github.com/nicocha30/ligolo-ng/pkg/node"
	"github.com/nicocha30/ligolo-ng/pkg/proxy/netstack"
	"github.com/nicocha30/ligolo-ng/pkg/session"
	"github.com/nicocha30/ligolo-ng/pkg/tlsutils"
	"github.com/nicocha30/ligolo-ng/pkg/transport"
	"github.com/nicocha30/ligolo-ng/pkg/transport/muxtransport"
	"github.com/nicocha30/ligolo-ng/pkg/transport/quictransport"
	"github.com/sirupsen/logrus"
)

func main() {
	listenAddr := flag.String("listen", "quic://0.0.0.0:11601", "listen URL: quic://host:port or tls://host:port")
	tunName := flag.String("tun", "ligolo", "TUN interface name for the userland network stack")
	keyHex := flag.String("key", "", "server static private key (hex); generated if empty")
	pskStr := flag.String("psk", "", "optional pre-shared key (IKpsk2)")
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
	default:
		logrus.Fatalf("unknown transport scheme %q (use quic:// or tls://)", scheme)
	}
	if err != nil {
		logrus.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	tun := &tunnel{tunName: *tunName}

	srv := node.NewServer(node.ServerConfig{
		Identity: identity,
		PSK:      []byte(*pskStr),
		Version:  "ng",
		OnConnect: func(s *session.Session) {
			logrus.Infof("operator view: agent %q (%s) is now available", s.Name, s.ID)
			tun.attach(s)
		},
		OnDisconnect: func(s *session.Session) {
			logrus.Infof("operator view: agent %q (%s) disconnected", s.Name, s.ID)
			tun.detach(s)
		},
	})
	tun.srv = srv

	logrus.Infof("assign the tunnel an address and route, e.g.: sudo ip addr add 240.0.0.1/4 dev %s && sudo ip link set %s up", *tunName, *tunName)
	if err := srv.Serve(context.Background(), ln); err != nil {
		logrus.Fatalf("serve: %v", err)
	}
}

// tunnel lazily creates one gVisor stack bound to the TUN device and routes the
// currently active agent's flows through it. This mirrors the legacy single
// active-tunnel model; a full multi-agent build would create one stack per
// selected agent.
type tunnel struct {
	tunName string
	srv     *node.Server

	mu     sync.Mutex
	stack  *netstack.NetStack
	pool   *netstack.ConnPool
	active *session.Session
}

func (t *tunnel) attach(s *session.Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active != nil {
		logrus.Infof("a tunnel is already active for %s; %s is available but not routed", t.active.ID, s.ID)
		return
	}
	if t.stack == nil {
		ns, err := netstack.NewStack(netstack.StackSettings{TunName: t.tunName, MaxInflight: 4096}, nil)
		if err != nil {
			logrus.Errorf("failed to create userland stack (need root + TUN): %v", err)
			return
		}
		t.stack = ns
	}
	pool := netstack.NewConnPool(4096)
	t.pool = &pool
	t.stack.SetConnPool(&pool)
	t.active = s
	go t.run(s, &pool)
	logrus.Infof("tunnel attached: routing %s through %s", s.ID, t.tunName)
}

func (t *tunnel) run(s *session.Session, pool *netstack.ConnPool) {
	for {
		tc, err := pool.Get()
		if err != nil {
			return
		}
		go node.HandlePacket(t.srv, s, t.stack.GetStack(), tc)
	}
}

func (t *tunnel) detach(s *session.Session) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active == s {
		if t.pool != nil {
			t.pool.Close()
			t.pool = nil
		}
		t.active = nil
	}
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
