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

// Command ng-agent is the reverse-connecting agent for the refactored Ligolo
// architecture. It dials the server over a pluggable transport, authenticates
// with Noise IKpsk2 against the pinned server key, and serves tunneled flows.
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"time"

	"github.com/nicocha30/ligolo-ng/pkg/auth"
	"github.com/nicocha30/ligolo-ng/pkg/node"
	"github.com/nicocha30/ligolo-ng/pkg/transport"
	"github.com/nicocha30/ligolo-ng/pkg/transport/muxtransport"
	"github.com/nicocha30/ligolo-ng/pkg/transport/quictransport"
	"github.com/nicocha30/ligolo-ng/pkg/transport/wstransport"
	"github.com/sirupsen/logrus"
)

func main() {
	connectAddr := flag.String("connect", "quic://127.0.0.1:11601", "server URL: quic://, tls://, ws:// or wss://host:port")
	serverKeyHex := flag.String("server-key", "", "pinned server static public key (hex), required")
	pskStr := flag.String("psk", "", "optional pre-shared key (IKpsk2), must match the server")
	keyHex := flag.String("key", "", "agent static private key (hex); generated if empty")
	reconnect := flag.Bool("reconnect", true, "auto-reconnect after the session is lost")
	reconnectDelay := flag.Int("reconnect-delay", 10, "reconnect delay in seconds")
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()

	if *verbose {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if *serverKeyHex == "" {
		logrus.Fatal("-server-key is required (pin the server's static public key)")
	}
	serverKey, err := hex.DecodeString(*serverKeyHex)
	if err != nil {
		logrus.Fatalf("invalid -server-key hex: %v", err)
	}

	identity := loadOrGenerateIdentity(*keyHex)
	logrus.Debugf("agent static public key: %s", identity.PublicHex())

	scheme, host := splitURL(*connectAddr)

	// Transport TLS validation is intentionally skipped: the Noise handshake
	// against the pinned server key is the real authentication, independent of
	// any TLS certificate or host trust store.
	tlsConfig := &tls.Config{InsecureSkipVerify: true}

	var dialer transport.Dialer
	serverAddr := host // quic/tls take host:port
	switch scheme {
	case "quic":
		dialer = quictransport.NewDialer(tlsConfig)
	case "tls":
		dialer = muxtransport.NewDialer(tlsConfig)
	case "ws":
		dialer = wstransport.NewDialer(nil)
		serverAddr = *connectAddr // websocket dial needs the full URL
	case "wss":
		dialer = wstransport.NewDialer(tlsConfig)
		serverAddr = *connectAddr
	default:
		logrus.Fatalf("unknown transport scheme %q (use quic://, tls://, ws:// or wss://)", scheme)
	}

	agent := node.NewAgent(node.AgentConfig{
		Identity:   identity,
		ServerKey:  serverKey,
		PSK:        []byte(*pskStr),
		Version:    "ng",
		ServerAddr: serverAddr,
	})

	ctx := context.Background()
	for {
		err := agent.Serve(ctx, dialer)
		if err != nil {
			logrus.Errorf("session ended: %v", err)
		}
		if !*reconnect {
			return
		}
		logrus.Infof("reconnecting in %d seconds...", *reconnectDelay)
		time.Sleep(time.Duration(*reconnectDelay) * time.Second)
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
			logrus.Fatalf("invalid agent key: %v", err)
		}
		return id
	}
	id, err := auth.GenerateIdentity()
	if err != nil {
		logrus.Fatalf("generate identity: %v", err)
	}
	return id
}

func splitURL(u string) (scheme, host string) {
	const sep = "://"
	for i := 0; i+len(sep) <= len(u); i++ {
		if u[i:i+len(sep)] == sep {
			return u[:i], u[i+len(sep):]
		}
	}
	return "quic", u
}
