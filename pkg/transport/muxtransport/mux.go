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

// Package muxtransport implements transport.Session/Listener/Dialer over
// TLS+yamux. This is the firewall-traversal fallback used when QUIC's UDP is
// blocked. It carries the well-known TCP-over-TCP limitations and is therefore
// only selected when the QUIC transport is unavailable.
package muxtransport

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/pkg/transport"
)

func yamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.ConnectionWriteTimeout = 120 * time.Second
	// 16MB window mitigates (but cannot eliminate) the TCP-over-TCP throughput
	// collapse on high-latency pivots.
	cfg.MaxStreamWindowSize = 16 * 1024 * 1024
	return cfg
}

type session struct {
	sess *yamux.Session
}

func (s *session) Open(ctx context.Context) (transport.Stream, error) {
	st, err := s.sess.OpenStream()
	if err != nil {
		return nil, err
	}
	return st, nil
}

func (s *session) Accept(ctx context.Context) (transport.Stream, error) {
	st, err := s.sess.AcceptStream()
	if err != nil {
		return nil, err
	}
	return st, nil
}

func (s *session) Close() error         { return s.sess.Close() }
func (s *session) IsClosed() bool       { return s.sess.IsClosed() }
func (s *session) RemoteAddr() net.Addr { return s.sess.RemoteAddr() }
func (s *session) LocalAddr() net.Addr  { return s.sess.LocalAddr() }
func (s *session) Kind() transport.Kind { return transport.KindTLSMux }

// Server wraps an already-accepted net.Conn (the dialing peer) as a yamux
// server session. By convention the listening side runs the yamux server.
func Server(conn net.Conn) (transport.Session, error) {
	ys, err := yamux.Server(conn, yamuxConfig())
	if err != nil {
		return nil, err
	}
	return &session{sess: ys}, nil
}

// Client wraps a dialed net.Conn as a yamux client session.
func Client(conn net.Conn) (transport.Session, error) {
	ys, err := yamux.Client(conn, yamuxConfig())
	if err != nil {
		return nil, err
	}
	return &session{sess: ys}, nil
}

// Dialer dials a TLS connection then runs the yamux client over it.
type Dialer struct {
	TLSConfig *tls.Config
}

func NewDialer(tlsConfig *tls.Config) *Dialer {
	return &Dialer{TLSConfig: tlsConfig}
}

func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	var dialer net.Dialer
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, d.TLSConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return Client(tlsConn)
}

func (d *Dialer) Kind() transport.Kind { return transport.KindTLSMux }

// Listener accepts TLS connections and runs the yamux server over each.
type Listener struct {
	ln net.Listener
}

func Listen(addr string, tlsConfig *tls.Config) (*Listener, error) {
	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}
	return &Listener{ln: ln}, nil
}

func (l *Listener) Accept(ctx context.Context) (transport.Session, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	return Server(conn)
}

func (l *Listener) Close() error         { return l.ln.Close() }
func (l *Listener) Addr() net.Addr       { return l.ln.Addr() }
func (l *Listener) Kind() transport.Kind { return transport.KindTLSMux }
