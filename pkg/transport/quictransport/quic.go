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

// Package quictransport implements transport.Session/Listener/Dialer over QUIC.
//
// QUIC is the default Ligolo data plane. Because QUIC multiplexes streams inside
// the transport and recovers loss per-packet, a dropped datagram only stalls the
// streams it carried, eliminating the cross-stream head-of-line blocking and
// TCP-over-TCP meltdown that the legacy TLS+yamux design suffers on lossy links.
package quictransport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/nicocha30/ligolo-ng/pkg/transport"
	"github.com/quic-go/quic-go"
)

// ALPN is the QUIC application protocol identifier negotiated during the TLS
// handshake. It doubles as a coarse protocol version marker.
const ALPN = "ligolo/2"

var errNoTLS = errors.New("quictransport: a TLS configuration is required")

func defaultConfig() *quic.Config {
	return &quic.Config{
		// Keep idle sessions alive across stateful firewalls; this is an
		// explicit transport keepalive, distinct from the application-level
		// heartbeat on the control stream.
		KeepAlivePeriod: 15 * time.Second,
		MaxIdleTimeout:  60 * time.Second,
		// Large windows so a single pivoted bulk transfer can fill a high-BDP
		// link. Unlike yamux these are per-stream and grow automatically.
		InitialStreamReceiveWindow:     2 * 1024 * 1024,
		MaxStreamReceiveWindow:         32 * 1024 * 1024,
		InitialConnectionReceiveWindow: 4 * 1024 * 1024,
		MaxConnectionReceiveWindow:     64 * 1024 * 1024,
		EnableDatagrams:                true,
	}
}

// stream adapts *quic.Stream to net.Conn by borrowing the connection addresses.
// quic.Stream intentionally omits Local/RemoteAddr since they belong to the
// connection, but the relay code expects a full net.Conn.
type stream struct {
	*quic.Stream
	conn *quic.Conn
}

func (s *stream) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *stream) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

type session struct {
	conn *quic.Conn
}

func (s *session) Open(ctx context.Context) (transport.Stream, error) {
	qs, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &stream{Stream: qs, conn: s.conn}, nil
}

func (s *session) Accept(ctx context.Context) (transport.Stream, error) {
	qs, err := s.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return &stream{Stream: qs, conn: s.conn}, nil
}

func (s *session) Close() error { return s.conn.CloseWithError(0, "bye") }

func (s *session) IsClosed() bool {
	select {
	case <-s.conn.Context().Done():
		return true
	default:
		return false
	}
}

func (s *session) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }
func (s *session) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *session) Kind() transport.Kind { return transport.KindQUIC }

// SendDatagram / ReceiveDatagram implement transport.DatagramSession. Datagrams
// are enabled in defaultConfig; UDP flows can ride these instead of streams.
func (s *session) SendDatagram(b []byte) error { return s.conn.SendDatagram(b) }

func (s *session) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return s.conn.ReceiveDatagram(ctx)
}

// Ensure the QUIC session advertises datagram support.
var _ transport.DatagramSession = (*session)(nil)

// Dialer dials QUIC sessions (used by the agent).
type Dialer struct {
	TLSConfig *tls.Config
	Config    *quic.Config
}

func NewDialer(tlsConfig *tls.Config) *Dialer {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = []string{ALPN}
	return &Dialer{TLSConfig: tlsConfig, Config: defaultConfig()}
}

func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	conn, err := quic.DialAddr(ctx, addr, d.TLSConfig, d.Config)
	if err != nil {
		return nil, err
	}
	return &session{conn: conn}, nil
}

func (d *Dialer) Kind() transport.Kind { return transport.KindQUIC }

// Listener accepts QUIC sessions (used by the server).
type Listener struct {
	ql *quic.Listener
}

func Listen(addr string, tlsConfig *tls.Config) (*Listener, error) {
	if tlsConfig == nil {
		return nil, errNoTLS
	}
	tlsConfig = tlsConfig.Clone()
	tlsConfig.NextProtos = []string{ALPN}
	ql, err := quic.ListenAddr(addr, tlsConfig, defaultConfig())
	if err != nil {
		return nil, err
	}
	return &Listener{ql: ql}, nil
}

func (l *Listener) Accept(ctx context.Context) (transport.Session, error) {
	conn, err := l.ql.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &session{conn: conn}, nil
}

func (l *Listener) Close() error         { return l.ql.Close() }
func (l *Listener) Addr() net.Addr       { return l.ql.Addr() }
func (l *Listener) Kind() transport.Kind { return transport.KindQUIC }
