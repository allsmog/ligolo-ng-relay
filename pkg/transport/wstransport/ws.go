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

// Package wstransport implements transport.Session/Listener/Dialer over a
// WebSocket carrying a yamux multiplexer. WebSocket traffic looks like ordinary
// HTTP(S) and traverses web proxies and CDNs, so this is the fallback used when
// both QUIC (UDP) and raw TLS are blocked. It shares yamux's TCP-over-TCP
// limitations and is selected last.
package wstransport

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"
	"github.com/nicocha30/ligolo-ng/pkg/transport"
)

func yamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 30 * time.Second
	cfg.ConnectionWriteTimeout = 120 * time.Second
	cfg.MaxStreamWindowSize = 16 * 1024 * 1024
	return cfg
}

type session struct {
	sess *yamux.Session
}

func (s *session) Open(ctx context.Context) (transport.Stream, error)   { return s.sess.OpenStream() }
func (s *session) Accept(ctx context.Context) (transport.Stream, error) { return s.sess.AcceptStream() }
func (s *session) Close() error                                         { return s.sess.Close() }
func (s *session) IsClosed() bool                                       { return s.sess.IsClosed() }
func (s *session) RemoteAddr() net.Addr                                 { return s.sess.RemoteAddr() }
func (s *session) LocalAddr() net.Addr                                  { return s.sess.LocalAddr() }
func (s *session) Kind() transport.Kind                                 { return transport.KindWebsocket }

// Dialer dials a WebSocket and runs the yamux client over it.
type Dialer struct {
	TLSConfig *tls.Config
	UserAgent string
	// Host overrides the HTTP Host header, enabling domain fronting: dial a CDN
	// edge with a benign SNI (TLSConfig.ServerName) while the encrypted Host
	// header names the real backend.
	Host string
}

func NewDialer(tlsConfig *tls.Config) *Dialer {
	return &Dialer{TLSConfig: tlsConfig, UserAgent: "Mozilla/5.0"}
}

// NewDialerOpts builds a Dialer with a custom User-Agent and (optional) Host
// header for domain fronting.
func NewDialerOpts(tlsConfig *tls.Config, userAgent, host string) *Dialer {
	if userAgent == "" {
		userAgent = "Mozilla/5.0"
	}
	return &Dialer{TLSConfig: tlsConfig, UserAgent: userAgent, Host: host}
}

func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	httpClient := &http.Client{}
	if d.TLSConfig != nil {
		httpClient.Transport = &http.Transport{TLSClientConfig: d.TLSConfig}
	}
	hdr := http.Header{}
	hdr.Set("User-Agent", d.UserAgent)
	ws, _, err := websocket.Dial(ctx, addr, &websocket.DialOptions{
		HTTPClient: httpClient,
		HTTPHeader: hdr,
		Host:       d.Host,
	})
	if err != nil {
		return nil, err
	}
	netConn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	ys, err := yamux.Client(netConn, yamuxConfig())
	if err != nil {
		netConn.Close()
		return nil, err
	}
	return &session{sess: ys}, nil
}

func (d *Dialer) Kind() transport.Kind { return transport.KindWebsocket }

// Listener accepts WebSocket connections and runs a yamux server over each.
type Listener struct {
	httpSrv  *http.Server
	netLn    net.Listener
	sessions chan transport.Session
	addr     net.Addr
}

// Listen starts an HTTP(S) server that upgrades requests to WebSockets. If
// tlsConfig is non-nil the listener serves wss.
func Listen(addr string, tlsConfig *tls.Config) (*Listener, error) {
	netLn, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &Listener{
		netLn:    netLn,
		sessions: make(chan transport.Session, 16),
		addr:     netLn.Addr(),
	}
	l.httpSrv = &http.Server{Handler: http.HandlerFunc(l.handle)}
	go func() {
		if tlsConfig != nil {
			l.httpSrv.TLSConfig = tlsConfig
			_ = l.httpSrv.ServeTLS(netLn, "", "")
		} else {
			_ = l.httpSrv.Serve(netLn)
		}
	}()
	return l, nil
}

func (l *Listener) handle(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: []string{"*"}})
	if err != nil {
		return
	}
	netConn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	ys, err := yamux.Server(netConn, yamuxConfig())
	if err != nil {
		netConn.Close()
		return
	}
	sess := &session{sess: ys}
	select {
	case l.sessions <- sess:
	case <-r.Context().Done():
		ys.Close()
		return
	}
	// Keep the HTTP handler (and thus the websocket) alive for the session's life.
	<-ys.CloseChan()
}

func (l *Listener) Accept(ctx context.Context) (transport.Session, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case s, ok := <-l.sessions:
		if !ok {
			return nil, errors.New("wstransport: listener closed")
		}
		return s, nil
	}
}

func (l *Listener) Close() error         { return l.httpSrv.Close() }
func (l *Listener) Addr() net.Addr       { return l.addr }
func (l *Listener) Kind() transport.Kind { return transport.KindWebsocket }
