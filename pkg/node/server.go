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

package node

import (
	"context"
	"errors"
	"math/rand"
	"time"

	"github.com/nicocha30/ligolo-ng/pkg/auth"
	"github.com/nicocha30/ligolo-ng/pkg/session"
	"github.com/nicocha30/ligolo-ng/pkg/transport"
	"github.com/nicocha30/ligolo-ng/pkg/wire"
	"github.com/sirupsen/logrus"
)

// ServerConfig configures a Server.
type ServerConfig struct {
	Identity          auth.Identity // server static keypair (clients pin Identity.Public())
	PSK               []byte        // optional pre-shared key (must match agents)
	Version           string
	HeartbeatInterval time.Duration // 0 -> default 30s
	LivenessTimeout   time.Duration // 0 -> default 90s

	// Authorize, if set, gates an agent by its authenticated static public key
	// (hex). Returning false rejects the agent. nil means accept any agent that
	// completed the Noise handshake (i.e. knew the server key / psk).
	Authorize func(peerKeyHex string) bool

	// OnConnect / OnDisconnect notify the operator layer of session lifecycle.
	OnConnect    func(*session.Session)
	OnDisconnect func(*session.Session)
}

// Server is the refactored Ligolo server. It owns the session Registry, which is
// the single source of truth shared by all connected operators.
type Server struct {
	cfg      ServerConfig
	Registry *session.Registry
}

// NewServer builds a Server.
func NewServer(cfg ServerConfig) *Server {
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 30 * time.Second
	}
	if cfg.LivenessTimeout == 0 {
		cfg.LivenessTimeout = 90 * time.Second
	}
	return &Server{cfg: cfg, Registry: session.NewRegistry()}
}

// Serve accepts sessions from the listener until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln transport.Listener) error {
	logrus.Infof("listening on %s (%s)", ln.Addr(), ln.Kind())
	for {
		sess, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			logrus.Errorf("accept session: %v", err)
			continue
		}
		go s.handleSession(ctx, sess)
	}
}

func (s *Server) handleSession(ctx context.Context, tsess transport.Session) {
	// The agent's first stream is the control stream.
	ctrlStream, err := tsess.Accept(ctx)
	if err != nil {
		logrus.Debugf("accept control stream: %v", err)
		tsess.Close()
		return
	}
	secure, err := auth.HandshakeResponder(ctrlStream, s.cfg.Identity, s.cfg.PSK)
	if err != nil {
		logrus.Warnf("rejected agent (noise handshake failed): %v", err)
		tsess.Close()
		return
	}
	peerKeyHex := secure.PeerKeyHex()
	if s.cfg.Authorize != nil && !s.cfg.Authorize(peerKeyHex) {
		logrus.Warnf("rejected agent %s (not authorized)", peerKeyHex)
		tsess.Close()
		return
	}

	ctrl := wire.NewCodec(secure)
	if err := ctrl.Decode(); err != nil {
		logrus.Debugf("read hello: %v", err)
		tsess.Close()
		return
	}
	hello, ok := ctrl.Payload.(*wire.HelloRequest)
	if !ok {
		logrus.Warn("first control message was not a hello")
		tsess.Close()
		return
	}

	// Capability negotiation: operate on the intersection.
	serverCaps := uint32(wire.CapTCP | wire.CapUDP | wire.CapICMP |
		wire.CapReverseListener | wire.CapResume | wire.CapHeartbeat)
	negotiated := wire.Negotiate(hello.Capabilities, serverCaps)

	var sess *session.Session
	resumed := false
	if hello.ResumeToken != "" && hello.SessionID != "" && wire.Has(negotiated, wire.CapResume) {
		if existing, okResume := s.Registry.Resume(hello.SessionID, hello.ResumeToken, tsess); okResume {
			sess = existing
			resumed = true
			logrus.Infof("resumed session %s for %s", sess.ID, hello.Name)
		}
	}
	if sess == nil {
		sess = s.Registry.Create(peerKeyHex, tsess)
	}
	sess.Name = hello.Name
	sess.Caps = negotiated
	sess.Interfaces = hello.Interfaces

	resp := wire.HelloResponse{
		ProtocolVersion:   wire.ProtocolVersion,
		ServerVersion:     s.cfg.Version,
		AcceptedCaps:      negotiated,
		SessionID:         sess.ID,
		ResumeToken:       sess.ResumeToken,
		Resumed:           resumed,
		HeartbeatInterval: int(s.cfg.HeartbeatInterval.Seconds()),
	}
	if err := ctrl.Encode(resp); err != nil {
		logrus.Debugf("send hello response: %v", err)
		tsess.Close()
		return
	}

	logrus.Infof("agent online: %s id=%s key=%s caps=%#x via %s",
		hello.Name, sess.ID, peerKeyHex[:16], negotiated, tsess.Kind())

	if s.cfg.OnConnect != nil {
		s.cfg.OnConnect(sess)
	}
	defer func() {
		if s.cfg.OnDisconnect != nil {
			s.cfg.OnDisconnect(sess)
		}
		s.Registry.Remove(sess.ID)
		tsess.Close()
	}()

	s.runControl(ctx, sess, ctrl)
}

// runControl drives the heartbeat loop on the control stream and detects loss.
func (s *Server) runControl(ctx context.Context, sess *session.Session, ctrl *wire.Codec) {
	if !wire.Has(sess.Caps, wire.CapHeartbeat) {
		// No heartbeat: just block until the control stream errors.
		for {
			if err := ctrl.Decode(); err != nil {
				return
			}
		}
	}

	// Reader goroutine: surfaces heartbeat responses and control-stream loss.
	pong := make(chan uint64, 4)
	readErr := make(chan error, 1)
	go func() {
		for {
			if err := ctrl.Decode(); err != nil {
				readErr <- err
				return
			}
			if hb, ok := ctrl.Payload.(*wire.HeartbeatResponse); ok {
				pong <- hb.Nonce
				sess.Touch()
			}
		}
	}()

	ticker := time.NewTicker(s.cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case err := <-readErr:
			logrus.Infof("agent %s control stream closed: %v", sess.ID, err)
			return
		case <-ticker.C:
			if time.Since(sess.LastSeen()) > s.cfg.LivenessTimeout {
				logrus.Warnf("agent %s missed liveness timeout, dropping", sess.ID)
				return
			}
			nonce := rand.Uint64()
			if err := ctrl.Encode(wire.HeartbeatRequest{Nonce: nonce}); err != nil {
				logrus.Infof("agent %s heartbeat send failed: %v", sess.ID, err)
				return
			}
		}
	}
}

// ---- Data-plane primitives (used by the netstack bridge and operator API) ----

// OpenConnect opens a fresh stream to the agent, asks it to dial the target and
// returns the stream ready for relaying. If the connection could not be
// established it returns ErrConnectFailed; reset reports whether a RST should be
// emitted by the userland stack.
func (s *Server) OpenConnect(ctx context.Context, sess *session.Session, req wire.ConnectRequest) (stream transport.Stream, reset bool, err error) {
	t := sess.Transport()
	if t == nil || t.IsClosed() {
		return nil, false, errors.New("session is offline")
	}
	stream, err = t.Open(ctx)
	if err != nil {
		return nil, false, err
	}
	codec := wire.NewCodec(stream)
	if err := codec.Encode(req); err != nil {
		stream.Close()
		return nil, false, err
	}
	if err := codec.Decode(); err != nil {
		stream.Close()
		return nil, false, err
	}
	resp, ok := codec.Payload.(*wire.ConnectResponse)
	if !ok {
		stream.Close()
		return nil, false, errors.New("unexpected connect response")
	}
	if !resp.Established {
		stream.Close()
		return nil, resp.Reset, ErrConnectFailed
	}
	return stream, false, nil
}

// HostPing asks the agent whether a host is alive (ICMP emulation).
func (s *Server) HostPing(ctx context.Context, sess *session.Session, address string) (bool, error) {
	t := sess.Transport()
	if t == nil || t.IsClosed() {
		return false, errors.New("session is offline")
	}
	stream, err := t.Open(ctx)
	if err != nil {
		return false, err
	}
	defer stream.Close()
	codec := wire.NewCodec(stream)
	if err := codec.Encode(wire.HostPingRequest{Address: address}); err != nil {
		return false, err
	}
	if err := codec.Decode(); err != nil {
		return false, err
	}
	resp, ok := codec.Payload.(*wire.HostPingResponse)
	if !ok {
		return false, errors.New("unexpected host ping response")
	}
	return resp.Alive, nil
}

// ErrConnectFailed indicates the agent could not reach the target.
var ErrConnectFailed = errors.New("agent could not establish connection")
