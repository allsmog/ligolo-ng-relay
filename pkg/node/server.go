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
	"sync"
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
	ResumeGrace       time.Duration // how long an offline session is retained for resume; 0 -> default 5m

	// Authorize, if set, gates an agent by its authenticated static public key
	// (hex). Returning false rejects the agent. nil means accept any agent that
	// completed the Noise handshake (i.e. knew the server key / psk).
	Authorize func(peerKeyHex string) bool

	// OnConnect / OnDisconnect notify the operator layer of session lifecycle.
	OnConnect    func(*session.Session)
	OnDisconnect func(*session.Session)
}

// EventKind classifies an agent lifecycle event.
type EventKind string

const (
	EventConnect    EventKind = "connect"
	EventResume     EventKind = "resume"
	EventDisconnect EventKind = "disconnect"
)

// Event is broadcast to subscribers (e.g. the operator hub) on agent lifecycle
// transitions.
type Event struct {
	Kind    EventKind
	Session *session.Session
}

// Server is the refactored Ligolo server. It owns the session Registry, which is
// the single source of truth shared by all connected operators.
type Server struct {
	cfg      ServerConfig
	Registry *session.Registry

	submu sync.Mutex
	subs  map[int]chan Event
	subID int
}

// Subscribe returns a channel of agent lifecycle events plus an unsubscribe
// function. Multiple operators can subscribe concurrently.
func (s *Server) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	s.submu.Lock()
	if s.subs == nil {
		s.subs = make(map[int]chan Event)
	}
	id := s.subID
	s.subID++
	s.subs[id] = ch
	s.submu.Unlock()
	return ch, func() {
		s.submu.Lock()
		if c, ok := s.subs[id]; ok {
			delete(s.subs, id)
			close(c)
		}
		s.submu.Unlock()
	}
}

func (s *Server) broadcast(kind EventKind, sess *session.Session) {
	s.submu.Lock()
	for _, ch := range s.subs {
		select {
		case ch <- Event{Kind: kind, Session: sess}:
		default: // drop if a slow subscriber is full
		}
	}
	s.submu.Unlock()
}

// NewServer builds a Server.
func NewServer(cfg ServerConfig) *Server {
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 30 * time.Second
	}
	if cfg.LivenessTimeout == 0 {
		cfg.LivenessTimeout = 90 * time.Second
	}
	if cfg.ResumeGrace == 0 {
		cfg.ResumeGrace = 5 * time.Minute
	}
	return &Server{cfg: cfg, Registry: session.NewRegistry()}
}

// Serve accepts sessions from the listener until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln transport.Listener) error {
	logrus.Infof("listening on %s (%s)", ln.Addr(), ln.Kind())
	go s.reapLoop(ctx)
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
	if _, ok := tsess.(transport.DatagramSession); ok {
		serverCaps |= uint32(wire.CapDatagramUDP)
	}
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
	if resumed {
		s.broadcast(EventResume, sess)
	} else {
		s.broadcast(EventConnect, sess)
	}
	defer func() {
		tsess.Close()
		// Only mark offline / notify if this connection is still the session's
		// bound transport. If the agent already resumed onto a newer connection,
		// leave that one alone.
		if !sess.IsCurrentTransport(tsess) {
			return
		}
		sess.MarkOffline()
		if s.cfg.OnDisconnect != nil {
			s.cfg.OnDisconnect(sess)
		}
		s.broadcast(EventDisconnect, sess)
		logrus.Infof("agent %s offline; retained for resume up to %s", sess.ID, s.cfg.ResumeGrace)
	}()

	s.runControl(ctx, sess, ctrl)
}

// reapLoop periodically removes sessions whose resume grace has elapsed.
func (s *Server) reapLoop(ctx context.Context) {
	interval := s.cfg.ResumeGrace / 4
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, dead := range s.Registry.Reap(s.cfg.ResumeGrace) {
				logrus.Infof("agent %s removed (resume grace elapsed)", dead.ID)
			}
		}
	}
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

// KillAgent asks the agent to terminate. The agent exits on receipt, so no
// response is expected.
func (s *Server) KillAgent(ctx context.Context, sess *session.Session) error {
	t := sess.Transport()
	if t == nil || t.IsClosed() {
		return errors.New("session is offline")
	}
	stream, err := t.Open(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()
	return wire.NewCodec(stream).Encode(wire.AgentKillRequest{})
}

// ErrConnectFailed indicates the agent could not reach the target.
var ErrConnectFailed = errors.New("agent could not establish connection")
