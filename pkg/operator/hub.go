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

package operator

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/nicocha30/ligolo-ng/pkg/node"
	"github.com/nicocha30/ligolo-ng/pkg/session"
	"github.com/sirupsen/logrus"
)

// Hub serves the operator API over a mutual-TLS listener, backed by a
// node.Server. It is safe for concurrent operators.
type Hub struct {
	srv *node.Server

	mu        sync.Mutex
	listeners map[string]map[int32]*node.ReverseListener // agentID -> id -> listener
}

// NewHub builds a Hub over the given server.
func NewHub(srv *node.Server) *Hub {
	return &Hub{srv: srv, listeners: make(map[string]map[int32]*node.ReverseListener)}
}

// Serve accepts operator connections on ln until ctx is cancelled. ln should be
// a mutual-TLS listener (see ServerTLSConfig).
func (h *Hub) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			logrus.Errorf("operator accept: %v", err)
			continue
		}
		go h.handle(ctx, conn)
	}
}

func (h *Hub) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	operator := operatorName(conn)
	logrus.Infof("operator connected: %s (%s)", operator, conn.RemoteAddr())
	defer logrus.Infof("operator disconnected: %s", operator)

	codec := NewCodec(conn)
	for {
		if err := codec.Decode(); err != nil {
			return
		}
		switch req := codec.Payload.(type) {
		case *ListAgentsRequest:
			_ = codec.Encode(ListAgentsResponse{Agents: h.snapshot()})
		case *AddListenerRequest:
			h.handleAddListener(ctx, codec, req)
		case *StopListenerRequest:
			h.handleStopListener(ctx, codec, req)
		case *KillAgentRequest:
			h.handleKillAgent(ctx, codec, req)
		case *SubscribeRequest:
			h.handleSubscribe(ctx, codec) // blocks until disconnect
			return
		default:
			_ = codec.Encode(ErrorResponse{Message: "unsupported request"})
		}
	}
}

func (h *Hub) handleAddListener(ctx context.Context, codec *Codec, req *AddListenerRequest) {
	sess, ok := h.srv.Registry.Get(req.AgentID)
	if !ok {
		_ = codec.Encode(ErrorResponse{Message: "unknown agent"})
		return
	}
	rl, err := h.srv.AddListener(ctx, sess, req.Network, req.Address, req.To)
	if err != nil {
		_ = codec.Encode(ErrorResponse{Message: err.Error()})
		return
	}
	h.mu.Lock()
	if h.listeners[req.AgentID] == nil {
		h.listeners[req.AgentID] = make(map[int32]*node.ReverseListener)
	}
	h.listeners[req.AgentID][rl.ID] = rl
	h.mu.Unlock()
	_ = codec.Encode(AddListenerResponse{ListenerID: rl.ID})
}

func (h *Hub) handleStopListener(ctx context.Context, codec *Codec, req *StopListenerRequest) {
	h.mu.Lock()
	rl := h.listeners[req.AgentID][req.ListenerID]
	if rl != nil {
		delete(h.listeners[req.AgentID], req.ListenerID)
	}
	h.mu.Unlock()
	if rl == nil {
		_ = codec.Encode(ErrorResponse{Message: "unknown listener"})
		return
	}
	if err := rl.Stop(ctx); err != nil {
		_ = codec.Encode(ErrorResponse{Message: err.Error()})
		return
	}
	_ = codec.Encode(StopListenerResponse{})
}

func (h *Hub) handleKillAgent(ctx context.Context, codec *Codec, req *KillAgentRequest) {
	sess, ok := h.srv.Registry.Get(req.AgentID)
	if !ok {
		_ = codec.Encode(ErrorResponse{Message: "unknown agent"})
		return
	}
	if err := h.srv.KillAgent(ctx, sess); err != nil {
		_ = codec.Encode(ErrorResponse{Message: err.Error()})
		return
	}
	_ = codec.Encode(KillAgentResponse{})
}

func (h *Hub) handleSubscribe(ctx context.Context, codec *Codec) {
	events, unsubscribe := h.srv.Subscribe()
	defer unsubscribe()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			if err := codec.Encode(AgentEvent{Kind: string(ev.Kind), Agent: agentInfo(ev.Session)}); err != nil {
				return
			}
		}
	}
}

func (h *Hub) snapshot() []AgentInfo {
	sessions := h.srv.Registry.List()
	out := make([]AgentInfo, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, agentInfo(s))
	}
	return out
}

func agentInfo(s *session.Session) AgentInfo {
	var ifaces []string
	for _, n := range s.Interfaces {
		ifaces = append(ifaces, n.Name)
	}
	var listeners []ListenerInfo
	for _, l := range s.Listeners() {
		listeners = append(listeners, ListenerInfo{ID: l.ID, Network: l.Network, Address: l.Address, To: l.To})
	}
	return AgentInfo{
		ID:         s.ID,
		Name:       s.Name,
		PeerKeyHex: s.PeerKeyHex,
		Online:     s.Online(),
		Caps:       s.Caps,
		Interfaces: ifaces,
		Listeners:  listeners,
	}
}

// operatorName extracts the operator identity from the verified client cert.
func operatorName(conn net.Conn) string {
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return "unknown"
	}
	state := tc.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "anonymous"
	}
	return state.PeerCertificates[0].Subject.CommonName
}
