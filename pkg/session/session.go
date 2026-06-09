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

// Package session holds per-session state for the refactored architecture.
//
// The legacy agent kept its connection-tracking maps, ID counters and the
// session identity in package-level globals (pkg/agent/handler.go), which is a
// data race under concurrent connections and collides across reconnects. Here
// all of that state is scoped to a Session value, IDs come from a CSPRNG (not
// the host MAC address), and the server-side Registry supports resuming a
// session onto a new transport connection.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nicocha30/ligolo-ng/pkg/transport"
	"github.com/nicocha30/ligolo-ng/pkg/wire"
)

// NewID returns a 128-bit random, unpredictable session identifier.
func NewID() string { return randomHex(16) }

// NewResumeToken returns a 256-bit random resume token.
func NewResumeToken() string { return randomHex(32) }

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand should never fail; fall back to a time-based value.
		for i := range b {
			b[i] = byte(time.Now().UnixNano() >> (i % 8 * 8))
		}
	}
	return hex.EncodeToString(b)
}

// Session is the server's view of a connected agent. It owns the transport
// session and all per-agent counters and tables.
type Session struct {
	ID          string
	ResumeToken string
	Name        string
	PeerKeyHex  string
	Caps        uint32
	Interfaces  []wire.NetInterface

	CreatedAt time.Time

	mu        sync.RWMutex
	tport     transport.Session
	lastSeen  time.Time
	connSeq   atomic.Uint64
	lisSeq    atomic.Uint32
	listeners map[int32]*Listener
}

// Listener tracks a reverse listener owned by a session.
type Listener struct {
	ID      int32
	Network string
	Address string
	To      string
}

func newSession(peerKeyHex string) *Session {
	now := time.Now()
	return &Session{
		ID:          NewID(),
		ResumeToken: NewResumeToken(),
		PeerKeyHex:  peerKeyHex,
		CreatedAt:   now,
		lastSeen:    now,
		listeners:   make(map[int32]*Listener),
	}
}

// Transport returns the current transport session.
func (s *Session) Transport() transport.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tport
}

// Rebind swaps in a new transport session (used on resume).
func (s *Session) Rebind(t transport.Session) {
	s.mu.Lock()
	s.tport = t
	s.lastSeen = time.Now()
	s.mu.Unlock()
}

// Touch records liveness.
func (s *Session) Touch() {
	s.mu.Lock()
	s.lastSeen = time.Now()
	s.mu.Unlock()
}

// LastSeen returns the last liveness timestamp.
func (s *Session) LastSeen() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastSeen
}

// NextConnID returns a fresh, monotonic connection id (atomic, race-free).
func (s *Session) NextConnID() uint64 { return s.connSeq.Add(1) }

// NextListenerID returns a fresh, monotonic listener id.
func (s *Session) NextListenerID() int32 { return int32(s.lisSeq.Add(1)) }

// AddListener registers a reverse listener.
func (s *Session) AddListener(l *Listener) {
	s.mu.Lock()
	s.listeners[l.ID] = l
	s.mu.Unlock()
}

// RemoveListener removes a reverse listener.
func (s *Session) RemoveListener(id int32) {
	s.mu.Lock()
	delete(s.listeners, id)
	s.mu.Unlock()
}

// Listeners returns a snapshot of the session's reverse listeners.
func (s *Session) Listeners() []*Listener {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Listener, 0, len(s.listeners))
	for _, l := range s.listeners {
		out = append(out, l)
	}
	return out
}

// Alive reports whether the underlying transport is still usable.
func (s *Session) Alive() bool {
	t := s.Transport()
	return t != nil && !t.IsClosed()
}

// Registry is the server's source of truth for connected agents. It is safe for
// concurrent use by multiple operators (the multi-operator hub reads from it).
type Registry struct {
	mu      sync.RWMutex
	byID    map[string]*Session
	byToken map[string]*Session
}

func NewRegistry() *Registry {
	return &Registry{byID: make(map[string]*Session), byToken: make(map[string]*Session)}
}

// Create registers a brand-new session for an authenticated agent.
func (r *Registry) Create(peerKeyHex string, t transport.Session) *Session {
	s := newSession(peerKeyHex)
	s.tport = t
	r.mu.Lock()
	r.byID[s.ID] = s
	r.byToken[s.ResumeToken] = s
	r.mu.Unlock()
	return s
}

// Resume looks up a session by id and validates its resume token, rebinding it
// to the new transport on success.
func (r *Registry) Resume(id, token string, t transport.Session) (*Session, bool) {
	r.mu.RLock()
	s, ok := r.byID[id]
	r.mu.RUnlock()
	if !ok || s.ResumeToken != token {
		return nil, false
	}
	s.Rebind(t)
	return s, true
}

// Get returns a session by id.
func (r *Registry) Get(id string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byID[id]
	return s, ok
}

// Remove deletes a session from the registry.
func (r *Registry) Remove(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.byID[id]; ok {
		delete(r.byToken, s.ResumeToken)
		delete(r.byID, id)
	}
}

// List returns a snapshot of all sessions.
func (r *Registry) List() []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Session, 0, len(r.byID))
	for _, s := range r.byID {
		out = append(out, s)
	}
	return out
}
