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

// Package webui serves the v2 web interface and its JSON REST API, backed by a
// Controller the proxy implements. It replaces the legacy Gin web/daemon and
// drives node.Server directly. The UI is a single embedded page (no build
// step); access is gated by a bearer token printed at startup.
package webui

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/sirupsen/logrus"
)

//go:embed index.html
var indexHTML []byte

// AgentView is the operator-facing snapshot of an agent for the web UI.
type AgentView struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Online    bool           `json:"online"`
	Caps      uint32         `json:"caps"`
	Interface string         `json:"interface"` // tunnel iface, "" if not routed
	Networks  []string       `json:"networks"`  // advertised subnets
	Listeners []ListenerView `json:"listeners"`
}

// ListenerView describes a reverse listener.
type ListenerView struct {
	ID      int32  `json:"id"`
	Network string `json:"network"`
	Bind    string `json:"bind"`
	To      string `json:"to"`
}

// Controller is the proxy-side capability surface the web UI drives. The proxy
// implements it over node.Server + the tunnel manager.
type Controller interface {
	Agents() []AgentView
	StartTunnel(agentID, ifname string) (string, error)
	StopTunnel(agentID string) error
	Autoroute(agentID string) ([]string, error)
	AddListener(agentID, network, bind, to string) (int32, error)
	StopListener(agentID string, listenerID int32) error
	Kill(agentID string) error
}

// Server is the web UI HTTP server.
type Server struct {
	ctrl  Controller
	token string
	mux   *http.ServeMux
}

// New builds a web UI server. If token is empty, a random one is generated and
// returned via Token().
func New(ctrl Controller, token string) *Server {
	if token == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		token = hex.EncodeToString(b)
	}
	s := &Server{ctrl: ctrl, token: token, mux: http.NewServeMux()}
	s.routes()
	return s
}

// Token returns the bearer token required to use the API.
func (s *Server) Token() string { return s.token }

// Handler returns the HTTP handler (useful for embedding/tests).
func (s *Server) Handler() http.Handler { return s.mux }

// Serve starts the HTTP server on addr. tlsCert/tlsKey enable HTTPS when set.
func (s *Server) Serve(addr, tlsCert, tlsKey string) error {
	logrus.Infof("web UI on %s (token: %s)", addr, s.token)
	srv := &http.Server{Addr: addr, Handler: s.mux}
	if tlsCert != "" && tlsKey != "" {
		return srv.ListenAndServeTLS(tlsCert, tlsKey)
	}
	return srv.ListenAndServe()
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(indexHTML)
	})
	s.mux.HandleFunc("GET /api/agents", s.auth(s.handleAgents))
	s.mux.HandleFunc("POST /api/agents/{id}/tunnel", s.auth(s.handleStartTunnel))
	s.mux.HandleFunc("DELETE /api/agents/{id}/tunnel", s.auth(s.handleStopTunnel))
	s.mux.HandleFunc("POST /api/agents/{id}/autoroute", s.auth(s.handleAutoroute))
	s.mux.HandleFunc("POST /api/agents/{id}/listeners", s.auth(s.handleAddListener))
	s.mux.HandleFunc("DELETE /api/agents/{id}/listeners/{lid}", s.auth(s.handleStopListener))
	s.mux.HandleFunc("POST /api/agents/{id}/kill", s.auth(s.handleKill))
}

// auth wraps a handler with constant-time bearer-token checking.
func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	want := "Bearer " + s.token
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		h(w, r)
	}
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.ctrl.Agents())
}

func (s *Server) handleStartTunnel(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Interface string `json:"interface"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	ifName, err := s.ctrl.StartTunnel(r.PathValue("id"), body.Interface)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"interface": ifName})
}

func (s *Server) handleStopTunnel(w http.ResponseWriter, r *http.Request) {
	if err := s.ctrl.StopTunnel(r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}

func (s *Server) handleAutoroute(w http.ResponseWriter, r *http.Request) {
	routes, err := s.ctrl.Autoroute(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"routes": routes})
}

func (s *Server) handleAddListener(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Network string `json:"network"`
		Bind    string `json:"bind"`
		To      string `json:"to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	id, err := s.ctrl.AddListener(r.PathValue("id"), body.Network, body.Bind, body.To)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]int32{"id": id})
}

func (s *Server) handleStopListener(w http.ResponseWriter, r *http.Request) {
	lid, err := strconv.Atoi(r.PathValue("lid"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid listener id"})
		return
	}
	if err := s.ctrl.StopListener(r.PathValue("id"), int32(lid)); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopped"})
}

func (s *Server) handleKill(w http.ResponseWriter, r *http.Request) {
	if err := s.ctrl.Kill(r.PathValue("id")); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "killed"})
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
