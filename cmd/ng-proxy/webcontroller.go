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

package main

import (
	"context"
	"errors"
	"sync"

	"github.com/nicocha30/ligolo-ng/pkg/node"
	"github.com/nicocha30/ligolo-ng/pkg/webui"
)

// webController adapts node.Server + the tunnel manager to webui.Controller, so
// the web UI drives the same v2 backend as the console and operator hub.
type webController struct {
	srv *node.Server
	tun *tunnelManager

	mu        sync.Mutex
	listeners map[string]map[int32]*node.ReverseListener // agentID -> id -> listener
}

func newWebController(srv *node.Server, tun *tunnelManager) *webController {
	return &webController{srv: srv, tun: tun, listeners: make(map[string]map[int32]*node.ReverseListener)}
}

func (c *webController) Agents() []webui.AgentView {
	out := []webui.AgentView{}
	for _, s := range c.srv.Registry.List() {
		lis := []webui.ListenerView{}
		for _, l := range s.Listeners() {
			lis = append(lis, webui.ListenerView{ID: l.ID, Network: l.Network, Bind: l.Address, To: l.To})
		}
		out = append(out, webui.AgentView{
			ID:        s.ID,
			Name:      s.Name,
			Online:    s.Online(),
			Caps:      s.Caps,
			Interface: c.tun.ifNameFor(s.ID),
			Networks:  agentSubnets(s.Interfaces),
			Listeners: lis,
		})
	}
	return out
}

func (c *webController) StartTunnel(agentID, ifname string) (string, error) {
	s, ok := c.srv.Registry.Get(agentID)
	if !ok {
		return "", errors.New("unknown agent")
	}
	return c.tun.start(s, ifname)
}

func (c *webController) StopTunnel(agentID string) error {
	if !c.tun.stop(agentID) {
		return errors.New("no tunnel for this agent")
	}
	return nil
}

func (c *webController) Autoroute(agentID string) ([]string, error) {
	s, ok := c.srv.Registry.Get(agentID)
	if !ok {
		return nil, errors.New("unknown agent")
	}
	ifName := c.tun.ifNameFor(agentID)
	if ifName == "" {
		return nil, errors.New("start a tunnel first")
	}
	return applyAutoroute(ifName, s), nil
}

func (c *webController) AddListener(agentID, network, bind, to string) (int32, error) {
	s, ok := c.srv.Registry.Get(agentID)
	if !ok {
		return 0, errors.New("unknown agent")
	}
	rl, err := c.srv.AddListener(context.Background(), s, network, bind, to)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	if c.listeners[agentID] == nil {
		c.listeners[agentID] = make(map[int32]*node.ReverseListener)
	}
	c.listeners[agentID][rl.ID] = rl
	c.mu.Unlock()
	return rl.ID, nil
}

func (c *webController) StopListener(agentID string, listenerID int32) error {
	c.mu.Lock()
	rl := c.listeners[agentID][listenerID]
	if rl != nil {
		delete(c.listeners[agentID], listenerID)
	}
	c.mu.Unlock()
	if rl == nil {
		return errors.New("unknown listener")
	}
	return rl.Stop(context.Background())
}

func (c *webController) Kill(agentID string) error {
	s, ok := c.srv.Registry.Get(agentID)
	if !ok {
		return errors.New("unknown agent")
	}
	return c.srv.KillAgent(context.Background(), s)
}
