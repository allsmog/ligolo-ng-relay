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
	"crypto/tls"
	"errors"
	"net"
	"sync"
)

// Client is an operator's connection to the Hub over mutual TLS.
type Client struct {
	conn  net.Conn
	codec *Codec
	mu    sync.Mutex // serializes unary RPCs on the shared connection
}

// Dial connects to the hub at addr using the given mTLS config.
func Dial(addr string, tlsConfig *tls.Config) (*Client, error) {
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, codec: NewCodec(conn)}, nil
}

// Close closes the operator connection.
func (c *Client) Close() error { return c.conn.Close() }

// call performs a unary request/response exchange.
func (c *Client) call(req interface{}) (interface{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.codec.Encode(req); err != nil {
		return nil, err
	}
	if err := c.codec.Decode(); err != nil {
		return nil, err
	}
	if e, ok := c.codec.Payload.(*ErrorResponse); ok {
		return nil, errors.New(e.Message)
	}
	return c.codec.Payload, nil
}

// ListAgents returns the current agent pool.
func (c *Client) ListAgents() ([]AgentInfo, error) {
	resp, err := c.call(ListAgentsRequest{})
	if err != nil {
		return nil, err
	}
	r, ok := resp.(*ListAgentsResponse)
	if !ok {
		return nil, errors.New("unexpected response")
	}
	return r.Agents, nil
}

// AddListener opens a reverse listener on the given agent.
func (c *Client) AddListener(agentID, network, address, to string) (int32, error) {
	resp, err := c.call(AddListenerRequest{AgentID: agentID, Network: network, Address: address, To: to})
	if err != nil {
		return 0, err
	}
	r, ok := resp.(*AddListenerResponse)
	if !ok {
		return 0, errors.New("unexpected response")
	}
	return r.ListenerID, nil
}

// StopListener closes a reverse listener.
func (c *Client) StopListener(agentID string, listenerID int32) error {
	_, err := c.call(StopListenerRequest{AgentID: agentID, ListenerID: listenerID})
	return err
}

// KillAgent terminates an agent.
func (c *Client) KillAgent(agentID string) error {
	_, err := c.call(KillAgentRequest{AgentID: agentID})
	return err
}

// Subscribe opens a dedicated streaming connection and returns a channel of
// agent events. The connection is closed when stop is called.
func Subscribe(addr string, tlsConfig *tls.Config) (<-chan AgentEvent, func(), error) {
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return nil, nil, err
	}
	codec := NewCodec(conn)
	if err := codec.Encode(SubscribeRequest{}); err != nil {
		conn.Close()
		return nil, nil, err
	}
	ch := make(chan AgentEvent, 64)
	go func() {
		defer close(ch)
		for {
			if err := codec.Decode(); err != nil {
				return
			}
			if ev, ok := codec.Payload.(*AgentEvent); ok {
				ch <- *ev
			}
		}
	}()
	return ch, func() { conn.Close() }, nil
}
