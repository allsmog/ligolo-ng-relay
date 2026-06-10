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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
)

const (
	mcpProtocolVersion = "2024-11-05"
	serverName         = "ligolo-ng"
	serverVersion      = "ng"
)

// JSON-RPC 2.0 message shapes (the subset MCP uses over its stdio transport).
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// tool is a single MCP tool backed by a call into the REST client. Only the
// exported fields are advertised in tools/list; handler is internal.
type tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	handler     func(ctx context.Context, args map[string]any) (json.RawMessage, error)
}

// server is a minimal, dependency-free MCP stdio server. It speaks
// newline-delimited JSON-RPC 2.0 (the MCP stdio transport) and exposes
// ligolo-ng pivoting operations as tools an AI agent can call. Kept small so it
// is easy to audit for a security tool.
type server struct {
	rc    *restClient
	tools []tool
	index map[string]*tool
}

func newServer(rc *restClient) *server {
	s := &server{rc: rc, index: map[string]*tool{}}

	s.register(tool{
		Name:        "list_agents",
		Description: "List all connected ligolo-ng agents with their id, name, online status, tunnel interface, advertised networks, and reverse listeners. Call this first to discover agent ids and the subnets each agent can reach.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		handler: func(ctx context.Context, _ map[string]any) (json.RawMessage, error) {
			return s.rc.call(ctx, "GET", "/api/agents", nil)
		},
	})

	s.register(tool{
		Name:        "start_tunnel",
		Description: "Start a TUN tunnel for an agent so its networks become routable on the operator host. Returns the created interface name.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"agent_id":{"type":"string","description":"agent id from list_agents"},"interface":{"type":"string","description":"optional TUN interface name; auto-generated if omitted"}},"required":["agent_id"],"additionalProperties":false}`),
		handler: func(ctx context.Context, args map[string]any) (json.RawMessage, error) {
			id, err := reqStr(args, "agent_id")
			if err != nil {
				return nil, err
			}
			body := map[string]string{}
			if v, ok := args["interface"].(string); ok && v != "" {
				body["interface"] = v
			}
			return s.rc.call(ctx, "POST", agentPath(id, "/tunnel"), body)
		},
	})

	s.register(tool{
		Name:        "stop_tunnel",
		Description: "Stop the TUN tunnel for an agent and remove its interface.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"agent_id":{"type":"string"}},"required":["agent_id"],"additionalProperties":false}`),
		handler: func(ctx context.Context, args map[string]any) (json.RawMessage, error) {
			id, err := reqStr(args, "agent_id")
			if err != nil {
				return nil, err
			}
			return s.rc.call(ctx, "DELETE", agentPath(id, "/tunnel"), nil)
		},
	})

	s.register(tool{
		Name:        "autoroute",
		Description: "Install routes on the operator host for every network the agent advertises, so traffic to those subnets is sent through the agent's tunnel. Requires a tunnel to be started first. Returns the routes that were added. Note: this modifies the operator host's routing table.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"agent_id":{"type":"string"}},"required":["agent_id"],"additionalProperties":false}`),
		handler: func(ctx context.Context, args map[string]any) (json.RawMessage, error) {
			id, err := reqStr(args, "agent_id")
			if err != nil {
				return nil, err
			}
			return s.rc.call(ctx, "POST", agentPath(id, "/autoroute"), nil)
		},
	})

	s.register(tool{
		Name:        "add_listener",
		Description: "Create a reverse listener (port forward) on the agent: the agent binds a port and forwards accepted connections to a destination. Use this to expose a service reachable from the agent back to the operator, or to relay into the target network. Returns the listener id.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"agent_id":{"type":"string"},"network":{"type":"string","description":"tcp or udp"},"bind":{"type":"string","description":"address the agent binds, e.g. 0.0.0.0:1234"},"to":{"type":"string","description":"destination the agent forwards to, e.g. 127.0.0.1:8080"}},"required":["agent_id","network","bind","to"],"additionalProperties":false}`),
		handler: func(ctx context.Context, args map[string]any) (json.RawMessage, error) {
			id, err := reqStr(args, "agent_id")
			if err != nil {
				return nil, err
			}
			network, err := reqStr(args, "network")
			if err != nil {
				return nil, err
			}
			bind, err := reqStr(args, "bind")
			if err != nil {
				return nil, err
			}
			to, err := reqStr(args, "to")
			if err != nil {
				return nil, err
			}
			return s.rc.call(ctx, "POST", agentPath(id, "/listeners"), map[string]string{
				"network": network, "bind": bind, "to": to,
			})
		},
	})

	s.register(tool{
		Name:        "stop_listener",
		Description: "Stop and remove a reverse listener by its id (from add_listener or list_agents).",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"agent_id":{"type":"string"},"listener_id":{"type":"integer"}},"required":["agent_id","listener_id"],"additionalProperties":false}`),
		handler: func(ctx context.Context, args map[string]any) (json.RawMessage, error) {
			id, err := reqStr(args, "agent_id")
			if err != nil {
				return nil, err
			}
			lid, err := reqInt(args, "listener_id")
			if err != nil {
				return nil, err
			}
			return s.rc.call(ctx, "DELETE", agentPath(id, "/listeners/"+strconv.Itoa(lid)), nil)
		},
	})

	s.register(tool{
		Name:        "kill_agent",
		Description: "Forcibly disconnect an agent. This is destructive: the agent's session and all its tunnels and listeners are torn down.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"agent_id":{"type":"string"}},"required":["agent_id"],"additionalProperties":false}`),
		handler: func(ctx context.Context, args map[string]any) (json.RawMessage, error) {
			id, err := reqStr(args, "agent_id")
			if err != nil {
				return nil, err
			}
			return s.rc.call(ctx, "POST", agentPath(id, "/kill"), nil)
		},
	})

	return s
}

func (s *server) register(t tool) {
	s.tools = append(s.tools, t)
	s.index[t.Name] = &s.tools[len(s.tools)-1]
}

// run reads newline-delimited JSON-RPC requests from in and writes responses to
// out until in is exhausted. Notifications (requests without an id) get no reply.
func (s *server) run(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	w := bufio.NewWriter(out)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			s.write(w, rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
			continue
		}
		resp, notification := s.handle(ctx, &req)
		if notification {
			continue
		}
		s.write(w, resp)
	}
	return sc.Err()
}

func (s *server) handle(ctx context.Context, req *rpcRequest) (resp rpcResponse, notification bool) {
	resp = rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch {
	case req.Method == "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		pv := p.ProtocolVersion
		if pv == "" {
			pv = mcpProtocolVersion
		}
		resp.Result = map[string]any{
			"protocolVersion": pv,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": serverName, "version": serverVersion},
		}
	case strings.HasPrefix(req.Method, "notifications/"):
		notification = true
	case req.Method == "ping":
		resp.Result = map[string]any{}
	case req.Method == "tools/list":
		resp.Result = map[string]any{"tools": s.tools}
	case req.Method == "tools/call":
		resp.Result = s.callTool(ctx, req.Params)
	default:
		if len(req.ID) == 0 {
			notification = true // unknown notification: ignore
			return
		}
		resp.Error = &rpcError{Code: -32601, Message: "method not found: " + req.Method}
	}
	return
}

// callTool dispatches a tools/call. Per MCP, tool-level failures are returned as
// a result with isError=true (not as a JSON-RPC error), so the agent can read
// the message and decide how to recover.
func (s *server) callTool(ctx context.Context, params json.RawMessage) map[string]any {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return toolErr("invalid params: " + err.Error())
	}
	t := s.index[p.Name]
	if t == nil {
		return toolErr("unknown tool: " + p.Name)
	}
	out, err := t.handler(ctx, p.Arguments)
	if err != nil {
		return toolErr(err.Error())
	}
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(out)}},
		"isError": false,
	}
}

func toolErr(msg string) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": msg}},
		"isError": true,
	}
}

func (s *server) write(w *bufio.Writer, resp rpcResponse) {
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	w.Write(b)
	w.WriteByte('\n')
	w.Flush()
}

func agentPath(id, suffix string) string {
	return "/api/agents/" + url.PathEscape(id) + suffix
}

func reqStr(args map[string]any, key string) (string, error) {
	v, ok := args[key]
	if !ok {
		return "", fmt.Errorf("missing required argument %q", key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("argument %q must be a non-empty string", key)
	}
	return s, nil
}

func reqInt(args map[string]any, key string) (int, error) {
	v, ok := args[key]
	if !ok {
		return 0, fmt.Errorf("missing required argument %q", key)
	}
	switch n := v.(type) {
	case float64: // JSON numbers decode to float64
		return int(n), nil
	case string:
		i, err := strconv.Atoi(n)
		if err != nil {
			return 0, fmt.Errorf("argument %q must be an integer", key)
		}
		return i, nil
	default:
		return 0, fmt.Errorf("argument %q must be an integer", key)
	}
}
