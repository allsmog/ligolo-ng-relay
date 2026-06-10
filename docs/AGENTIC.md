# Agentic pivoting

Ligolo-ng's v2 operator control plane (`pkg/webui`) exposes a small, stable
capability surface — list agents, start/stop tunnels, install host routes, add/
stop reverse listeners, kill agents. Two front doors make that surface usable by
an AI agent:

- **`ng-mcp`** — a [Model Context Protocol](https://modelcontextprotocol.io)
  server. This is the native way for an LLM agent (Claude Desktop, Claude Code,
  or any MCP client) to drive pivoting through tool calls.
- **OpenAPI spec** — served at `GET /api/openapi.json` (no auth) and embedded at
  `pkg/webui/openapi.json`, for agents or tooling that speak plain HTTP.

Both drive the *same* backend as the web UI and the interactive console, with
the same bearer-token auth.

## 1. Start the proxy with the web API enabled

```sh
ng-proxy -listen quic://0.0.0.0:11601 -web-listen 127.0.0.1:8080 -web-token "$LIGOLO_WEB_TOKEN"
```

If `-web-token` is omitted, the proxy generates one and prints it at startup.

## 2. Run the MCP bridge

`ng-mcp` talks MCP over stdio and bridges to the proxy's web API. Point it at the
`-web-listen` address; pass the token via `$LIGOLO_WEB_TOKEN` (preferred — keeps
it out of the process list) or `-token`.

```sh
LIGOLO_WEB_TOKEN=... ng-mcp -url http://127.0.0.1:8080
```

### Wiring it into an MCP client

Most MCP clients launch the server as a subprocess. Example client config:

```json
{
  "mcpServers": {
    "ligolo": {
      "command": "/path/to/ng-mcp",
      "args": ["-url", "http://127.0.0.1:8080"],
      "env": { "LIGOLO_WEB_TOKEN": "your-token" }
    }
  }
}
```

## Tools

| Tool | Arguments | Action |
|---|---|---|
| `list_agents` | — | List agents with ids, networks, tunnel iface, listeners |
| `start_tunnel` | `agent_id`, `interface?` | Create a TUN tunnel; returns the interface name |
| `stop_tunnel` | `agent_id` | Tear down the tunnel |
| `autoroute` | `agent_id` | Install host routes for the agent's networks (modifies the host routing table) |
| `add_listener` | `agent_id`, `network`, `bind`, `to` | Create a reverse listener; returns its id |
| `stop_listener` | `agent_id`, `listener_id` | Remove a reverse listener |
| `kill_agent` | `agent_id` | Forcibly disconnect an agent (destructive) |

A typical agent flow: `list_agents` to find an agent advertising the target
subnet, `start_tunnel`, then `autoroute` — after which the target network is
reachable from the operator host.

## Security notes

- The token is the only credential; anyone who can reach `-web-listen` and holds
  it has full control. Bind the web API to localhost and run `ng-mcp` on the same
  host, so the only exposed transport is MCP stdio.
- `autoroute` changes the **operator host's** routing table, and `kill_agent` is
  destructive. The MCP tools expose the full capability set by design; if you
  want a read-only or reduced-capability agent, front it with a token scoped at
  the proxy or omit those tools in your client configuration.
- This is for authorized engagements only.
