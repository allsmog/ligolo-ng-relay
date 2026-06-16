# Relay API and Automation

Enable the API without interactive config prompts:

```
proxy -daemon -selfcert -api -no-web-ui \
  -api-laddr 127.0.0.1:8080 \
  -web-user relay -web-password 'change-me'
```

Authenticate:

```
TOKEN="$(curl -fsS http://127.0.0.1:8080/api/auth \
  -H 'Content-Type: application/json' \
  -d '{"Username":"relay","Password":"change-me"}' | jq -r .token)"
```

Start relay mode on agent `1`:

```
curl -fsS http://127.0.0.1:8080/api/v1/relay/1 \
  -H "Authorization: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"ListenAddr":"<agent-interface-ip>:11602","TokenTTLSeconds":28800}'
```

The proxy generates a relay auth token when `AuthToken` is omitted. The response
includes that token, its expiry, and a fingerprint-pinned downstream connect
command. Add `"OneTimeToken": true` to allow a token to authenticate one
downstream agent only.

```json
{
  "message": "relay started",
  "fingerprint": "ABCD...",
  "auth_token": "relay-token...",
  "token_expires_at": "2026-06-16T20:00:00Z",
  "one_time_token": false,
  "connect_command": "./agent -connect <relay-agent-reachable-ip>:11602 -accept-fingerprint ABCD... -relay-token relay-token..."
}
```

Rotate the active token. Rotation restarts the relay listener and disconnects
downstream descendants so they must reconnect with the new token:

```
curl -fsS http://127.0.0.1:8080/api/v1/relay/1/token \
  -H "Authorization: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"TokenTTLSeconds":1800}'
```

Revoke the active token and stop relay mode:

```
curl -fsS -X DELETE http://127.0.0.1:8080/api/v1/relay/1/token \
  -H "Authorization: $TOKEN"
```

Inspect chain health:

```
curl -fsS http://127.0.0.1:8080/api/v1/chains \
  -H "Authorization: $TOKEN" | jq
```

The chain response keeps the human topology string and adds structured nodes:

```json
{
  "topology": "Chain topology:\n  Proxy\n  ...",
  "max_depth": 5,
  "agents": [
    {
      "agent_id": 1,
      "session_id": "agent-a",
      "state": "online",
      "path_rtt_ms": 4,
      "relay_active": true,
      "relay_listen_addr": "<agent-interface-ip>:11602",
      "relay_fingerprint": "ABCD...",
      "relay_token_expires_at": "2026-06-16T20:00:00Z",
      "relay_token_expired": false,
      "relay_one_time_token": false,
      "children": []
    }
  ]
}
```

`path_rtt_ms` is proxy-to-agent round-trip time over the full active path, not an
isolated single-hop measurement. It is cached briefly, probed in parallel for
stale entries, and omitted when a node is offline or does not answer before the
probe timeout.

`max_depth` is the maximum number of agents in a single branch, including the
direct root agent. With the default `5`, the deepest allowed branch is
`Proxy -> A -> B -> C -> D -> E`; a downstream agent below `E` is rejected.

The CLI exposes the same data with:

```
chain_list
chain_list --json
```

Run relay diagnostics:

```
curl -fsS 'http://127.0.0.1:8080/api/v1/relay/doctor?with_ipv6=false&interface_prefix=ligolo' \
  -H "Authorization: $TOKEN" | jq
```

The doctor response includes the chain snapshot, route candidates, duplicate
route warnings, active relay metadata, token expiry state, and recent relay
events such as downstream auth rejection, pending connection overload, depth
rejection, or relay control-channel closure.

Inspect route candidates across all online agents:

```
curl -fsS 'http://127.0.0.1:8080/api/v1/chain_routes?with_ipv6=false&interface_prefix=ligolo' \
  -H "Authorization: $TOKEN" | jq
```

Configure per-agent route/interface entries across the chain:

```
curl -fsS http://127.0.0.1:8080/api/v1/chain_autoroute \
  -H "Authorization: $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"InterfacePrefix":"ligolo","WithIPv6":false,"Start":false}'
```

## relayctl

The `relayctl` helper wraps the same REST calls for scripts:

```
relayctl -api http://127.0.0.1:8080 -user relay -password change-me chains
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" doctor
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" relay-start --agent 1 --listen <agent-interface-ip>:11602 --token-ttl 8h
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" relay-token-rotate --agent 1 --token-ttl 30m
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" relay-token-revoke --agent 1
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" chain-routes
relayctl -api http://127.0.0.1:8080 -token "$TOKEN" chain-autoroute --interface-prefix ligolo
```

Environment variable equivalents are supported:

- `LIGOLO_API`
- `LIGOLO_USER`
- `LIGOLO_PASSWORD`
- `LIGOLO_TOKEN`
- `LIGOLO_RELAY_TOKEN`
