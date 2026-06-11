# Warren Enhancements

Warren is a fork of [Ligolo-ng](https://github.com/nicocha30/ligolo-ng). It adds
multi-hop agent chaining (relay mode) and ICMP Port Unreachable responses on top of
upstream Ligolo-ng. Everything else — setup, tunneling, listeners, the web UI — works
exactly as in upstream, so the [Ligolo-ng documentation](https://docs.ligolo.ng/)
still applies.

---

## Multi-Hop Agent Chaining (Relay Mode)

Agents can act as lightweight TLS relays for downstream agents. This lets you pivot
through segmented networks where some hosts cannot reach the proxy directly:

```
Proxy <---> Agent A (relay) <---> Agent B ---> Target Network
```

Agent A relays the downstream connection with a direct, bidirectional `io.Copy`
bridge (no nested yamux multiplexing), so the relay adds minimal overhead. Once
Agent B registers on the proxy through the relay, it behaves like any directly
connected agent — tunnels, listeners, and session recovery all work across the
full chain.

### Setup

1. Select an agent and start relay mode:

   ```
   ligolo-ng » session             # select Agent A
   [Agent: user@DMZ] » relay_start --addr 0.0.0.0:11602
   ```

2. On the downstream host (reachable from Agent A but not the proxy), connect
   through the relay:

   ```
   ./agent -connect <AgentA_IP>:11602 -ignore-cert
   ```

3. Agent B auto-registers on the proxy and can be used like any other agent.

### Commands

| Command | Description |
| --- | --- |
| `relay_start --addr <ip:port>` | Start a relay listener on the current agent |
| `relay_stop` | Stop the relay on the current agent |
| `chain_list` | Display the relay chain topology |

### REST API

| Method & path | Description |
| --- | --- |
| `POST /api/v1/relay/:id` | Start relay (body: `{"ListenAddr": "0.0.0.0:11602"}`) |
| `DELETE /api/v1/relay/:id` | Stop relay |
| `GET /api/v1/chains` | Get the chain topology |

### Notes & limits

- Maximum chain depth is **5 hops**; circular chains are detected and rejected.
- The `InfoReplyPacket` now carries a `RelayCapable` field so the proxy knows which
  agents can relay.
- Session recovery is supported for both relay agents and downstream agents.
- A `LIGOLO_SESSION_ID` environment variable allows running multiple agents on a
  single host (useful for testing chains locally).

**Implementation:** new protocol messages (`RelayRequest`, `RelayResponse`,
`RelayNewConnection`, `RelayBridgeRequest`), an agent-side relay listener with
self-signed TLS, and a `ChainManager` that tracks topology, enforces depth limits,
and detects circular chains.

---

## ICMP Port Unreachable for UDP Scans

When a UDP connection to a remote port is refused (`ECONNREFUSED`), the proxy now
generates an ICMP Destination Unreachable packet (Type 3, Code 3 — Port Unreachable)
and injects it back into the TUN interface. Scanners like `nmap` detect closed UDP
ports instantly instead of waiting for a timeout on every port.

The ICMP error payload includes the original IP header plus the first 8 bytes of the
UDP header (per RFC 792), so scanners can correlate the response with the probe that
triggered it.

Previously, UDP failures silently disappeared because `Terminate()` was a no-op for
UDP connections — leaving scanners to time out on every closed port.

**Implementation:** `pkg/proxy/netstack/icmp.go` (new) and a small change in
`pkg/proxy/netstack/handlers.go`.
