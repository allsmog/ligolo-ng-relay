# Ligolo-ng Relay Enhancements

Ligolo-ng Relay is a maintained fork of
[Ligolo-ng](https://github.com/nicocha30/ligolo-ng). It adds multi-hop agent
chaining (relay mode) and ICMP Port Unreachable responses on top of upstream
Ligolo-ng. Everything else — setup, tunneling, listeners, the web UI — works
exactly as in upstream, so the [Ligolo-ng documentation](https://docs.ligolo.ng/)
still applies.

Operational docs:

- [FORK-DELTA.md](FORK-DELTA.md) tracks the fork's upstream base and exact delta.
- [doc/RELAY_API.md](doc/RELAY_API.md) documents relay automation and structured
  chain status, including the `relayctl` helper.
- [test/relay/README.md](test/relay/README.md) explains the Docker relay lab.
- [doc/UDP_SCAN_BENCHMARK.md](doc/UDP_SCAN_BENCHMARK.md) covers scan speed and
  classification benchmarks.
- [doc/RESTRICTIVE_EGRESS.md](doc/RESTRICTIVE_EGRESS.md) documents WebSocket,
  HTTP proxy, SOCKS, and relay-chain usage for constrained networks.
- [doc/PERFORMANCE.md](doc/PERFORMANCE.md) gives repeatable relay-chain path RTT
  and throughput checks.

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
   ligolo-ng-relay » session       # select Agent A
   [Agent: user@DMZ] » relay_start --addr <agent-interface-ip>:11602
   ```

2. On the downstream host (reachable from Agent A but not the proxy), connect
   through the relay using the command printed by `relay_start`:

   ```
   ./agent -connect <AgentA_IP>:11602 -accept-fingerprint <fingerprint> -relay-token <relay-token>
   ```

3. Agent B auto-registers on the proxy and can be used like any other agent.

### Commands

| Command | Description |
| --- | --- |
| `relay_start --addr <ip:port>` | Start a relay listener on the current agent |
| `relay_stop` | Stop the relay on the current agent |
| `chain_list` | Display the relay chain topology |
| `chain_list --json` | Display structured chain status for automation |
| `chain_routes` | Display route candidates across direct and relayed agents |
| `chain_autoroute` | Configure per-agent routes/interfaces across the chain |

### REST API

| Method & path | Description |
| --- | --- |
| `POST /api/v1/relay/:id` | Start relay (body: `{"ListenAddr": "<agent-interface-ip>:11602"}`) |
| `DELETE /api/v1/relay/:id` | Stop relay |
| `GET /api/v1/chains` | Get human and structured chain topology |
| `GET /api/v1/chain_routes` | Get route candidates across the chain |
| `POST /api/v1/chain_autoroute` | Configure per-agent routes/interfaces |

### Notes & limits

- A relay branch can contain up to **5 agents**: one direct root agent plus four
  downstream relay levels. Circular chains are detected and rejected.
- The `InfoReplyPacket` now carries a `RelayCapable` field so the proxy knows which
  agents can relay.
- Session recovery is supported for both relay agents and downstream agents.
- A `LIGOLO_SESSION_ID` environment variable allows running multiple agents on a
  single host (useful for testing chains locally).
- `relay_start` and the REST API return a fingerprint-pinned downstream connect
  command using `-accept-fingerprint` plus a proxy-minted `-relay-token`.
- Stopping a relay now closes downstream sessions registered through that relay
  and prunes their chain links.
- Structured chain status reports online/offline state and cached proxy-to-agent
  `path_rtt_ms` when the health probe succeeds.

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

ICMP Port Unreachable responses are rate-limited per target/scanner pair. The
default interval is `1s`; tune it with `LIGOLO_ICMP_UNREACHABLE_INTERVAL`
(`250ms`, `1s`, `0` to disable limiting).

**Implementation:** `pkg/proxy/netstack/icmp.go` (new) and a small change in
`pkg/proxy/netstack/handlers.go`.
