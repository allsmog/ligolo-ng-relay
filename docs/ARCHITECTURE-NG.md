# Ligolo-ng v2 architecture (refactor)

This document describes the from-scratch architecture implemented under
`pkg/transport`, `pkg/auth`, `pkg/wire`, `pkg/session`, `pkg/node` and the
`cmd/ng-agent` / `cmd/ng-proxy` entrypoints. It is a clean reimplementation of
the Ligolo core that keeps the parts of the legacy design that were genuinely
good (the gVisor userland network stack and TUN delivery) and replaces the parts
that limit stability and performance.

## Why

The legacy agent and proxy tunnel every logical stream through a single
TLS connection multiplexed with `hashicorp/yamux`. That has two structural
problems and several implementation ones:

* **TCP-over-TCP meltdown.** Running TCP streams inside one TCP connection means
  a single lost segment stalls every multiplexed stream (transport-level
  head-of-line blocking), and the inner and outer congestion-control loops
  fight each other on lossy or high-latency links, collapsing throughput.
* **Brittle multiplexer keepalive.** A single yamux ping timeout tears down the
  entire session and all of its streams.
* **Global mutable agent state.** The legacy agent kept its conntrack maps and
  id counters (`connTrackID`, `listenerID`) and its session identity in
  package-level globals, which races under concurrent connections and collides
  across reconnects.
* **Predictable identity.** The legacy session id is derived from the host MAC
  address (`uuid.NodeID()`), not a random value.
* **No version/capability negotiation.** The legacy control protocol writes a
  bare msgpack type byte with no framing, magic or version, so the two binaries
  cannot evolve independently or fall back gracefully.

## Three planes

The refactor separates concerns into three planes.

### Data plane — `pkg/transport`

A small interface (`Session`, `Stream`, `Listener`, `Dialer`) hides the
multiplexer so the data plane can run over different transports:

| Implementation | Package | Notes |
|---|---|---|
| **QUIC (default)** | `pkg/transport/quictransport` | UDP based, per-stream loss recovery (no cross-stream HoL blocking), built-in stream multiplexing, large auto-growing windows, transport keepalive, and unreliable **datagrams** (`transport.DatagramSession`) for UDP. |
| **TLS+yamux (fallback)** | `pkg/transport/muxtransport` | For environments where UDP is blocked. Carries the TCP-over-TCP limitations and is only chosen when QUIC is unavailable. |
| **WebSocket (fallback)** | `pkg/transport/wstransport` | yamux over a WebSocket (`ws://`/`wss://`) for CDN / HTTP-proxy traversal; traffic looks like ordinary HTTP(S). Selected last. |

`Stream` satisfies `net.Conn`, so streams are handed straight to the existing
`pkg/relay` and to gVisor's `gonet` adapters with no glue.

The gVisor userland stack and TUN device are reused unchanged from
`pkg/proxy/netstack`. `pkg/node/dataplane.go` is a transport-agnostic
replacement for the yamux-specific `netstack.HandlePacket`: it drives a
`Server` + `session.Session` instead of a `*yamux.Session`, so the same packet
handler works over QUIC or TLS+mux.

### Control plane — `pkg/wire`

A self-describing, length-prefixed, versioned frame replaces the legacy bare
msgpack stream. Each frame is an 8-byte header followed by a msgpack payload:

```
magic[2] = 0x4C 0x47 ("LG")
version  uint8        protocol version
type     uint8        message type
length   uint32 (BE)  payload length
```

* **Capability negotiation.** The `HelloRequest`/`HelloResponse` exchange carries
  a capability bitmap; the server operates on the intersection
  (`wire.Negotiate`), so agent and server can add features independently.
* **Explicit heartbeat.** `HeartbeatRequest`/`HeartbeatResponse` is an
  application-level liveness probe with its own timeout, so a single missed
  ping does not tear down the session the way yamux's keepalive does.
* **Session resumption.** `ResumeRequest` + the session id / resume token let an
  agent rebind an existing session to a new transport connection (complementing
  QUIC connection migration).

The control plane is logically separate from bulk data streams, so a saturated
transfer never blocks a heartbeat or kill command.

### Auth plane — `pkg/auth`

Mutual authentication uses the Noise framework's **IKpsk2** pattern
(`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`, the WireGuard construction):

* The agent (initiator) ships with the server's static public key pinned at
  build time; the server learns the agent's identity in the first message.
* An optional pre-shared key (`-psk`) is mixed in at message two.
* The handshake provides mutual auth, forward secrecy and key pinning with no
  PKI/CA machinery, and is independent of the transport TLS — so transport TLS
  can be a throwaway self-signed cert. The derived cipher states also encrypt
  the control stream, so control traffic is confidential even over an untrusted
  transport.

### Operator plane / multi-operator — `pkg/session` + `pkg/operator`

All per-agent state lives on a `session.Session` value (conntrack tables,
atomic id counters, capabilities, the bound transport) rather than in globals.
Ids and resume tokens come from `crypto/rand`. The server's `session.Registry`
is the single source of truth for connected agents and is safe for concurrent
reads by multiple operators.

`pkg/operator` is the Sliver-style multiplayer hub. It serves a typed RPC
surface (list agents, add/stop reverse listeners, kill agent, and a live event
stream of agent connect/resume/disconnect) over a **mutual-TLS** listener: each
operator authenticates with a client certificate and is identified by its
certificate common name. `ng-proxy -operator-listen` provisions an operator PKI,
writes a self-contained operator config bundle (`new-operator` flow), and serves
the hub; `ng-operator` is the operator CLI.

> Implementation note: the operator RPC uses the project's length-prefixed
> framing (msgpack) rather than gRPC/protobuf, because the build environment has
> no `protoc`. The message set in `pkg/operator/api.go` is the service contract
> and maps directly onto a `.proto` if gRPC codegen is desired.

### Session resumption and the disconnect grace window

When an agent's transport drops, the server does **not** immediately discard the
session: it marks it offline and retains it for a grace window
(`ServerConfig.ResumeGrace`, default 5 min), reaped by a background loop. On
reconnect the agent re-presents its session id + resume token; the server
validates the token, rebinds the new transport to the existing session, and
emits a `resume` event. This complements QUIC connection migration and means a
flaky agent keeps its identity and operator-visible state across reconnects.

## End-to-end flow

1. Agent dials the server over the chosen transport (`quic://`, `tls://`,
   `ws://` or `wss://`).
2. Agent opens the **control stream** and runs the Noise IKpsk2 handshake
   (initiator). The server authorizes the agent by its authenticated static key.
3. Agent sends `HelloRequest` (version, capabilities, interfaces, optional
   resume token); server replies `HelloResponse` with the negotiated capability
   set and a session id + resume token.
4. Server sends periodic heartbeats on the control stream and applies a liveness
   timeout.
5. For each flow the gVisor stack intercepts, the server opens a **data stream**,
   sends a `ConnectRequest`, and on success relays it to the userland endpoint.
   Reverse listeners and ICMP host-ping work the same way over their own streams.
6. When UDP-over-datagram is negotiated (QUIC only), UDP flows take a fast path:
   the server sets up the flow on a short-lived stream (`ConnectRequest.Datagram`
   + `FlowID`) and then carries packets over the connection's **datagram channel**
   keyed by `FlowID` (`pkg/node/dgram.go`), avoiding per-flow streams and stream
   head-of-line blocking. The setup stream stays open purely as a teardown
   signal. Datagrams larger than the QUIC MTU fall back to being dropped, matching
   UDP semantics; typical UDP (DNS, etc.) fits.

## Interactive console

`ng-proxy -console` drops into a small operator console driving `node.Server`
and the tunnel manager directly: `agents`, `use <id>`, `start [ifname]`/`stop`
(route the selected agent through its own TUN), `tunnels`,
`listener <net> <bind> <to>`, `listeners`, `stop-listener <id>`, and
`kill <id>`. This gives the legacy CLI's core UX on the v2 stack. Without
`-console` the proxy auto-routes every agent on its own interface (daemon-style).

## Multi-tunnel routing

The proxy routes any number of agents simultaneously: `tunnelManager`
(`cmd/ng-proxy`) gives each routed agent its own gVisor stack bound to its own
TUN interface (`ligolo`, `ligolo1`, …), with its own connection pool and
forwarding goroutine. Stopping a tunnel tears down its stack and removes the
interface; an agent disconnecting tears down its tunnel automatically.

## Security note on transport TLS

Transport TLS validation is intentionally skipped on the agent
(`InsecureSkipVerify`) because the Noise handshake against the pinned server key
is the real authentication and is independent of any certificate or host trust
store. This defeats enterprise TLS-inspection proxies and removes all PKI
management.

## Running it

```sh
# Server: QUIC data plane + operator hub. Prints the static public key to pin.
go run ./cmd/ng-proxy -listen quic://0.0.0.0:11601 -operator-listen 127.0.0.1:11602

# Agent: pin the server key printed above (transport can be quic/tls/ws/wss).
go run ./cmd/ng-agent -connect quic://server:11601 -server-key <hex>

# Operator: uses the bundle ng-proxy wrote to ./ligolo-operator/.
go run ./cmd/ng-operator -connect 127.0.0.1:11602 -config ./ligolo-operator list
go run ./cmd/ng-operator -connect 127.0.0.1:11602 -config ./ligolo-operator \
    listener <agentID> tcp 0.0.0.0:8080 127.0.0.1:80
go run ./cmd/ng-operator -connect 127.0.0.1:11602 -config ./ligolo-operator watch
```

## Build & test

```sh
go build ./...
go test -race ./pkg/wire/... ./pkg/auth/... ./pkg/session/... \
    ./pkg/node/... ./pkg/operator/... ./pkg/transport/...
```

Coverage of the integration tests:

* `pkg/node` stands up real QUIC, TLS+mux and WebSocket servers + agents, runs
  the full Noise handshake + capability negotiation, and relays connections end
  to end to an echo target; it also covers reverse listeners (incl. close) and
  session resumption (drop + reconnect keeps the same session id).
* `pkg/operator` runs the mTLS hub with a connected agent and exercises
  list/add-listener/event-stream, plus rejection of an operator with no client
  certificate.
* `pkg/transport/quictransport` proves QUIC datagrams flow over the
  `DatagramSession` interface.
* `TestRejectWrongServerKey` proves an agent that pins the wrong server key is
  rejected by the Noise handshake.

## Status / scope

Implemented and tested end to end: the three-plane core, all three transports
(QUIC default + TLS+mux and WebSocket fallbacks), Noise IKpsk2 auth, the
versioned control protocol with capability negotiation, reverse TCP/UDP
listeners, session resumption with a disconnect grace window, the mTLS
multi-operator hub with a CLI, **UDP-over-QUIC datagrams wired into the UDP
forwarder**, an **interactive operator console** for the proxy, and
**per-agent multi-tunnel routing** (each routed agent on its own TUN).

On the legacy front end: the v1 grumble CLI / web UI / daemon
(`cmd/proxy`, `web/`, `pkg/controller`) are intentionally left intact. They are
tightly bound to `*yamux.Session` through `controller.LigoloAgent` across ~2000
lines, so rather than retrofit them, the v2 stack ships its own operator
surfaces — the `ng-proxy -console` and the `ng-operator` mTLS client — which
together provide the legacy CLI's core UX on `node.Server`. Fully porting the
web UI / daemon onto `node.Server` (or deleting the v1 path once parity is
confirmed) remains the last migration step.

Remaining: retiring the v1 controller/yamux path. This is gated on reaching
feature parity for the pieces the v1 front end still owns and the v2 stack does
not yet replace — the web UI, daemon mode, route/interface autoconfiguration
(autoroute) and autobind, and config-file persistence. Until those land on
`node.Server`, deleting `cmd/proxy` / `web` / `pkg/controller` would regress
shipped functionality, so the v1 path is kept alongside v2 rather than removed.
