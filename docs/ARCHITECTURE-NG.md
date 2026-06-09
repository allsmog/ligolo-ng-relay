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
| **QUIC (default)** | `pkg/transport/quictransport` | UDP based, per-stream loss recovery (no cross-stream HoL blocking), built-in stream multiplexing, large auto-growing windows, transport keepalive. |
| **TLS+yamux (fallback)** | `pkg/transport/muxtransport` | For environments where UDP is blocked. Carries the TCP-over-TCP limitations and is only chosen when QUIC is unavailable. |

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

### Operator plane / multi-operator — `pkg/session`

All per-agent state lives on a `session.Session` value (conntrack tables,
atomic id counters, capabilities, the bound transport) rather than in globals.
Ids and resume tokens come from `crypto/rand`. The server's `session.Registry`
is the single source of truth for connected agents and is safe for concurrent
reads by multiple operators — the foundation for a Sliver-style multi-operator
hub. Resuming validates the session id against its secret resume token before
rebinding the transport.

## End-to-end flow

1. Agent dials the server over the chosen transport (`quic://` or `tls://`).
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

## Security note on transport TLS

Transport TLS validation is intentionally skipped on the agent
(`InsecureSkipVerify`) because the Noise handshake against the pinned server key
is the real authentication and is independent of any certificate or host trust
store. This defeats enterprise TLS-inspection proxies and removes all PKI
management.

## Build & test

```sh
go build ./...
go test ./pkg/wire/... ./pkg/auth/... ./pkg/session/... ./pkg/node/...
```

The `pkg/node` integration tests stand up a real QUIC (and TLS+mux) server and
agent, run the full handshake + capability negotiation, and relay a connection
end to end to a local echo target. `TestRejectWrongServerKey` proves an agent
that pins the wrong server key is rejected by the Noise handshake.

## Status / scope

This is the core architecture, wired and tested. It does not yet replace the
legacy CLI / web UI / daemon / autoroute, which continue to use the v1 stack.
Follow-on work: a gRPC+mTLS operator API on top of `session.Registry`,
per-agent multi-tunnel routing, UDP-over-QUIC datagrams (`CapDatagramUDP`), and
a WebSocket/HTTPS fallback transport for CDN traversal.
