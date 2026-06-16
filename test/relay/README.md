# Relay Integration Lab

This lab proves the fork's multi-hop relay path with real proxy and agent
processes in Docker:

```
Proxy <-> Agent A relay <-> Agent B relay <-> Agent C
```

Run it from the repository root:

```
make relay-test
```

The script builds disposable Linux proxy/agent binaries, starts containers on a
private Docker network, starts relay mode on Agent A and then Agent B through the
REST API, connects Agent C through the nested relay, and asserts the structured
chain topology. It also verifies `chain_routes`/`chain_autoroute`, relays TCP
listener traffic from Agent C back to a proxy-side HTTP fixture, rechecks that
traffic after an idle period, verifies descendant cleanup when Agent B's relay is
stopped, re-forms Agent C through Agent B, and checks cleanup after Agent B is
killed. It also verifies the `relayctl doctor` diagnostics endpoint.

Requirements:

- Docker
- `curl`
- `jq`

Set `DOCKER="sudo docker"` if Docker requires sudo. Set
`RELAY_TEST_API_PORT=18081` if local port `18080` is already in use. Set
`RELAY_TEST_IDLE_SECONDS=30` to make the idle check more aggressive than the
default five seconds.
