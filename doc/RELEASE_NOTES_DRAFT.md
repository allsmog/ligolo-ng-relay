# Ligolo-ng Relay Release Notes Draft

Ligolo-ng Relay is a maintained fork of upstream Ligolo-ng `v0.8.3` focused on
operator-safe multi-hop relay chains. The exact fork delta is tracked in
[FORK-DELTA.md](../FORK-DELTA.md).

## Highlights

- Multi-hop relay mode for `Proxy -> Agent A relay -> Agent B` and deeper chains.
- `relayctl` for scriptable API workflows.
- `relay_doctor` and `relayctl doctor` for chain health, relay token state,
  recent relay events, and duplicate route warnings.
- Relay auth tokens now expire by default, can be one-time, and can be rotated
  or revoked.
- Structured chain JSON now includes relay fingerprint and token expiry metadata.
- `chain_routes` and `chain_autoroute` support route planning across relayed
  agents and flag duplicate CIDRs.
- UDP scan acceleration via ICMP/ICMPv6 Port Unreachable responses.
- Release artifacts include proxy, agent, and `relayctl` binaries, archive
  SBOMs, checksums, a Sigstore checksum bundle, and GHCR images.

## Operator Docs

- [Relay Quickstart](QUICKSTART_RELAY.md)
- [Relay API and Automation](RELAY_API.md)
- [Restrictive Egress Runbook](RESTRICTIVE_EGRESS.md)
- [Relay Performance Checks](PERFORMANCE.md)
- [UDP Scan Benchmark](UDP_SCAN_BENCHMARK.md)

## Verification

Before publishing, attach or reference the output from:

```
go test ./...
go build ./cmd/proxy ./cmd/agent ./cmd/relayctl
make relay-test
goreleaser release --snapshot --clean --skip=publish
cosign verify-blob --bundle dist/checksums.txt.sigstore.json --key /tmp/ligolo-dryrun.pub dist/checksums.txt
```

For the first public release, also run the OIDC smoke test in
[doc/RELEASE.md](RELEASE.md).
