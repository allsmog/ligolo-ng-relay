# Ligolo-ng Relay Release Checklist

Ligolo-ng Relay should be released like an operator-facing security tool, not
an untracked patchset.

## Required Checks

```
git fetch upstream master
git merge-base --is-ancestor upstream/master HEAD
git submodule update --init --recursive
go test ./...
go build ./cmd/proxy ./cmd/agent
go build ./cmd/relayctl
make relay-test
```

For local GoReleaser dry-runs outside GitHub Actions, use snapshot mode and a
temporary cosign key so the checksum signing step does not wait for browser/OIDC
auth:

```
COSIGN_PASSWORD=dryrun cosign generate-key-pair --output-key-prefix /tmp/ligolo-dryrun
COSIGN_KEY=/tmp/ligolo-dryrun.key COSIGN_PASSWORD=dryrun \
  GITHUB_REPOSITORY_OWNER=<owner> GITHUB_TOKEN=dummy \
  goreleaser release --snapshot --clean --skip=publish
cosign verify-blob \
  --bundle dist/checksums.txt.sigstore.json \
  --key /tmp/ligolo-dryrun.pub \
  dist/checksums.txt
```

## Artifacts

GoReleaser builds proxy and agent binaries for Linux, macOS, Windows, FreeBSD,
and OpenBSD, plus the `relayctl` helper. Release artifacts should include:

- compressed proxy and agent archives
- `.spdx.sbom.json` SBOMs for release archives
- `checksums.txt`
- `checksums.txt.sigstore.json`
- GHCR images for `ligolo-ng-relay-proxy`, `ligolo-ng-relay-agent`, and
  `ligolo-ng-relayctl`
- cosign signatures for GHCR images and multi-arch manifests
- release notes that link to `FORK-DELTA.md`
- Docker relay lab verification output

## Signing

The release workflow installs Syft for SBOM generation and cosign for keyless
checksum and container-image signing. GoReleaser writes a Sigstore bundle for
`checksums.txt`. Users can verify downloaded archives by checking the archive
hash against `checksums.txt`, then verifying that file:

```
cosign verify-blob \
  --bundle dist/checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/<owner>/ligolo-ng-relay/.github/workflows/release.yml@refs/tags/<version>" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  dist/checksums.txt
```

Users can verify released container images with GitHub Actions OIDC identity:

```
cosign verify \
  --certificate-identity "https://github.com/<owner>/ligolo-ng-relay/.github/workflows/release.yml@refs/tags/<version>" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/<owner>/ligolo-ng-relay-proxy:<version>
```

## OIDC Smoke Test

Before the first public release, prove the GitHub Actions keyless signing path
with a temporary tag in the fork:

```
git tag v0.0.0-oidc-smoke
git push origin v0.0.0-oidc-smoke
gh run watch --repo <owner>/ligolo-ng-relay
gh release download v0.0.0-oidc-smoke --dir /tmp/ligolo-oidc-smoke
cosign verify-blob \
  --bundle /tmp/ligolo-oidc-smoke/checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/<owner>/ligolo-ng-relay/.github/workflows/release.yml@refs/tags/v0.0.0-oidc-smoke" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  /tmp/ligolo-oidc-smoke/checksums.txt
cosign verify \
  --certificate-identity "https://github.com/<owner>/ligolo-ng-relay/.github/workflows/release.yml@refs/tags/v0.0.0-oidc-smoke" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/<owner>/ligolo-ng-relay-proxy:v0.0.0-oidc-smoke
git push origin :refs/tags/v0.0.0-oidc-smoke
gh release delete v0.0.0-oidc-smoke --cleanup-tag --yes
```

Only keep the tag/release if the verification command succeeds from a clean
environment.

Do not publish a release from a branch where upstream is no longer an ancestor.
