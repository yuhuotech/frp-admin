# Release tooling

`build-binaries.sh` cross-compiles static Linux `amd64` and `arm64` Agent and
Server archives. Agent archives include the binary, example configuration,
systemd units, constrained root helper, and a package-aware installer.

```sh
deploy/release/build-binaries.sh v1.2.3 dist/archives
deploy/ops/release-metadata.sh --output-dir dist/release dist/archives/*.tar.gz
deploy/ops/verify-release.sh dist/release
```

The GitHub release workflow performs these steps for version tags, scans each
image architecture before publishing, creates multi-platform images in GHCR,
keyless-signs the immutable manifest digest, and attaches SPDX JSON SBOMs plus
`SHA256SUMS` to the GitHub Release. GitHub OIDC build-provenance attestations
cover every attached release file, including the checksum manifest.

Verify downloaded artifacts and their attestations:

```sh
sha256sum -c SHA256SUMS
gh attestation verify frp-agent_1.2.3_linux_amd64.tar.gz --repo OWNER/REPOSITORY
gh attestation verify SHA256SUMS --repo OWNER/REPOSITORY
```

Resolve an image digest and verify its keyless Cosign signature. The identity
regular expression deliberately binds verification to this release workflow
and version-tag refs:

```sh
image=ghcr.io/OWNER/REPOSITORY-server
digest=$(docker buildx imagetools inspect "$image:v1.2.3" | awk '$1 == "Digest:" {print $2; exit}')
cosign verify "$image@$digest" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/OWNER/REPOSITORY/.github/workflows/release.yml@refs/tags/v'
```
