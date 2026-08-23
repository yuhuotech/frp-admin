# Supply-chain verification evidence

Verification date: 2026-07-28

This report records local release-image evidence. The local OCI digests include
BuildKit provenance attestations and are not a substitute for the GHCR manifest
digest produced and signed by the tag-triggered release workflow.

## Image evidence

Images were built for both release architectures. Builder and runtime base
images are pinned by multi-platform manifest digest. Trivy was run from the
fixed image `aquasec/trivy:0.67.2` (image digest
`sha256:e2b22eac59c02003d8749f5b8d9bd073b62e30fefaef5b7c8371204e0a4b0c08`)
with OS and language package scanning enabled.

| Image | Architecture | Local OCI digest | Runtime user | HIGH | CRITICAL |
| --- | --- | --- | --- | ---: | ---: |
| Server | amd64 | `sha256:0a1d03d8a74140e055682ed51f879b04c756ce6fc644a527578fcffa56cb5ca1` | `frpadmin` (UID 100) | 0 | 0 |
| Server | arm64 | `sha256:493eeb32b47893736d6bdb7f1ba4a633c677765930ea4ac8b7e26861432bfbf3` | `frpadmin` (UID 100) | 0 | 0 |
| Web | amd64 | `sha256:a18913ce6afa26b361581cc6ac759a7e101c7c5c2d9c6869e0d260636bc48c79` | UID 101 | 0 | 0 |
| Web | arm64 | `sha256:535951ca581046a474f107a83c8a2f5628ebd4d441a8e06737cbee7e4ecd279d` | UID 101 | 0 | 0 |

The Web base initially contained 12 HIGH findings in c-ares, curl, OpenSSL,
Expat, and libxml2. All had Alpine fixes and were removed by upgrading runtime
packages during the image build. Both architectures were rebuilt and rescanned
after the change.

Reproduction command, run once for each image tag:

```sh
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:0.67.2 image \
  --skip-version-check --scanners vuln --pkg-types os,library \
  --severity HIGH,CRITICAL --exit-code 1 IMAGE
```

## Runtime evidence

- Server `amd64`: `x86_64`, UID 100, Docker health `healthy`.
- Server `arm64`: `aarch64`, UID 100, Docker health `healthy`, readiness body
  `{"status":"ready"}`.
- Web `amd64`: `x86_64`, UID 101, Docker health `healthy`, `/healthz` returned
  `ok`.
- Web `arm64`: `aarch64`, UID 101, Docker health `healthy`, `/healthz` returned
  `ok`.
- Production and Web E2E Compose files both passed `docker compose config`.

## Source dependency evidence

`govulncheck v1.6.0 ./...` result:

| Module | Reachable vulnerabilities | Imported-package vulnerabilities | Module-only vulnerabilities |
| --- | ---: | ---: | ---: |
| contracts | 0 | 0 | 1 |
| agent | 0 | 0 | 1 |
| server | 0 | 0 | 1 |

The Server package-level findings were removed by upgrading Chi to `v5.3.0`,
`filippo.io/edwards25519` to `v1.1.1`, and `golang.org/x/net` to `v0.56.0`.
The remaining module-only advisory is for the unmaintained
`golang.org/x/crypto/openpgp` package: the application does not import or call
that package and the advisory has no fixed version.

`npm audit --omit=dev --audit-level=high` reports package entries that resolve
to the single scoped exception `GHSA-qwww-vcr4-c8h2`, an RSC Mode
action-execution advisory in React Router. The application uses React Router
`7.18.1` through `BrowserRouter` as a Vite-built browser-only SPA, does not
import an RSC/SSR/server-action runtime, and the production image contains only
static assets and Nginx. The vulnerable server-side path is therefore not
reachable. No other npm HIGH/CRITICAL advisory is allowlisted. Downgrading to
`7.11.0` was rejected because it reintroduces two older HIGH advisories. This
exception must be removed when RSC/server actions are introduced or a patched
React Router release becomes available.
