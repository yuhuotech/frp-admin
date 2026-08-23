#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/frp-admin-production-check.XXXXXXXX")
cleanup() { rm -rf -- "$build_dir"; }
trap cleanup EXIT INT TERM

command -v go >/dev/null 2>&1 || { printf '%s\n' 'required command not found: go' >&2; exit 2; }
go_bin=$(go env GOPATH)/bin
PATH="$PATH:$go_bin"
export PATH

for command in npm protoc protoc-gen-go protoc-gen-go-grpc sqlite3 openssl tar; do
  command -v "$command" >/dev/null 2>&1 || { printf 'required command not found: %s\n' "$command" >&2; exit 2; }
done

cd "$repo_root"
printf '%s\n' '[1/8] Generate contracts and verify committed output'
if [[ -d contracts/gen ]]; then
  cp -R contracts/gen "$build_dir/contracts-gen-before"
else
  mkdir -p "$build_dir/contracts-gen-before"
fi
./contracts/scripts/generate.sh
diff -ru "$build_dir/contracts-gen-before" contracts/gen
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  git diff --exit-code -- contracts/gen
fi

printf '%s\n' '[2/8] Run all Go tests'
(cd contracts && go test ./...)
(cd agent && go test ./...)
(cd server && go test ./...)

printf '%s\n' '[3/8] Run full Go race suites'
(cd contracts && go test -race ./...)
(cd agent && go test -race ./...)
(cd server && go test -race ./...)

printf '%s\n' '[4/8] Run Go vet'
(cd contracts && go vet ./...)
(cd agent && go vet ./...)
(cd server && go vet ./...)

printf '%s\n' '[5/8] Run Web lint, tests, production audit, and build'
(cd web && npm run lint && npm test -- --run && npm run audit:production && npm run build)

printf '%s\n' '[6/8] Build Server and Agent binaries'
(cd agent && go build -trimpath -o "$build_dir/frp-agent" ./cmd/frp-agent)
(cd server && go build -trimpath -o "$build_dir/frp-admin-server" ./cmd/frp-admin-server)

printf '%s\n' '[7/8] Validate shell syntax'
while IFS= read -r shell_file; do
  bash -n "$shell_file"
done < <(find deploy contracts scripts -type f -name '*.sh' -print | LC_ALL=C sort)
bash -n deploy/e2e/systemd/frp-e2e-prestart

printf '%s\n' '[8/8] Run backup/restore regression including historical keyring materialization'
./deploy/ops/test.sh

cat <<'EOF'
Deterministic production checks passed.

This is not production approval. The following gates are intentionally not
executed here and require retained evidence from their target environments:
  - make production-check-database (run separately for MySQL and PostgreSQL)
  - make production-check-systemd
  - make production-check-controlplane
  - security/release workflows for Trivy, SBOM, signing, and provenance
  - make production-check-soak (must complete 168 hours)
EOF
