#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/../../.." && pwd)"
compose_file="$script_dir/compose.yaml"
project="frp-admin-web-e2e-${GITHUB_RUN_ID:-local}-${RANDOM}-$$"

if [[ -z "${E2E_WEB_PORT:-}" ]]; then
  E2E_WEB_PORT="$(node -e 'const s=require("node:net").createServer();s.listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')"
fi
E2E_BOOTSTRAP_TOKEN="$(openssl rand -hex 24)"
export E2E_WEB_PORT E2E_BOOTSTRAP_TOKEN

cleanup() {
  docker compose -p "$project" -f "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker compose -p "$project" -f "$compose_file" up --build --detach --wait --wait-timeout 180

cd "$repo_dir/web"
PLAYWRIGHT_BASE_URL="http://127.0.0.1:${E2E_WEB_PORT}" \
  E2E_BOOTSTRAP_TOKEN="$E2E_BOOTSTRAP_TOKEN" \
  npm run test:e2e
