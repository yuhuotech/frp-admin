#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh
source "$script_dir/lib.sh"

usage() {
  cat >&2 <<'EOF'
Usage: smoke.sh --base-url URL [--username NAME --password-file FILE --expected-ca FILE]

Without credentials, checks liveness, readiness, and bootstrap state. With credentials,
also verifies login, restored CA identity, node/config reads, and decrypts one existing
config revision when available. Password contents are never passed as command arguments.
EOF
  exit 2
}

base_url=''
username=''
password_file=''
expected_ca=''
while (($#)); do
  case "$1" in
    --base-url) base_url=${2:-}; shift 2 ;;
    --username) username=${2:-}; shift 2 ;;
    --password-file) password_file=${2:-}; shift 2 ;;
    --expected-ca) expected_ca=${2:-}; shift 2 ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done
[[ "$base_url" =~ ^https?:// ]] || usage
require_command curl

curl_opts=(--fail --silent --show-error --connect-timeout 5 --max-time 15)
curl "${curl_opts[@]}" "$base_url/health/live" >/dev/null
curl "${curl_opts[@]}" "$base_url/health/ready" >/dev/null
curl "${curl_opts[@]}" "$base_url/api/v1/auth/bootstrap-status" >/dev/null

if [[ -z "$username$password_file$expected_ca" ]]; then
  log "unauthenticated restore smoke passed"
  exit 0
fi
[[ -n "$username" && -n "$password_file" && -n "$expected_ca" ]] || usage
require_private_file "$password_file" "password file"
[[ -f "$expected_ca" && ! -L "$expected_ca" ]] || die "expected CA must be a regular non-symlink file"
require_command jq

work=$(mktemp -d "${TMPDIR:-/tmp}/frp-admin-smoke.XXXXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT INT TERM
jq -n --arg username "$username" --rawfile password "$password_file" \
  '{username:$username,password:($password | sub("[\\r\\n]+$"; ""))}' >"$work/login.json"
curl "${curl_opts[@]}" -c "$work/cookies" -H 'Content-Type: application/json' \
  --data-binary @"$work/login.json" "$base_url/api/v1/auth/login" >"$work/login-response.json"
jq -e '.id and .username and .role' "$work/login-response.json" >/dev/null
curl "${curl_opts[@]}" -b "$work/cookies" "$base_url/api/v1/users/me" | jq -e '.id and .role' >/dev/null
curl "${curl_opts[@]}" -b "$work/cookies" "$base_url/api/v1/system/agent-ca" >"$work/restored-ca.crt"
expected_fingerprint=$(openssl x509 -in "$expected_ca" -outform DER | openssl dgst -sha256 -r | awk '{print $1}')
actual_fingerprint=$(openssl x509 -in "$work/restored-ca.crt" -outform DER | openssl dgst -sha256 -r | awk '{print $1}')
[[ "$actual_fingerprint" == "$expected_fingerprint" ]] || die "restored Agent CA does not match the backup"

curl "${curl_opts[@]}" -b "$work/cookies" "$base_url/api/v1/nodes?limit=100" >"$work/nodes.json"
jq -e '.items | type == "array"' "$work/nodes.json" >/dev/null
while IFS= read -r node_id; do
  curl "${curl_opts[@]}" -b "$work/cookies" "$base_url/api/v1/nodes/$node_id/config-revisions?limit=1" >"$work/revisions.json"
  revision_id=$(jq -r '.items[0].id // empty' "$work/revisions.json")
  if [[ -n "$revision_id" ]]; then
    curl "${curl_opts[@]}" -b "$work/cookies" "$base_url/api/v1/config-revisions/$revision_id/content" | jq -e '.content | type == "string"' >/dev/null
    log "authenticated restore smoke passed, including config decryption"
    exit 0
  fi
done < <(jq -r '.items[].id' "$work/nodes.json")
log "authenticated restore smoke passed; no config revision existed to exercise decryption"
