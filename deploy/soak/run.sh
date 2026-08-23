#!/usr/bin/env bash
set -uo pipefail
umask 077

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/../.." && pwd)
agents=${SOAK_AGENTS:-100}
duration=${SOAK_DURATION:-168h}
sample_interval=${SOAK_SAMPLE_INTERVAL:-60}
http_url=${SOAK_HTTP_URL:-http://127.0.0.1:8080}
grpc_url=${SOAK_GRPC_URL:-https://127.0.0.1:8443}
metrics_url=${SOAK_METRICS_URL:-http://127.0.0.1:9090/metrics}
server_name=${SOAK_SERVER_NAME:-localhost}
username=${SOAK_USERNAME:-soak-admin}
password_file=${SOAK_PASSWORD_FILE:-}
bootstrap_token_file=${SOAK_BOOTSTRAP_TOKEN_FILE:-}
reconnect_after=${SOAK_RECONNECT_AFTER:-5m}
concurrency=${SOAK_CONCURRENCY:-20}
task_concurrency=${SOAK_TASK_CONCURRENCY:-100}
task_interval=${SOAK_TASK_INTERVAL:-30s}

for command in curl go jq ps; do command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 2; }; done
[[ "$agents" =~ ^[0-9]+$ && "$agents" -gt 0 ]] || { echo "SOAK_AGENTS must be positive" >&2; exit 2; }
[[ "$sample_interval" =~ ^[0-9]+$ && "$sample_interval" -gt 0 ]] || { echo "SOAK_SAMPLE_INTERVAL must be integer seconds" >&2; exit 2; }

server_pid=${SOAK_SERVER_PID:-}
if [[ -n ${SOAK_SERVER_CONTAINER:-} ]]; then
  command -v docker >/dev/null || { echo "docker is required for SOAK_SERVER_CONTAINER" >&2; exit 2; }
  server_pid=$(docker inspect --format '{{.State.Pid}}' "$SOAK_SERVER_CONTAINER") || exit 2
fi
[[ "$server_pid" =~ ^[0-9]+$ ]] && kill -0 "$server_pid" 2>/dev/null || {
  echo "set SOAK_SERVER_PID or SOAK_SERVER_CONTAINER to a running Linux server target" >&2
  exit 2
}

if [[ -n ${SOAK_OUTPUT_DIR:-} ]]; then
  output_dir=$SOAK_OUTPUT_DIR
  [[ ! -e "$output_dir" ]] || { echo "SOAK_OUTPUT_DIR already exists: $output_dir" >&2; exit 2; }
  mkdir -p "$output_dir"
else
  mkdir -p "$repo_root/soak-results"
  output_dir=$(mktemp -d "$repo_root/soak-results/run.XXXXXXXX")
fi
output_dir=$(cd "$output_dir" && pwd)
stop_file="$output_dir/.stop"
load_binary="$output_dir/frp-agent-load"
samples="$output_dir/samples.csv"
load_json="$output_dir/load.json"
load_stderr="$output_dir/load.stderr.log"
report="$output_dir/report.md"
credential_dir="$output_dir/credentials"

sampler_pid=''
load_pid=''
cleanup() {
  touch "$stop_file"
  [[ -z "$load_pid" ]] || kill "$load_pid" 2>/dev/null || true
  [[ -z "$sampler_pid" ]] || wait "$sampler_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

(
  cd "$repo_root/agent"
  GOWORK=off go build -trimpath -o "$load_binary" ./cmd/frp-agent-load
) || exit 1

mkdir -m 0700 "$credential_dir"
if [[ -z "$password_file" ]]; then
  [[ -n ${SOAK_PASSWORD:-} ]] || { echo "set SOAK_PASSWORD_FILE or SOAK_PASSWORD" >&2; exit 2; }
  password_file="$credential_dir/password"
  printf '%s\n' "$SOAK_PASSWORD" >"$password_file"
  chmod 0600 "$password_file"
fi
if [[ -z "$bootstrap_token_file" && -n ${SOAK_BOOTSTRAP_TOKEN:-} ]]; then
  bootstrap_token_file="$credential_dir/bootstrap-token"
  printf '%s\n' "$SOAK_BOOTSTRAP_TOKEN" >"$bootstrap_token_file"
  chmod 0600 "$bootstrap_token_file"
fi

"$script_dir/sample.sh" "$server_pid" "$metrics_url" "$samples" "$sample_interval" "$stop_file" &
sampler_pid=$!
start_epoch=$(date +%s)
load_args=(
  -http-url "$http_url" -grpc-url "$grpc_url" -server-name "$server_name"
  -username "$username" -password-file "$password_file" -agents "$agents" -concurrency "$concurrency"
  -task-concurrency "$task_concurrency" -task-interval "$task_interval"
  -duration "$duration" -reconnect-after "$reconnect_after" -state-dir "$output_dir/agent-state"
)
[[ -z "$bootstrap_token_file" ]] || load_args+=(-bootstrap-token-file "$bootstrap_token_file")
"$load_binary" "${load_args[@]}" >"$load_json" 2>"$load_stderr" &
load_pid=$!
wait "$load_pid"
load_exit=$?
load_pid=''
end_epoch=$(date +%s)
touch "$stop_file"
wait "$sampler_pid"
sampler_exit=$?
sampler_pid=''
actual_seconds=$((end_epoch - start_epoch))
((sampler_exit == 0)) || load_exit=1

if [[ -z ${SOAK_REQUIRE_168H+x} ]]; then
  if [[ "$duration" == 168h ]]; then export SOAK_REQUIRE_168H=true; else export SOAK_REQUIRE_168H=false; fi
fi
if "$script_dir/analyze.sh" "$samples" "$load_json" "$actual_seconds" "$agents" "$load_exit" "$report"; then
  echo "soak gate passed: $report"
  exit 0
fi
echo "soak gate failed: $report" >&2
exit 1
