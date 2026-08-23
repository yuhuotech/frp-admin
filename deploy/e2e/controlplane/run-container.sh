#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname "$0")/../../.." && pwd)
server_image=${FRP_CONTROLPLANE_SERVER_IMAGE:-frp-admin-server-e2e:local}
agent_image=${FRP_CONTROLPLANE_AGENT_IMAGE:-frp-agent-systemd-e2e:local}
network="frp-controlplane-e2e-$$"
data_volume="frp-controlplane-data-$$"
restored_volume="frp-controlplane-restored-$$"
server="frp-controlplane-server-$$"
agent="frp-controlplane-agent-$$"
postgres="frp-controlplane-postgres-$$"
mysql="frp-controlplane-mysql-$$"
restore_helper="frp-controlplane-restore-helper-$$"
database_driver=${FRP_CONTROLPLANE_DATABASE_DRIVER:-sqlite}
stats_file=$(mktemp)
restore_work=$(mktemp -d)
stats_pid=""

cleanup() {
  if [ -n "$stats_pid" ]; then
    kill "$stats_pid" >/dev/null 2>&1 || true
    wait "$stats_pid" >/dev/null 2>&1 || true
  fi
  rm -f "$stats_file"
  rm -rf "$restore_work"
  docker rm -f "$agent" "$server" "$postgres" "$mysql" "$restore_helper" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$data_volume" >/dev/null 2>&1 || true
  docker volume rm "$restored_volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker build -f "$repo_root/server/Dockerfile" -t "$server_image" "$repo_root"
docker build -f "$repo_root/deploy/e2e/systemd/Dockerfile" -t "$agent_image" "$repo_root"
docker network create "$network" >/dev/null
docker volume create "$data_volume" >/dev/null
docker run --rm --user 0 --entrypoint sh -v "$data_volume:/app/data" "$server_image" -c '
  install -d -o frpadmin -g frpadmin -m 0700 /app/data /app/data/keys
  dd if=/dev/urandom of=/app/data/keys/old.key bs=32 count=1 status=none
  dd if=/dev/urandom of=/app/data/keys/new.key bs=32 count=1 status=none
  chown frpadmin:frpadmin /app/data/keys/*.key
  chmod 0600 /app/data/keys/*.key
'
if [ "$database_driver" = mysql ]; then
  docker run -d --name "$mysql" --network "$network" --network-alias mysql \
    -e MYSQL_DATABASE=frpadmin -e MYSQL_USER=frpadmin -e MYSQL_PASSWORD=frpadmin \
    -e MYSQL_ROOT_PASSWORD=controlplane-e2e-root mysql:8.4 >/dev/null
  ready=false
  for _ in $(seq 1 90); do
    if docker exec "$mysql" mysqladmin ping -h 127.0.0.1 -uroot -pcontrolplane-e2e-root --silent >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 1
  done
  if [ "$ready" != true ]; then
    docker logs "$mysql"
    exit 1
  fi
  docker create --name "$server" --network "$network" --network-alias control \
    -v "$data_volume:/app/data" \
    -e FRP_ADMIN_DATABASE_DRIVER=mysql \
    -e 'FRP_ADMIN_DATABASE_DSN=frpadmin:frpadmin@tcp(mysql:3306)/frpadmin?parseTime=true' \
    "$server_image" -config /app/server-e2e.yaml >/dev/null
elif [ "$database_driver" = postgres ]; then
  docker run -d --name "$postgres" --network "$network" --network-alias postgres \
    -e POSTGRES_DB=frpadmin -e POSTGRES_USER=frpadmin -e POSTGRES_PASSWORD=frpadmin \
    postgres:16-alpine >/dev/null
  ready=false
  for _ in $(seq 1 60); do
    if docker exec "$postgres" pg_isready -U frpadmin -d frpadmin >/dev/null 2>&1; then
      ready=true
      break
    fi
    sleep 1
  done
  if [ "$ready" != true ]; then
    docker logs "$postgres"
    exit 1
  fi
  docker create --name "$server" --network "$network" --network-alias control \
    -v "$data_volume:/app/data" \
    -e FRP_ADMIN_DATABASE_DRIVER=postgres \
    -e "FRP_ADMIN_DATABASE_DSN=postgres://frpadmin:frpadmin@postgres:5432/frpadmin?sslmode=disable" \
    "$server_image" -config /app/server-e2e.yaml >/dev/null
elif [ "$database_driver" = sqlite ]; then
  docker create --name "$server" --network "$network" --network-alias control \
    -v "$data_volume:/app/data" \
    "$server_image" -config /app/server-e2e.yaml >/dev/null
else
  echo "unsupported FRP_CONTROLPLANE_DATABASE_DRIVER=$database_driver" >&2
  exit 1
fi
docker cp "$repo_root/deploy/e2e/controlplane/server.yaml" "$server:/app/server-e2e.yaml"
docker start "$server" >/dev/null

ready=false
for _ in $(seq 1 30); do
  if docker exec "$server" wget -q -O /dev/null http://127.0.0.1:8080/api/v1/auth/bootstrap-status 2>/dev/null; then
    ready=true
    break
  fi
  sleep 1
done
if [ "$ready" != true ]; then
  docker logs "$server"
  exit 1
fi

docker run -d --name "$agent" --hostname controlplane-agent --network "$network" \
  --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -v "$data_volume:/control-data:ro" \
  --tmpfs /run --tmpfs /run/lock "$agent_image" >/dev/null
ready=false
for _ in $(seq 1 30); do
  state=$(docker exec "$agent" systemctl is-system-running 2>/dev/null || true)
  case "$state" in
    running|degraded) ready=true; break ;;
  esac
  sleep 1
done
if [ "$ready" != true ]; then
  docker logs "$agent"
  exit 1
fi

if ! docker exec \
  -e FRP_CONTROLPLANE_E2E=1 \
  -e FRP_CONTROLPLANE_HTTP=http://control:8080 \
  -e FRP_CONTROLPLANE_GRPC=https://control:8443 \
  "$agent" /usr/local/bin/frp-agent-systemd-e2e -test.run '^TestControlPlane$' -test.v -test.timeout 2m; then
  docker exec "$agent" journalctl -u frp-agent.service -u frp-agent-helper.service --no-pager -n 100 || true
  docker logs "$server" || true
  exit 1
fi

if [ "$database_driver" = sqlite ]; then
  mkdir -m 0700 "$restore_work/source" "$restore_work/restored"
  docker stop "$server" >/dev/null
  docker cp "$server:/app/data/." "$restore_work/source"
  "$repo_root/deploy/ops/backup.sh" --driver sqlite \
    --sqlite-path "$restore_work/source/frp-admin.db" \
    --master-key "$restore_work/source/keys/new.key" \
    --key-version "old=$restore_work/source/keys/old.key" \
    --key-version "new=$restore_work/source/keys/new.key" \
    --pki-dir "$restore_work/source/pki" --output "$restore_work/backup.tar"
  "$repo_root/deploy/ops/restore.sh" --archive "$restore_work/backup.tar" \
    --sqlite-target "$restore_work/restored/frp-admin.db" \
    --master-key-target "$restore_work/restored/master.key" \
    --pki-target "$restore_work/restored/pki" \
    --keyring-target "$restore_work/restored/keyring"
  docker rm "$server" >/dev/null
  docker volume create "$restored_volume" >/dev/null
  docker create --name "$restore_helper" --user 0 --entrypoint sh \
    -v "$restored_volume:/app/data" "$server_image" -c \
    'chown -R frpadmin:frpadmin /app/data && chmod 0700 /app/data /app/data/pki /app/data/keyring' >/dev/null
  docker cp "$restore_work/restored/." "$restore_helper:/app/data"
  docker start -a "$restore_helper" >/dev/null
  docker rm "$restore_helper" >/dev/null
  docker create --name "$server" --network "$network" --network-alias control \
    -v "$restored_volume:/app/data" \
    "$server_image" -config /app/server-restored.yaml >/dev/null
  docker cp "$repo_root/deploy/e2e/controlplane/server-restored.yaml" "$server:/app/server-restored.yaml"
  docker start "$server" >/dev/null
else
  docker restart "$server" >/dev/null
fi
ready=false
for _ in $(seq 1 30); do
  if docker exec "$server" wget -q -O /dev/null http://127.0.0.1:8080/api/v1/auth/bootstrap-status 2>/dev/null; then
    ready=true
    break
  fi
  sleep 1
done
if [ "$ready" != true ]; then
  docker logs "$server"
  exit 1
fi
docker exec \
  -e FRP_CONTROLPLANE_E2E=1 \
  -e FRP_CONTROLPLANE_HTTP=http://control:8080 \
  -e FRP_CONTROLPLANE_GRPC=https://control:8443 \
  "$agent" /usr/local/bin/frp-agent-systemd-e2e -test.run '^TestControlPlaneAfterServerRestart$' -test.v -test.timeout 1m

(
  while docker inspect "$server" >/dev/null 2>&1; do
    docker stats --no-stream --format '{{.CPUPerc}} {{.MemUsage}}' "$server" 2>/dev/null >>"$stats_file" || true
    sleep 1
  done
) &
stats_pid=$!

printf '%s\n' 'controlplane-e2e-password' | docker exec -i "$agent" sh -c \
  'umask 077; install -d -m 0700 /var/lib/frp-agent-load-credentials; cat > /var/lib/frp-agent-load-credentials/password'
docker exec "$agent" /usr/local/bin/frp-agent-load \
  -http-url http://control:8080 -grpc-url https://control:8443 -server-name control \
  -username admin -password-file /var/lib/frp-agent-load-credentials/password \
  -state-dir /var/lib/frp-agent-load \
  -agents "${FRP_CONTROLPLANE_LOAD_AGENTS:-25}" -concurrency 10 \
  -task-concurrency "${FRP_CONTROLPLANE_TASK_CONCURRENCY:-100}" \
  -task-interval "${FRP_CONTROLPLANE_TASK_INTERVAL:-0s}" \
  -heartbeat 1s -reconnect-after 2s -duration 6s

kill "$stats_pid" >/dev/null 2>&1 || true
wait "$stats_pid" >/dev/null 2>&1 || true
stats_pid=""
awk '
  function mib(value, number) {
    number = value
    if (sub(/GiB$/, "", number)) return number * 1024
    if (sub(/MiB$/, "", number)) return number
    if (sub(/KiB$/, "", number)) return number / 1024
    if (sub(/B$/, "", number)) return number / 1048576
    return 0
  }
  {
    gsub(/%$/, "", $1)
    memory = mib($2)
    if ($1 > peakCPU) peakCPU = $1
    if (memory > peakMemory) peakMemory = memory
    samples++
  }
  END { printf "server_resource_samples=%d peak_cpu_percent=%.2f peak_memory_mib=%.2f\n", samples, peakCPU, peakMemory }
' "$stats_file"
