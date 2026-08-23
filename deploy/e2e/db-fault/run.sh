#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname "$0")/../../.." && pwd)
suffix=$$
network="frp-db-fault-$suffix"
postgres="frp-db-fault-postgres-$suffix"
server="frp-db-fault-server-$suffix"
agent="frp-db-fault-agent-$suffix"
backend="frp-db-fault-backend-$suffix"
data_volume="frp-db-fault-data-$suffix"
server_image="frp-admin-server-db-fault:$suffix"
agent_image="frp-agent-db-fault:$suffix"

cleanup() {
  docker rm -f "$agent" "$server" "$postgres" "$backend" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  docker volume rm "$data_volume" >/dev/null 2>&1 || true
  docker image rm "$server_image" "$agent_image" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker build -f "$repo_root/server/Dockerfile" -t "$server_image" "$repo_root"
docker build -f "$repo_root/deploy/e2e/systemd/Dockerfile" -t "$agent_image" "$repo_root"
docker network create "$network" >/dev/null
docker volume create "$data_volume" >/dev/null
docker run -d --name "$postgres" --network "$network" --network-alias postgres \
  -e POSTGRES_DB=frpadmin -e POSTGRES_USER=frpadmin -e POSTGRES_PASSWORD=frpadmin \
  postgres:16-alpine >/dev/null
docker run -d --name "$backend" --network "$network" --network-alias backend \
  busybox:1.37 sh -c 'mkdir -p /www && echo frp-db-fault-data-plane-ok >/www/index.html && exec httpd -f -p 8080 -h /www' >/dev/null

postgres_ready=false
for _ in $(seq 1 60); do
  if docker exec "$postgres" pg_isready -U frpadmin -d frpadmin >/dev/null 2>&1; then
    postgres_ready=true
    break
  fi
  sleep 1
done
if [ "$postgres_ready" != true ]; then
  docker logs "$postgres"
  exit 1
fi

docker create --name "$server" --network "$network" --network-alias control \
  -v "$data_volume:/app/data" "$server_image" -config /app/server-db-fault.yaml >/dev/null
docker cp "$repo_root/deploy/e2e/db-fault/server.yaml" "$server:/app/server-db-fault.yaml"
docker start "$server" >/dev/null

server_ready=false
for _ in $(seq 1 30); do
  if docker exec "$server" wget -q -O /dev/null http://127.0.0.1:8080/health/ready 2>/dev/null; then
    server_ready=true
    break
  fi
  sleep 1
done
if [ "$server_ready" != true ]; then
  docker logs "$server"
  exit 1
fi

docker run -d --name "$agent" --hostname db-fault-agent --network "$network" \
  --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /run --tmpfs /run/lock "$agent_image" >/dev/null
systemd_ready=false
for _ in $(seq 1 30); do
  state=$(docker exec "$agent" systemctl is-system-running 2>/dev/null || true)
  case "$state" in
    running|degraded) systemd_ready=true; break ;;
  esac
  sleep 1
done
if [ "$systemd_ready" != true ]; then
  docker logs "$agent"
  exit 1
fi

run_agent_test() {
  test_name=$1
  docker exec \
    -e FRP_DB_FAULT_E2E=1 \
    -e FRP_CONTROLPLANE_HTTP=http://control:8080 \
    -e FRP_CONTROLPLANE_GRPC=https://control:8443 \
    "$agent" /usr/local/bin/frp-agent-systemd-e2e -test.run "^$test_name$" -test.v -test.timeout 2m
}

run_agent_test TestDatabaseFaultSetup

server_id_before=$(docker inspect -f '{{.Id}}' "$server")
docker stop "$postgres" >/dev/null
docker exec "$agent" systemctl start frp-agent.service
run_agent_test TestDatabaseFaultDuringOutage

docker start "$postgres" >/dev/null
postgres_ready=false
for _ in $(seq 1 60); do
  if docker exec "$postgres" pg_isready -U frpadmin -d frpadmin >/dev/null 2>&1; then
    postgres_ready=true
    break
  fi
  sleep 1
done
if [ "$postgres_ready" != true ]; then
  docker logs "$postgres"
  exit 1
fi

server_ready=false
for _ in $(seq 1 30); do
  if docker exec "$server" wget -q -O /dev/null http://127.0.0.1:8080/health/ready 2>/dev/null; then
    server_ready=true
    break
  fi
  sleep 1
done
if [ "$server_ready" != true ]; then
  docker logs "$server"
  exit 1
fi
test "$(docker inspect -f '{{.Id}}' "$server")" = "$server_id_before"

run_agent_test TestDatabaseFaultRecovered

task_count=$(docker exec "$postgres" psql -U frpadmin -d frpadmin -Atc \
  "SELECT COUNT(*) FROM tasks WHERE idempotency_key = 'db-fault-outage-runtime-collection'")
test "$task_count" = 0

queued_count=$(docker exec "$postgres" psql -U frpadmin -d frpadmin -Atc \
  "SELECT COUNT(*) FROM tasks WHERE type = 'collect_runtime' AND state = 'succeeded'")
test "$queued_count" = 1

printf '%s\n' 'PostgreSQL fault injection PASS: readiness=503, runtime mutation rejected, frp data plane continuous, Server recovered without restart, Agent reconnected, capability-checked queued runtime task succeeded exactly once.'
