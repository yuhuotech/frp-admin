#!/bin/sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname "$0")/../../.." && pwd)
image=${FRP_SYSTEMD_E2E_IMAGE:-frp-agent-systemd-e2e:local}
container="frp-agent-systemd-e2e-$$"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker build -f "$repo_root/deploy/e2e/systemd/Dockerfile" -t "$image" "$repo_root"
docker run -d --name "$container" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /run --tmpfs /run/lock "$image" >/dev/null

ready=false
for _ in $(seq 1 30); do
  state=$(docker exec "$container" systemctl is-system-running 2>/dev/null || true)
  case "$state" in
    running|degraded) ready=true; break ;;
  esac
  sleep 1
done

if [ "$ready" != true ]; then
  docker logs "$container"
  exit 1
fi

docker exec "$container" /opt/frp-admin-e2e/run.sh
