#!/usr/bin/env bash
set -euo pipefail
umask 022

usage() {
  echo "usage: build-binaries.sh VERSION OUTPUT_DIRECTORY" >&2
  exit 2
}

[[ $# == 2 ]] || usage
version=$1
output_dir=$2
[[ "$version" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([+-][A-Za-z0-9._-]+)?$ ]] || {
  echo "invalid release version: $version" >&2
  exit 2
}
[[ ! -e "$output_dir" ]] || {
  echo "output already exists: $output_dir" >&2
  exit 2
}

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/../.." && pwd)
display_version=${version#v}
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT
mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)

for arch in amd64 arm64; do
  agent_root="$work_dir/frp-agent_${display_version}_linux_${arch}"
  server_root="$work_dir/frp-admin-server_${display_version}_linux_${arch}"
  mkdir -p "$agent_root/systemd" "$server_root/systemd"

  (
    cd "$repo_root/agent"
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOWORK=off go build -trimpath \
      -ldflags="-s -w -X main.version=$version" -o "$agent_root/frp-agent" ./cmd/frp-agent
  )
  (
    cd "$repo_root/agent"
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOWORK=off go build -trimpath \
      -ldflags="-s -w -X main.version=$version" -o "$agent_root/frp-agent-helper" ./cmd/frp-agent-helper
  )
  install -m 0644 "$repo_root/agent/config.example.yaml" "$agent_root/config.example.yaml"
  install -m 0644 "$repo_root/agent/README.md" "$agent_root/README.md"
  install -m 0755 "$script_dir/install-agent.sh" "$agent_root/install.sh"
  install -m 0644 "$repo_root/agent/packaging/systemd/frp-agent.service" "$agent_root/systemd/frp-agent.service"
  install -m 0644 "$repo_root/agent/packaging/systemd/frp-agent-helper.service" "$agent_root/systemd/frp-agent-helper.service"
  install -m 0644 "$repo_root/agent/packaging/systemd/frp-agent-helper.socket" "$agent_root/systemd/frp-agent-helper.socket"
  install -m 0600 "$repo_root/agent/packaging/helper.example.json" "$agent_root/helper.example.json"

  (
    cd "$repo_root/server"
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOWORK=off go build -trimpath \
      -ldflags="-s -w -X main.version=$version" -o "$server_root/frp-admin-server" ./cmd/frp-admin-server
  )
  install -m 0644 "$repo_root/server/config.example.yaml" "$server_root/config.example.yaml"
  install -m 0644 "$repo_root/deploy/systemd/frp-admin-server.service" "$server_root/systemd/frp-admin-server.service"

  tar -C "$work_dir" -czf "$output_dir/$(basename "$agent_root").tar.gz" "$(basename "$agent_root")"
  tar -C "$work_dir" -czf "$output_dir/$(basename "$server_root").tar.gz" "$(basename "$server_root")"
done

echo "release archives created in $output_dir"
