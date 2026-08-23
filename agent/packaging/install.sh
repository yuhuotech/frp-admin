#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "frp-agent installer must run as root" >&2
  exit 1
fi

for command_name in getent groupadd useradd install systemctl; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required command is missing: $command_name" >&2
    exit 1
  fi
done

script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
agent_binary=${1:-"$script_dir/frp-agent"}
helper_binary=${2:-"$script_dir/frp-agent-helper"}
helper_config=${3:-}
unit_source="$script_dir/systemd/frp-agent.service"
helper_service_source="$script_dir/systemd/frp-agent-helper.service"
helper_socket_source="$script_dir/systemd/frp-agent-helper.socket"
helper_example_source="$script_dir/helper.example.json"
for source_file in "$agent_binary" "$helper_binary" "$unit_source" "$helper_service_source" "$helper_socket_source" "$helper_example_source"; do
  if [ ! -f "$source_file" ] || [ -L "$source_file" ]; then
    echo "required regular bundle file is missing or is a symlink: $source_file" >&2
    exit 1
  fi
done
if [ ! -x "$agent_binary" ] || [ ! -x "$helper_binary" ]; then
  echo "frp-agent binaries must be executable" >&2
  exit 1
fi
if [ ! -d /run/systemd/system ]; then
  echo "systemd is not running as the host init system" >&2
  exit 1
fi
if ! getent group frp-agent >/dev/null 2>&1; then
  groupadd --system frp-agent
fi
if ! getent passwd frp-agent >/dev/null 2>&1; then
  useradd --system --gid frp-agent --home-dir /var/lib/frp-agent \
    --shell /usr/sbin/nologin frp-agent
fi

install -d -o root -g frp-agent -m 0750 /etc/frp-agent
install -d -o frp-agent -g frp-agent -m 0700 /var/lib/frp-agent /var/lib/frp-agent/pki
install -d -o root -g root -m 0700 /var/lib/frp-agent-helper
install -d -o root -g root -m 0755 /etc/frp /opt/frp /opt/frp/bin
install -o root -g root -m 0755 "$agent_binary" /usr/local/bin/frp-agent
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 "$helper_binary" /usr/local/libexec/frp-agent-helper
install -o root -g root -m 0644 "$unit_source" /etc/systemd/system/frp-agent.service
install -o root -g root -m 0644 "$helper_service_source" /etc/systemd/system/frp-agent-helper.service
install -o root -g root -m 0644 "$helper_socket_source" /etc/systemd/system/frp-agent-helper.socket
install -o root -g root -m 0600 "$helper_example_source" /etc/frp-agent/helper.json.example
if [ -n "$helper_config" ]; then
  if [ ! -f "$helper_config" ] || [ -L "$helper_config" ]; then
    echo "helper config must be a regular non-symlink file" >&2
    exit 1
  fi
  install -o root -g root -m 0600 "$helper_config" /etc/frp-agent/helper.json
fi
systemctl daemon-reload
if [ -f /etc/frp-agent/helper.json ]; then
  systemctl enable --now frp-agent-helper.socket
fi
