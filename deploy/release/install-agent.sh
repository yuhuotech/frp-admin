#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "install.sh must run as root" >&2
  exit 1
fi

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

install -o root -g root -m 0755 "$package_dir/frp-agent" /usr/local/bin/frp-agent
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 "$package_dir/frp-agent-helper" /usr/local/libexec/frp-agent-helper

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
if [ ! -e /etc/frp-agent/agent.yaml ]; then
  install -o root -g frp-agent -m 0640 "$package_dir/config.example.yaml" /etc/frp-agent/agent.yaml
fi
install -o root -g root -m 0644 "$package_dir/systemd/frp-agent.service" /etc/systemd/system/frp-agent.service
install -o root -g root -m 0644 "$package_dir/systemd/frp-agent-helper.service" /etc/systemd/system/frp-agent-helper.service
install -o root -g root -m 0644 "$package_dir/systemd/frp-agent-helper.socket" /etc/systemd/system/frp-agent-helper.socket
install -o root -g root -m 0600 "$package_dir/helper.example.json" /etc/frp-agent/helper.json.example

systemctl daemon-reload
echo "frp-agent installed; edit agent.yaml and root-owned helper.json, enroll it, then enable the agent and helper socket"
