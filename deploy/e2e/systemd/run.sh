#!/bin/sh
set -eu

/opt/frp-admin-e2e/setup.sh
systemctl is-active --quiet frpc.service
systemctl is-active --quiet frp-agent.service
systemctl is-active --quiet frp-agent-helper.socket

test "$(systemctl show frp-agent.service -p NoNewPrivileges --value)" = "yes"
test "$(systemctl show frp-agent.service -p ProtectSystem --value)" = "strict"
test "$(systemctl show frp-agent.service -p User --value)" = "frp-agent"
systemctl cat frp-agent.service | grep -q 'ReadWritePaths=/var/lib/frp-agent /etc/frp /opt/frp/bin'
test "$(stat -c '%U:%G:%a' /etc/frp)" = "root:root:755"
test "$(stat -c '%U:%G:%a' /opt/frp)" = "root:root:755"
test "$(stat -c '%U:%G:%a' /opt/frp/bin)" = "root:root:755"
if runuser -u frp-agent -- sh -c 'mv /etc/frp/frpc.toml /etc/frp/frpc.toml.replaced' 2>/dev/null; then
  echo "frp-agent unexpectedly replaced root-owned configuration" >&2
  exit 1
fi
if runuser -u frp-agent -- sh -c 'mv /opt/frp/bin/frpc /opt/frp/bin/frpc.replaced' 2>/dev/null; then
  echo "frp-agent unexpectedly replaced root-owned binary" >&2
  exit 1
fi
FRP_SYSTEMD_E2E=1 /usr/local/bin/frp-agent-systemd-e2e -test.run 'Test0(1|2|3|4|5|6)' -test.v
runuser -u frp-agent -- env FRP_SYSTEMD_E2E=1 \
  /usr/local/bin/frp-agent-systemd-e2e -test.run 'Test0(7|8)' -test.v

systemctl stop frp-agent-helper.service frp-agent-helper.socket
cat >/etc/frp/frps.toml <<'EOF'
bindAddr = "127.0.0.1"
bindPort = 17000
webServer.addr = "0.0.0.0"
webServer.port = 17500
EOF
chown root:root /etc/frp/frps.toml
chmod 0600 /etc/frp/frps.toml
cat >/etc/frp-agent/helper.json <<'EOF'
{"Role":"server","BinaryPath":"/opt/frp/bin/frps","ConfigPath":"/etc/frp/frps.toml","ServiceName":"frps.service","StateDir":"/var/lib/frp-agent-helper"}
EOF
chmod 0600 /etc/frp-agent/helper.json
systemctl start frps.service frp-agent-helper.socket
runuser -u frp-agent -- env FRP_SYSTEMD_E2E=1 \
  /usr/local/bin/frp-agent-systemd-e2e -test.run 'Test(09|10)' -test.v
