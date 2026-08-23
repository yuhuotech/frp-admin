#!/bin/sh
set -eu

install -d -o root -g frp-agent -m 0750 /etc/frp-agent
install -d -o frp-agent -g frp-agent -m 0700 /var/lib/frp-agent /var/lib/frp-agent/pki
install -d -o root -g root -m 0700 /var/lib/frp-agent-helper
install -d -o root -g root -m 0755 /etc/frp
install -d -o frp-agent -g frp-agent -m 0700 /run/frp-admin-e2e

cat >/etc/frp/frpc.toml <<'EOF'
serverAddr = "127.0.0.1"
serverPort = 65534
loginFailExit = false
EOF
chown root:root /etc/frp/frpc.toml
chmod 0640 /etc/frp/frpc.toml

cat >/etc/frp-agent/helper.json <<'EOF'
{"Role":"client","BinaryPath":"/opt/frp/bin/frpc","ConfigPath":"/etc/frp/frpc.toml","ServiceName":"frpc.service","StateDir":"/var/lib/frp-agent-helper"}
EOF
chown root:root /etc/frp-agent/helper.json
chmod 0600 /etc/frp-agent/helper.json

openssl ecparam -name prime256v1 -genkey -noout -out /var/lib/frp-agent/pki/ca-key.pem
openssl req -x509 -new -key /var/lib/frp-agent/pki/ca-key.pem -sha256 -days 30 \
  -subj '/CN=frp-e2e-ca' -out /var/lib/frp-agent/pki/ca.pem
openssl ecparam -name prime256v1 -genkey -noout -out /var/lib/frp-agent/pki/client-key.pem
openssl req -new -key /var/lib/frp-agent/pki/client-key.pem -subj '/CN=e2e-node' -out /tmp/client.csr
openssl x509 -req -in /tmp/client.csr -CA /var/lib/frp-agent/pki/ca.pem \
  -CAkey /var/lib/frp-agent/pki/ca-key.pem -CAcreateserial -days 30 -sha256 \
  -out /var/lib/frp-agent/pki/client.pem
rm -f /tmp/client.csr /var/lib/frp-agent/pki/ca.srl
chmod 0600 /var/lib/frp-agent/pki/*
chown -R frp-agent:frp-agent /var/lib/frp-agent

cat >/etc/frp-agent/agent.yaml <<'EOF'
serverURL: https://127.0.0.1:65535
role: client
nodeID: e2e-node
stateDir: /var/lib/frp-agent
tls:
  caFile: /var/lib/frp-agent/pki/ca.pem
  certFile: /var/lib/frp-agent/pki/client.pem
  keyFile: /var/lib/frp-agent/pki/client-key.pem
  serverName: localhost
frp:
  serviceName: frpc.service
  binaryPath: /opt/frp/bin/frpc
  configPath: /etc/frp/frpc.toml
  helperSocket: /run/frp-agent-helper.sock
upgrade:
  allowedHosts: [127.0.0.1]
  maxArtifactBytes: 268435456
EOF
chown root:frp-agent /etc/frp-agent/agent.yaml
chmod 0640 /etc/frp-agent/agent.yaml

systemctl daemon-reload
systemctl enable frpc.service frp-agent.service frp-agent-helper.socket
systemctl start frp-agent-helper.socket
systemctl restart frpc.service
systemctl restart frp-agent.service
