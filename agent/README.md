# frp-agent

The agent manages exactly one locally configured `frpc` or `frps` service. On
Linux it integrates with systemd; on macOS it integrates with the current
user's launchd GUI domain. The control protocol has no arbitrary command or
shell field.

## Development

```sh
go test ./...
go build ./cmd/frp-agent
```

Enrollment creates the private key locally and writes certificates plus the
assigned node ID under `stateDir`. A production installation should provision
the enrollment HTTPS CA through the host trust store before running:

```sh
frp-agent -config /etc/frp-agent/agent.yaml \
  -enroll-token ONE_TIME_TOKEN \
  -enroll-ca /etc/frp-agent/enrollment-ca.pem
```

`-enroll-ca` is required when the enrollment endpoint certificate is not
trusted by the host system roots. Copy this CA through a trusted provisioning
channel and verify it out of band; disabling TLS verification is not supported.

On Linux, the supplied systemd unit runs as the dedicated `frp-agent` user. Its systemd
writable-path allowlist is limited to `/var/lib/frp-agent`, `/etc/frp`, and
`/opt/frp/bin`, but the installer keeps the frp resource directories
`root:root 0755`; the allowlist does not bypass filesystem permissions. An
operator may explicitly configure a same-user deployment where frp also runs
as `frp-agent`. Configuration and upgrade capabilities are advertised only
when service identity, target ownership, parent-directory checks, and the
privileged service probe pass. The root helper derives exactly one unit from
its root-owned role allowlist and accepts only typed start, stop, and restart
operations; reset-failed is an internal start/restart step. Configuration
therefore requires `frpc.service` for a
client node and `frps.service` for a server node. Build a release bundle with
the Agent binary beside `packaging/install.sh`, or pass its path explicitly:

```sh
sudo ./packaging/install.sh /path/to/frp-agent /path/to/frp-agent-helper /path/to/helper.json
```

The installer requires a running systemd host, installs the Agent and helper
binaries and units, and does not overwrite `/etc/frp-agent/agent.yaml`.
The optional third argument installs the root-owned helper allowlist and enables
the socket-activated helper at `/run/frp-agent-helper.sock`. The helper accepts
only typed service operations, permission repair, and Admin API loopback
repair. It validates the connecting `frp-agent` UID with `SO_PEERCRED` and never
accepts a unit, path, argument vector, or shell command from the caller. Without
a valid helper, Linux service mutation and repair capabilities are not
advertised; `packaging/helper.example.json` is an operator-edited template.

On macOS, set `frp.serviceName` to the launchd label and optionally set
`frp.launchdPlistPath` to the user's LaunchAgent plist. The Agent must run as
the same user that owns the launchd service. It uses only fixed `launchctl`
operations (`print`, `enable`, `disable`, `kickstart`, `kill`, and `bootstrap`)
and never accepts a launchd label, path, or shell command from the control
plane.

Configuration apply is a local transaction: checksum and `frpc/frps verify -c`
run before replacement, the candidate is created beside the target file for an
atomic rename, and service or health failures restore the previous file. The
last ten local revisions are recorded under `stateDir/backups/config` and
`stateDir/config-state.json`.

frp upgrades accept HTTPS artifacts only. Every redirect host must appear in
`upgrade.allowedHosts`, compressed and extracted sizes are bounded, archive
paths and links are rejected, and only the binary matching the configured role
is selected. Version and current-config verification run before the service is stopped.
Failed starts or health checks restore the previous binary using an independent
cleanup timeout. On Linux, same-user installations may use `/opt/frp/bin/frpc`
or `/opt/frp/bin/frps`, matching the systemd unit's exact writable path. On
macOS, the configured frp binary must be owned and writable by the launchd
user; a root-owned Homebrew binary is intentionally not advertised as
upgradeable until it is moved into a user-owned path.

Client certificates are checked every 12 hours and rotated seven days before
expiry over the already authenticated mTLS stream. The new certificate must
retain the node DNS SAN and `spiffe://frp-admin/{role}/{nodeID}` URI SAN. CA
rotation is intentionally a separate, unsupported capability: a rotation
response carrying a different CA is rejected and the current keypair remains.

Runtime collection reads only the local frp Admin API through fixed endpoints;
it never executes a shell command and never accepts a URL from a control-plane
command. Configure Basic Auth, timeout, and response bounds locally:

```yaml
frp:
  adminAPI:
    endpoint: http://127.0.0.1:7400 # use the configured frps port for server nodes
    username: runtime-reader
    passwordFile: /run/credentials/frp-agent.service/frp-admin-api-password
    timeout: 3s
    maxResponseBytes: 1048576
```

Provision the file with a systemd `LoadCredential=` entry or another root-owned
regular file whose group/other permission bits are zero. The endpoint must use
a literal loopback IP. Credentials and raw Admin API
responses are not included in protocol results, logs, or diagnostics.

The agent also performs a read-only deployment security inspection immediately
after connecting and every five minutes. It reports typed findings, never raw
configuration or log lines, when a server Admin API listens on a non-loopback
address, a configuration containing `auth.token` has group/other permission
bits, or recent file/journald logs contain a proxy-name conflict. Configuration
input is capped at 16 MiB and recent log input at 1 MiB; inspection failure does
not interrupt the control channel or frp data plane.
