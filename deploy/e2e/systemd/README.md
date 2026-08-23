# Agent systemd E2E

This suite runs the production Agent adapters against PID 1 systemd and the
official `frpc` binary in Ubuntu 24.04. The image pins frp `v0.70.0` and verifies
the published SHA256 for both `linux/amd64` and `linux/arm64` before installing
it.

## Run

The host needs Docker, cgroup v2, and permission to start privileged
containers:

```sh
./deploy/e2e/systemd/run-container.sh
```

Equivalent self-hosted runner command:

```sh
docker build -f deploy/e2e/systemd/Dockerfile -t frp-agent-systemd-e2e .
docker run -d --name frp-agent-e2e --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  frp-agent-systemd-e2e
docker exec frp-agent-e2e /opt/frp-admin-e2e/run.sh
```

## Coverage

- real systemd status, start, stop, and restart;
- valid config apply and invalid `frpc verify` rejection;
- start failure with automatic old-config restoration;
- concurrent mutation rejection by the Agent executor;
- local TLS artifact upgrade, checksum rejection, and start-failure rollback;
- process restart recovery from config and binary transaction journals;
- runtime checks for `NoNewPrivileges`, `ProtectSystem=strict`, and exact writable
  paths required by config/binary transactions.

The fixture runs Agent as `frp-agent`. Resource transactions are enabled only
when the frp service and safely owned files use that same non-root identity;
typed start, stop, and restart operations go through the root helper. The Agent
unit removes ambient privilege escalation and makes the filesystem read-only
except for `/var/lib/frp-agent`, `/etc/frp`, and `/opt/frp/bin`. Deployments using
another binary directory require a corresponding fixed helper allowlist and
unit sandbox rather than a YAML-only path change.

## Environment and limits

The suite was executed on Docker Engine 29.2.1 in Colima, Linux arm64, cgroup
v2, from a macOS arm64 host. GitHub-hosted Linux runners normally support the
same privileged-container command; if an organization disables privileged
Docker, run the exact script on a self-hosted runner labelled for systemd E2E.

This suite does not exercise a real control-plane gRPC connection, a
non-container VM boot, or kernel-level fault injection
during the individual `rename(2)` instruction. The transaction recovery cases
materialize the same durable journal and partial target state, then restart the
real Agent service.
