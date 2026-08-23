# Real control-plane E2E

This fixture starts the production Server and a privileged Ubuntu 24.04
systemd container on one Docker network. It exercises the public HTTP API,
real gRPC enrollment, the mTLS Agent stream, heartbeats, service actions,
configuration deployment, and rollback.

After the systemd workflow, the script also runs a 25-Agent reconnect-wave
smoke load by default. Override the count with
`FRP_CONTROLPLANE_LOAD_AGENTS`. The load process prints JSON metrics for
session success/failure, heartbeats, peak active sessions, Welcome latency,
and reconnect latency (p50/p95/p99).
Set `FRP_CONTROLPLANE_TASK_INTERVAL` (for example `1s`) to add mixed
`inspect`/`collect_runtime` task waves. `FRP_CONTROLPLANE_TASK_CONCURRENCY`
defaults to 100; task created/succeeded/failed/timeout counts and latency
percentiles are included in the JSON report.

Run from the repository root:

```sh
./deploy/e2e/controlplane/run-container.sh
```

For a 1000-Agent run on a suitably sized Docker host:

```sh
FRP_CONTROLPLANE_LOAD_AGENTS=1000 ./deploy/e2e/controlplane/run-container.sh
```

Run the same workflow against PostgreSQL 16 instead of the SQLite baseline:

```sh
FRP_CONTROLPLANE_DATABASE_DRIVER=postgres \
FRP_CONTROLPLANE_LOAD_AGENTS=1000 \
./deploy/e2e/controlplane/run-container.sh
```

Use `FRP_CONTROLPLANE_DATABASE_DRIVER=mysql` for the MySQL 8.4 fixture:

```sh
FRP_CONTROLPLANE_DATABASE_DRIVER=mysql \
FRP_CONTROLPLANE_LOAD_AGENTS=1000 \
./deploy/e2e/controlplane/run-container.sh
```

This is a finite functional/load harness. It is not evidence of a seven-day
soak test; long-running soak validation must be executed and reported
separately with host and Server resource telemetry.

## Observed local baseline

The following runs were observed on 2026-07-28. The host was an Apple M5 Pro
(15 CPU cores, 48 GiB RAM); the Colima Docker VM was limited to 4 vCPU and
7.74 GiB RAM and ran Ubuntu 24.04 arm64. The database baseline runs used
1000 Agents, 10 load
workers, one reconnect wave, 1-second heartbeats, and a 6-second connected
window.

| Database | Sessions | Failures | Welcome p95/p99 | Reconnect p95/p99 | Wave | Server peak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SQLite | 2000 | 0 | 9.869 / 12.852 ms | 14.726 / 89.385 ms | 848.101 ms | 68.04% CPU / 93.40 MiB |
| PostgreSQL 16 | 2000 | 0 | 9.108 / 13.343 ms | 7.588 / 13.625 ms | 585.705 ms | 8.19% CPU / 93.85 MiB |
| MySQL 8.4 | 2000 | 0 | 4.747 / 5.915 ms | 4.201 / 26.602 ms | 602.356 ms | 69.23% CPU / 90.87 MiB |

A separate SQLite run used 100 Agents, 100 task concurrency, and one-second
mixed `inspect`/`collect_runtime` waves. All 500 tasks succeeded with no task,
connection, reconnect, or stream failures. Task latency was 175.784 ms p50,
228.719 ms p95, and 256.002 ms p99; sampled Server peak usage was 37.25% CPU
and 142.40 MiB RSS.

The resource sampler used one-second `docker stats` snapshots, so short CPU
spikes between samples may be missed. SQLite is only a local connection
baseline. PostgreSQL/MySQL deployment-specific capacity gates still require
representative infrastructure, workload duration, data volume, and SLOs.

The fixture is destructive only inside its temporary containers and Docker
network. It does not expose the Server ports on the host.
