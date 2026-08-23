# frp-admin

frp-admin is a self-hosted control plane for managing official `frpc` and `frps` processes without forking or embedding frp.

The repository is organized as a monorepo with independently buildable projects:

- `server/`: control-plane API, agent gateway, task scheduler, authentication and persistence;
- `web/`: React operations console;
- `agent/`: node-side process, configuration and upgrade controller;
- `contracts/`: versioned Protobuf contracts shared by Agent and Server;
- `deploy/`: local and production deployment assets;
- `docs/`: product and implementation design.

The default database is local SQLite. MySQL 8.0+ and PostgreSQL 15+ are selectable alternatives; one server installation uses one database backend.

## Development

Prerequisites:

- Go 1.26.5+
- Node.js 22+
- npm 10+
- Protobuf compiler
- Docker for integration tests and Compose deployment

Run `make help` for the available commands. The usual validation loop is:

```bash
make generate
make test
make build
```

Before a release candidate is promoted, run the deterministic repository gate:

```bash
make production-check
```

This gate runs contract generation, all Go tests and full race suites, vet, Web lint/tests/build, binary builds, shell syntax checks, and the backup/restore regression. It deliberately does not claim external evidence. MySQL and PostgreSQL contracts, privileged systemd/control-plane E2E, Trivy/SBOM/signing workflows, and the required 168-hour soak remain separate release gates; see [the production gate report](docs/production_gate_report.md).

See [the implementation plan](docs/frp_admin_implementation.md) for architecture, security boundaries and phased scope.

On an empty database, configure `FRP_ADMIN_BOOTSTRAP_TOKEN` or mount a secret through `FRP_ADMIN_BOOTSTRAP_TOKEN_FILE`. The server fails closed when neither is set and never writes this administrator credential to logs.

## Local Compose

```bash
cd deploy/compose
cp .env.example .env
docker compose up --build
```

Open `http://127.0.0.1:3000`, initialize the administrator with the bootstrap token from `.env`, then use **Nodes > Add node** to create a one-time Agent token and download the Agent CA.

The local Agent example is at `deploy/examples/agent.local.yaml`. It is intended for enrollment and protocol testing; process-management commands require a Linux host with systemd and an installed `frpc`/`frps`.

## Production status

The repository is a production-candidate implementation, not an approved production release. Core control-plane, Agent, Web, three-database migrations, encrypted configuration/secrets/upgrade material, RBAC/audit, alerts, runtime inventory, backup/restore, and real Linux E2E fixtures are implemented. Promotion remains blocked until a retained 168-hour soak report passes and every environment-specific gate in the production report has current evidence.
