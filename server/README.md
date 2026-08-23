# frp-admin server

The control-plane backend defaults to a local SQLite database. MySQL 8+ and PostgreSQL 15+ use the same repository contract and equivalent versioned migrations.

The Agent API listens on `:8443` with TLS 1.3. On first startup the server creates a persistent Agent CA and server certificate in `data/pki`; partial PKI state is treated as fatal. Enrollment may connect without a client certificate, while every `Connect` stream requires a verified per-node client certificate.

```sh
go run ./cmd/frp-admin-server -config config.example.yaml
```

On an empty database, set `FRP_ADMIN_BOOTSTRAP_TOKEN` or `FRP_ADMIN_BOOTSTRAP_TOKEN_FILE`. The Server refuses to start without one and never writes the bootstrap credential to logs. Create the first administrator with `POST /api/v1/auth/bootstrap`. For local HTTP development, set `FRP_ADMIN_AUTH_SECURE_COOKIES=false`; production cookies are secure by default.

Configuration environment overrides use the `FRP_ADMIN_` prefix. The database selector is `FRP_ADMIN_DATABASE_DRIVER=sqlite|mysql|postgres` and `FRP_ADMIN_DATABASE_DSN` contains the selected driver's DSN. One server process uses exactly one primary database.

The Server includes opaque cookie sessions with CSRF protection, admin/operator/viewer/auditor RBAC, transactional audit, encrypted configuration and Secret storage, single-node FRP upgrades, runtime proxy/client snapshots, alert Webhooks, task cancellation/timeouts, and optional metrics on a separate listener. Nodes enroll in `observe` mode; only an administrator can switch them to `managed`, and the Store transactionally prevents concurrent managed mutations.

Master-key rotation is versioned for Secrets and upgrade artifact URLs. Configure every key version still referenced by the database under `masterKey.keyFiles`; startup fails closed when a referenced historical key is missing.

Run `make production-check` from the repository root for deterministic checks. This does not replace real MySQL/PostgreSQL contracts, privileged Agent E2E, image vulnerability/SBOM/signing workflows, or the 168-hour soak gate documented in [production_gate_report.md](../docs/production_gate_report.md).
