# PostgreSQL fault injection E2E

This fixture proves recovery from a brief PostgreSQL 16 outage without
restarting the Server. It runs a real Server, a systemd Agent,
frps/frpc, and an independent HTTP backend behind an frp TCP proxy.

```sh
./deploy/e2e/db-fault/run.sh
```

The gate verifies:

- `/health/ready` returns 503 while PostgreSQL is stopped.
- An authenticated runtime-collection write returns a bounded non-2xx
  response and its idempotency key is absent after recovery.
- Existing traffic through the frp proxy continues during the database
  outage.
- The same Server container becomes ready after PostgreSQL returns.
- The Agent reconnects automatically and executes a `collect_runtime` task
  queued while it was offline.
- PostgreSQL contains one succeeded task and the Agent journal contains the
  matching succeeded command/idempotency result.

This is a short functional fault injection. It does not replace HA database
testing, network latency/packet-loss testing, or the required 168-hour soak.
