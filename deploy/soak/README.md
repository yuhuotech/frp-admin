# Seven-day soak gate

The harness runs the existing virtual Agent load generator while sampling the
Server process and `/metrics`. Defaults are 100 Agents, 168 hours, and one
sample per minute. A formal default run fails unless the actual elapsed time is
at least 168 hours.

Run it on the Linux host that owns the Server process:

```sh
SOAK_SERVER_PID=1234 \
SOAK_BOOTSTRAP_TOKEN='from-a-secret-store' \
SOAK_METRICS_URL=http://127.0.0.1:9090/metrics \
deploy/soak/run.sh
```

For a container, set `SOAK_SERVER_CONTAINER` instead of the PID. The output
directory contains raw CSV samples, load-generator JSON/stderr, cached virtual
Agent credentials, and `report.md`; protect it because Agent credentials are
stateful test identities.

Short validation runs may override duration and sampling without claiming the
seven-day gate:

```sh
SOAK_AGENTS=2 SOAK_DURATION=30s SOAK_RECONNECT_AFTER=5s \
SOAK_SAMPLE_INTERVAL=2 SOAK_SERVER_PID=1234 deploy/soak/run.sh
```

Thresholds are configurable through `SOAK_*_MAX` variables in `analyze.sh`.
The defaults block load-generator failures, task failures/timeouts/cancellations,
event drops, metric scrape failures, excessive CPU/RSS/goroutine/FD/DB trends,
and a final Agent-session average below 95% of the requested load.
