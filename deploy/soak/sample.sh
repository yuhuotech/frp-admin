#!/usr/bin/env bash
set -euo pipefail

[[ $# == 5 ]] || {
  echo "usage: sample.sh PID METRICS_URL CSV_PATH INTERVAL_SECONDS STOP_FILE" >&2
  exit 2
}

pid=$1
metrics_url=$2
csv_path=$3
interval=$4
stop_file=$5
[[ "$pid" =~ ^[0-9]+$ && "$interval" =~ ^[0-9]+$ && "$interval" -gt 0 ]] || exit 2

metric() {
  local name=$1 input=$2
  awk -v name="$name" '$1 == name {sum += $2; found = 1} END {if (found) print sum; else print -1}' <<<"$input"
}

task_failures() {
  awk '$1 ~ /^frp_admin_task_results_total\{/ && $1 !~ /state="(success|succeeded|completed)"/ {sum += $2} END {print sum + 0}' <<<"$1"
}

echo 'timestamp,cpu_pct,rss_bytes,goroutines,open_fds,db_open,db_in_use,sessions,task_failures,task_timeouts,task_cancellations,event_dropped,scrape_failures' >"$csv_path"
scrape_failures=0
while [[ ! -e "$stop_file" ]]; do
  kill -0 "$pid" 2>/dev/null || {
    echo "target process $pid exited" >&2
    exit 1
  }
  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  cpu=$(ps -p "$pid" -o %cpu= | tr -d ' ')
  rss_kb=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null || true)
  [[ -n "$rss_kb" ]] || rss_kb=$(ps -p "$pid" -o rss= | tr -d ' ')
  [[ -n "$cpu" ]] || cpu=-1
  [[ -n "$rss_kb" ]] || rss_kb=-1
  if [[ "$rss_kb" -ge 0 ]]; then rss_bytes=$((rss_kb * 1024)); else rss_bytes=-1; fi

  if metrics=$(curl --fail --silent --show-error --max-time 5 "$metrics_url"); then
    goroutines=$(metric frp_admin_process_goroutines "$metrics")
    open_fds=$(metric frp_admin_process_open_fds "$metrics")
    if [[ "$open_fds" -lt 0 ]] && command -v lsof >/dev/null; then
      open_fds=$(lsof -p "$pid" 2>/dev/null | awk 'NR > 1 {count++} END {print count + 0}')
    fi
    db_open=$(metric frp_admin_db_connections_open "$metrics")
    db_in_use=$(metric frp_admin_db_connections_in_use "$metrics")
    sessions=$(metric frp_admin_agent_sessions "$metrics")
    failed_tasks=$(task_failures "$metrics")
    task_timeouts=$(metric frp_admin_task_timeouts_total "$metrics")
    task_cancellations=$(metric frp_admin_task_cancellations_total "$metrics")
    event_dropped=$(metric frp_admin_event_dropped_total "$metrics")
  else
    scrape_failures=$((scrape_failures + 1))
    goroutines=-1 open_fds=-1 db_open=-1 db_in_use=-1 sessions=-1 failed_tasks=-1
    task_timeouts=-1 task_cancellations=-1 event_dropped=-1
  fi
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$now" "$cpu" "$rss_bytes" "$goroutines" "$open_fds" "$db_open" "$db_in_use" \
    "$sessions" "$failed_tasks" "$task_timeouts" "$task_cancellations" "$event_dropped" "$scrape_failures" >>"$csv_path"
  sleep "$interval" &
  wait $! || true
done
