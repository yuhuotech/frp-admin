#!/usr/bin/env bash
set -euo pipefail

[[ $# == 6 ]] || {
  echo "usage: analyze.sh SAMPLES_CSV LOAD_JSON ACTUAL_SECONDS AGENTS LOAD_EXIT REPORT" >&2
  exit 2
}

csv=$1 load_json=$2 actual_seconds=$3 agents=$4 load_exit=$5 report=$6
for value in "$actual_seconds" "$agents" "$load_exit"; do [[ "$value" =~ ^[0-9]+$ ]] || exit 2; done

window=${SOAK_TREND_WINDOW:-10}
warmup=${SOAK_WARMUP_SAMPLES:-2}
min_samples=${SOAK_MIN_SAMPLES:-5}
rss_abs_max=${SOAK_RSS_GROWTH_BYTES_MAX:-268435456}
rss_pct_max=${SOAK_RSS_GROWTH_PERCENT_MAX:-25}
goroutine_abs_max=${SOAK_GOROUTINE_GROWTH_MAX:-20}
goroutine_pct_max=${SOAK_GOROUTINE_GROWTH_PERCENT_MAX:-25}
fd_abs_max=${SOAK_FD_GROWTH_MAX:-32}
fd_pct_max=${SOAK_FD_GROWTH_PERCENT_MAX:-25}
db_open_growth_max=${SOAK_DB_OPEN_GROWTH_MAX:-10}
cpu_final_max=${SOAK_CPU_FINAL_AVG_MAX:-85}
cpu_growth_max=${SOAK_CPU_GROWTH_POINTS_MAX:-20}
session_floor_pct=${SOAK_SESSION_FLOOR_PERCENT:-95}
require_168h=${SOAK_REQUIRE_168H:-false}

stats=$(awk -F, -v window="$window" -v warmup="$warmup" '
  NR == 1 {next}
  {n++; for (i=2; i<=13; i++) value[n,i]=$i}
  END {
    w=window; if (w > n-warmup) w=n-warmup; if (w < 1) w=1
    bstart=warmup+1; bend=bstart+w-1; if (bend > n) bend=n
    fstart=n-w+1; if (fstart < 1) fstart=1
    printf "samples=%d\n", n
    for (i=2; i<=8; i++) {
      bs=bc=fs=fc=0
      for (j=bstart; j<=bend; j++) if (value[j,i] >= 0) {bs+=value[j,i]; bc++}
      for (j=fstart; j<=n; j++) if (value[j,i] >= 0) {fs+=value[j,i]; fc++}
      printf "b%d=%.6f\nf%d=%.6f\n", i, (bc ? bs/bc : -1), i, (fc ? fs/fc : -1)
    }
    for (i=9; i<=13; i++) {
      first=last=-1
      for (j=1; j<=n; j++) if (value[j,i] >= 0) {if (first < 0) first=value[j,i]; last=value[j,i]}
      printf "d%d=%.6f\n", i, (first >= 0 ? last-first : -1)
    }
  }
' "$csv")

get() { awk -F= -v key="$1" '$1 == key {print $2}' <<<"$stats"; }
samples=$(get samples)
b_cpu=$(get b2); f_cpu=$(get f2); b_rss=$(get b3); f_rss=$(get f3)
b_go=$(get b4); f_go=$(get f4); b_fd=$(get b5); f_fd=$(get f5)
b_db=$(get b6); f_db=$(get f6); f_sessions=$(get f8)
task_failure_delta=$(get d9); timeout_delta=$(get d10); cancellation_delta=$(get d11)
event_drop_delta=$(get d12); scrape_failure_delta=$(get d13)

pct_growth() { awk -v b="$1" -v f="$2" 'BEGIN {if (b <= 0) print (f > b ? 100 : 0); else printf "%.2f", (f-b)*100/b}'; }
rss_growth=$(awk -v b="$b_rss" -v f="$f_rss" 'BEGIN {printf "%.0f", f-b}')
go_growth=$(awk -v b="$b_go" -v f="$f_go" 'BEGIN {printf "%.0f", f-b}')
fd_growth=$(awk -v b="$b_fd" -v f="$f_fd" 'BEGIN {printf "%.0f", f-b}')
db_growth=$(awk -v b="$b_db" -v f="$f_db" 'BEGIN {printf "%.0f", f-b}')
cpu_growth=$(awk -v b="$b_cpu" -v f="$f_cpu" 'BEGIN {printf "%.2f", f-b}')
rss_pct=$(pct_growth "$b_rss" "$f_rss")
go_pct=$(pct_growth "$b_go" "$f_go")
fd_pct=$(pct_growth "$b_fd" "$f_fd")
session_floor=$(awk -v a="$agents" -v p="$session_floor_pct" 'BEGIN {printf "%.2f", a*p/100}')

load_failures=-1
task_created=-1
task_succeeded=-1
if jq -e . "$load_json" >/dev/null 2>&1; then
  load_failures=$(jq '[.provision_failures, .initial_connect_failures, .reconnect_failures, .stream_errors, .tasks_failed, .tasks_timed_out] | map(. // 0) | add' "$load_json")
  task_created=$(jq '.tasks_created // 0' "$load_json")
  task_succeeded=$(jq '.tasks_succeeded // 0' "$load_json")
fi

failures=()
check_gt() { awk -v a="$1" -v b="$2" 'BEGIN {exit !(a>b)}'; }
check_lt() { awk -v a="$1" -v b="$2" 'BEGIN {exit !(a<b)}'; }
((samples >= min_samples)) || failures+=("sample count $samples is below $min_samples")
for pair in "CPU:$b_cpu:$f_cpu" "RSS:$b_rss:$f_rss" "goroutines:$b_go:$f_go" "open FDs:$b_fd:$f_fd" "DB open connections:$b_db:$f_db" "Agent sessions:0:$f_sessions"; do
  name=${pair%%:*}; values=${pair#*:}; baseline=${values%%:*}; final=${values#*:}
  check_lt "$baseline" 0 && failures+=("$name baseline is unavailable")
  check_lt "$final" 0 && failures+=("$name final sample is unavailable")
done
((load_exit == 0)) || failures+=("load generator exited with $load_exit")
((load_failures == 0)) || failures+=("load generator failure count is $load_failures")
((task_created > 0)) || failures+=("load generator created no control-plane tasks")
((task_succeeded == task_created)) || failures+=("task success count $task_succeeded differs from created count $task_created")
check_gt "$rss_growth" "$rss_abs_max" && failures+=("RSS grew by $rss_growth bytes")
check_gt "$rss_pct" "$rss_pct_max" && failures+=("RSS grew by $rss_pct percent")
check_gt "$go_growth" "$goroutine_abs_max" && failures+=("goroutines grew by $go_growth")
check_gt "$go_pct" "$goroutine_pct_max" && failures+=("goroutines grew by $go_pct percent")
check_gt "$fd_growth" "$fd_abs_max" && failures+=("open FDs grew by $fd_growth")
check_gt "$fd_pct" "$fd_pct_max" && failures+=("open FDs grew by $fd_pct percent")
check_gt "$db_growth" "$db_open_growth_max" && failures+=("DB open connections grew by $db_growth")
check_gt "$f_cpu" "$cpu_final_max" && failures+=("final CPU average is $f_cpu percent")
check_gt "$cpu_growth" "$cpu_growth_max" && failures+=("CPU grew by $cpu_growth points")
check_lt "$f_sessions" "$session_floor" && failures+=("final sessions average $f_sessions is below $session_floor")
for pair in "task failures:$task_failure_delta" "task timeouts:$timeout_delta" "task cancellations:$cancellation_delta" "event drops:$event_drop_delta" "metric scrape failures:$scrape_failure_delta"; do
  name=${pair%%:*}; value=${pair#*:}; check_gt "$value" 0 && failures+=("$name increased by $value")
done

qualified=false
((actual_seconds >= 604800)) && qualified=true
if [[ "$require_168h" == true && "$qualified" != true ]]; then failures+=("actual duration is below the required 168 hours"); fi
status=PASS
((${#failures[@]} == 0)) || status=FAIL

{
  echo "# frp-admin soak report"
  echo
  echo "- Status: **$status**"
  echo "- Actual duration: ${actual_seconds}s"
  echo "- Agents: $agents"
  echo "- Samples: $samples"
  echo "- qualified_168h: $qualified"
  echo
  echo "| Metric | Baseline avg | Final avg | Growth |"
  echo "| --- | ---: | ---: | ---: |"
  echo "| CPU (%) | $b_cpu | $f_cpu | $cpu_growth points |"
  echo "| RSS (bytes) | $b_rss | $f_rss | $rss_growth ($rss_pct%) |"
  echo "| Goroutines | $b_go | $f_go | $go_growth ($go_pct%) |"
  echo "| Open FDs | $b_fd | $f_fd | $fd_growth ($fd_pct%) |"
  echo "| DB open connections | $b_db | $f_db | $db_growth |"
  echo "| Agent sessions | - | $f_sessions | floor $session_floor |"
  echo "| Control-plane tasks | $task_created created | $task_succeeded succeeded | zero failures/timeouts required |"
  echo
  echo "## Gate findings"
  echo
  if ((${#failures[@]} == 0)); then echo "No threshold violations."; else printf -- '- %s\n' "${failures[@]}"; fi
} >"$report"

[[ "$status" == PASS ]]
