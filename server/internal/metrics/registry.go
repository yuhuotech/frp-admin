package metrics

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

type DBStats struct {
	Open, InUse, Idle, WaitCount int64
	WaitDuration                 time.Duration
}

type ProcessStats struct {
	Goroutines int
	OpenFDs    int
}

type Registry struct {
	mu               sync.Mutex
	httpRequests     map[string]uint64
	httpDuration     map[string]time.Duration
	agentSessions    int64
	taskTimeouts     uint64
	taskCancels      uint64
	taskResults      map[string]uint64
	webhookResults   map[string]uint64
	grpcRequests     map[string]uint64
	grpcDuration     map[string]time.Duration
	sqlCount         uint64
	sqlDuration      time.Duration
	eventQueueDepth  int64
	eventSubscribers int64
	eventDropped     uint64
	dbStats          func() DBStats
	eventStats       func() (int, int)
	processStats     func() ProcessStats
}

var Default = New()

func New() *Registry {
	return &Registry{httpRequests: map[string]uint64{}, httpDuration: map[string]time.Duration{}, taskResults: map[string]uint64{}, webhookResults: map[string]uint64{}, grpcRequests: map[string]uint64{}, grpcDuration: map[string]time.Duration{}, processStats: currentProcessStats}
}

func currentProcessStats() ProcessStats {
	stats := ProcessStats{Goroutines: runtime.NumGoroutine(), OpenFDs: -1}
	if entries, err := os.ReadDir("/proc/self/fd"); err == nil {
		stats.OpenFDs = len(entries)
	}
	return stats
}

func (r *Registry) ObserveHTTP(method string, status int, elapsed time.Duration) {
	key := strings.ToUpper(method) + `",status="` + fmt.Sprint(status)
	r.mu.Lock()
	r.httpRequests[key]++
	r.httpDuration[key] += elapsed
	r.mu.Unlock()
}
func (r *Registry) AgentConnected()    { r.addSessions(1) }
func (r *Registry) AgentDisconnected() { r.addSessions(-1) }
func (r *Registry) addSessions(delta int64) {
	r.mu.Lock()
	r.agentSessions += delta
	r.mu.Unlock()
}
func (r *Registry) TaskTimeout(n int) {
	r.mu.Lock()
	r.taskTimeouts += uint64(n)
	r.mu.Unlock()
}
func (r *Registry) TaskCancelled() {
	r.mu.Lock()
	r.taskCancels++
	r.mu.Unlock()
}
func (r *Registry) TaskResult(state string) { r.mu.Lock(); r.taskResults[state]++; r.mu.Unlock() }
func (r *Registry) WebhookResult(outcome string) {
	r.mu.Lock()
	r.webhookResults[outcome]++
	r.mu.Unlock()
}
func (r *Registry) ObserveSQL(elapsed time.Duration) {
	r.mu.Lock()
	r.sqlCount++
	r.sqlDuration += elapsed
	r.mu.Unlock()
}
func (r *Registry) SetDBStatsProvider(v func() DBStats) { r.mu.Lock(); r.dbStats = v; r.mu.Unlock() }
func (r *Registry) SetProcessStatsProvider(v func() ProcessStats) {
	r.mu.Lock()
	r.processStats = v
	r.mu.Unlock()
}
func (r *Registry) SetEventStatsProvider(v func() (int, int)) {
	r.mu.Lock()
	r.eventStats = v
	r.mu.Unlock()
}
func (r *Registry) EventQueue(depth, subscribers int) {
	r.mu.Lock()
	r.eventQueueDepth, r.eventSubscribers = int64(depth), int64(subscribers)
	r.mu.Unlock()
}
func (r *Registry) EventDropped() { r.mu.Lock(); r.eventDropped++; r.mu.Unlock() }
func (r *Registry) observeGRPC(method, code string, elapsed time.Duration) {
	key := method + `",code="` + code
	r.mu.Lock()
	r.grpcRequests[key]++
	r.grpcDuration[key] += elapsed
	r.mu.Unlock()
}
func (r *Registry) UnaryServerInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	start := time.Now()
	resp, err := handler(ctx, req)
	r.observeGRPC(info.FullMethod, status.Code(err).String(), time.Since(start))
	return resp, err
}
func (r *Registry) StreamServerInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	start := time.Now()
	err := handler(srv, ss)
	r.observeGRPC(info.FullMethod, status.Code(err).String(), time.Since(start))
	return err
}

func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	requests, durations := clone(r.httpRequests), cloneDuration(r.httpDuration)
	sessions, timeouts, cancels := r.agentSessions, r.taskTimeouts, r.taskCancels
	webhooks := clone(r.webhookResults)
	results := clone(r.taskResults)
	grpcRequests, grpcDuration := clone(r.grpcRequests), cloneDuration(r.grpcDuration)
	sqlCount, sqlDuration := r.sqlCount, r.sqlDuration
	eventDepth, eventSubscribers, eventDropped := r.eventQueueDepth, r.eventSubscribers, r.eventDropped
	dbProvider := r.dbStats
	eventProvider := r.eventStats
	processProvider := r.processStats
	r.mu.Unlock()
	db := DBStats{}
	if dbProvider != nil {
		db = dbProvider()
	}
	if eventProvider != nil {
		depth, subscribers := eventProvider()
		eventDepth, eventSubscribers = int64(depth), int64(subscribers)
	}
	process := ProcessStats{OpenFDs: -1}
	if processProvider != nil {
		process = processProvider()
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintln(w, "# HELP frp_admin_agent_sessions Current authenticated Agent sessions.")
	fmt.Fprintln(w, "# TYPE frp_admin_agent_sessions gauge")
	fmt.Fprintf(w, "frp_admin_agent_sessions %d\n", sessions)
	fmt.Fprintln(w, "# TYPE frp_admin_http_requests_total counter")
	for _, key := range sortedKeys(requests) {
		fmt.Fprintf(w, "frp_admin_http_requests_total{method=\"%s\"} %d\n", key, requests[key])
		fmt.Fprintf(w, "frp_admin_http_request_duration_seconds_sum{method=\"%s\"} %.6f\n", key, durations[key].Seconds())
		fmt.Fprintf(w, "frp_admin_http_request_duration_seconds_count{method=\"%s\"} %d\n", key, requests[key])
	}
	fmt.Fprintf(w, "frp_admin_task_timeouts_total %d\nfrp_admin_task_cancellations_total %d\n", timeouts, cancels)
	for _, state := range sortedKeys(results) {
		fmt.Fprintf(w, "frp_admin_task_results_total{state=\"%s\"} %d\n", state, results[state])
	}
	for _, outcome := range sortedKeys(webhooks) {
		fmt.Fprintf(w, "frp_admin_alert_webhook_deliveries_total{outcome=\"%s\"} %d\n", outcome, webhooks[outcome])
	}
	for _, key := range sortedKeys(grpcRequests) {
		fmt.Fprintf(w, "frp_admin_grpc_requests_total{method=\"%s\"} %d\n", key, grpcRequests[key])
		fmt.Fprintf(w, "frp_admin_grpc_request_duration_seconds_sum{method=\"%s\"} %.6f\n", key, grpcDuration[key].Seconds())
		fmt.Fprintf(w, "frp_admin_grpc_request_duration_seconds_count{method=\"%s\"} %d\n", key, grpcRequests[key])
	}
	fmt.Fprintf(w, "frp_admin_sql_query_duration_seconds_sum %.6f\nfrp_admin_sql_query_duration_seconds_count %d\n", sqlDuration.Seconds(), sqlCount)
	fmt.Fprintf(w, "frp_admin_db_connections_open %d\nfrp_admin_db_connections_in_use %d\nfrp_admin_db_connections_idle %d\nfrp_admin_db_wait_total %d\nfrp_admin_db_wait_duration_seconds_total %.6f\n", db.Open, db.InUse, db.Idle, db.WaitCount, db.WaitDuration.Seconds())
	fmt.Fprintf(w, "frp_admin_event_queue_depth %d\nfrp_admin_event_subscribers %d\nfrp_admin_event_dropped_total %d\n", eventDepth, eventSubscribers, eventDropped)
	fmt.Fprintf(w, "frp_admin_process_goroutines %d\n", process.Goroutines)
	if process.OpenFDs >= 0 {
		fmt.Fprintf(w, "frp_admin_process_open_fds %d\n", process.OpenFDs)
	}
}
func clone(in map[string]uint64) map[string]uint64 {
	out := map[string]uint64{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func cloneDuration(in map[string]time.Duration) map[string]time.Duration {
	out := map[string]time.Duration{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func sortedKeys[T any](in map[string]T) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
