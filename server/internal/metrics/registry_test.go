package metrics

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
)

func TestOperationalMetricsExposure(t *testing.T) {
	r := New()
	r.ObserveSQL(25 * time.Millisecond)
	r.EventQueue(7, 2)
	r.EventDropped()
	r.SetDBStatsProvider(func() DBStats { return DBStats{Open: 4, InUse: 2, Idle: 2, WaitCount: 3, WaitDuration: time.Second} })
	r.SetProcessStatsProvider(func() ProcessStats { return ProcessStats{Goroutines: 17, OpenFDs: 23} })
	_, _ = r.UnaryServerInterceptor(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}, func(context.Context, any) (any, error) { return nil, errors.New("failure") })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	body := w.Body.String()
	for _, required := range []string{"frp_admin_grpc_requests_total", "frp_admin_sql_query_duration_seconds_count 1", "frp_admin_db_connections_open 4", "frp_admin_event_queue_depth 7", "frp_admin_event_dropped_total 1", "frp_admin_process_goroutines 17", "frp_admin_process_open_fds 23"} {
		if !strings.Contains(body, required) {
			t.Errorf("metrics missing %q:\n%s", required, body)
		}
	}
}
