package frpadmin

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/frp-admin/frp-admin/agent/internal/config"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

func testClient(t *testing.T, role string, handler http.Handler) *Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New(role, config.AdminAPI{Endpoint: server.URL, Username: "admin", Password: "secret", Timeout: time.Second, MaxResponseBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return time.Unix(10, 0) }
	return client
}

func requireAuth(t *testing.T, request *http.Request) {
	t.Helper()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:secret"))
	if request.Header.Get("Authorization") != want {
		t.Fatalf("authorization=%q", request.Header.Get("Authorization"))
	}
}

func TestCollectClientRuntime(t *testing.T) {
	client := testClient(t, "client", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireAuth(t, r)
		if r.URL.Path != "/api/status" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"tcp":[{"name":"ssh","status":"running","local_addr":"127.0.0.1:22","remote_addr":"public:6000","err":""}],"http":[{"name":"site","type":"http","status":"offline","err":"password=hunter2"}],"ignored":{"token":"must-not-escape"}}`))
	}))
	snapshot, err := client.Collect(context.Background(), "full")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.GetRole() != agentv1.NodeRole_NODE_ROLE_CLIENT || snapshot.GetCollectedAtUnixMs() != 10000 || len(snapshot.GetProxies()) != 2 {
		t.Fatalf("snapshot=%v", snapshot)
	}
	if snapshot.GetProxies()[0].GetStatus() != agentv1.RuntimeProxyStatus_RUNTIME_PROXY_STATUS_RUNNING || snapshot.GetProxies()[0].GetLocalAddress() != "127.0.0.1:22" {
		t.Fatalf("tcp=%v", snapshot.GetProxies()[0])
	}
	if got := snapshot.GetProxies()[1].GetLastError(); got != "runtime error details redacted" || strings.Contains(got, "hunter2") {
		t.Fatalf("diagnostic=%q", got)
	}
}

func TestCollectServerRuntime(t *testing.T) {
	client := testClient(t, "server", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireAuth(t, r)
		switch r.URL.Path {
		case "/api/serverinfo":
			_, _ = w.Write([]byte(`{"version":"0.70.0","bind_addr":"0.0.0.0","bind_port":7000}`))
		case "/api/clients":
			_, _ = w.Write([]byte(`{"clients":[{"run_id":"node-a","remote_addr":"10.0.0.2:1234","connected_at":"2026-01-02T03:04:05Z"}]}`))
		case "/api/proxy/tcp":
			_, _ = w.Write([]byte(`{"proxies":[{"name":"ssh","status":"online","cur_conns":2,"traffic_in":300,"traffic_out":400,"today_traffic_in":100,"today_traffic_out":200,"conf":{"local_ip":"127.0.0.1","local_port":22,"remote_port":6000}}]}`))
		default:
			if strings.HasPrefix(r.URL.Path, "/api/proxy/") {
				_, _ = w.Write([]byte(`{"proxies":[]}`))
				return
			}
			http.NotFound(w, r)
		}
	}))
	snapshot, err := client.Collect(context.Background(), "summary")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.GetFrpVersion() != "0.70.0" || snapshot.GetServer().GetProxyCount() != 1 || snapshot.GetServer().GetClientCount() != 1 {
		t.Fatalf("snapshot=%v", snapshot)
	}
	proxy := snapshot.GetProxies()[0]
	if proxy.GetRemoteAddress() != "0.0.0.0:6000" || proxy.GetTraffic().GetBytesIn() != 300 || proxy.GetTraffic().GetTodayBytesOut() != 200 || proxy.GetTraffic().GetCurrentConnections() != 2 {
		t.Fatalf("proxy=%v", proxy)
	}
	if snapshot.GetClients()[0].GetConnectedAtUnixMs() == 0 {
		t.Fatalf("client=%v", snapshot.GetClients()[0])
	}
}

func TestAdminAPIFailuresDoNotLeakResponseOrCredentials(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		max  int64
		code agentv1.ErrorCode
	}{
		{name: "invalid", body: `{"password":"super-secret"`, max: 4096, code: agentv1.ErrorCode_ERROR_CODE_ADMIN_API_INVALID_RESPONSE},
		{name: "large", body: strings.Repeat("x", 2048), max: 1024, code: agentv1.ErrorCode_ERROR_CODE_ADMIN_API_RESPONSE_TOO_LARGE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := testClient(t, "client", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(tc.body)) }))
			client.maxResponseBytes = tc.max
			_, err := client.Collect(context.Background(), "summary")
			var target *Error
			if !errors.As(err, &target) || target.Code != tc.code {
				t.Fatalf("error=%v", err)
			}
			if strings.Contains(err.Error(), "super-secret") || strings.Contains(err.Error(), "admin:secret") {
				t.Fatalf("error leaked secret: %v", err)
			}
		})
	}
}

func TestAdminAPITimeoutIsBoundedAndSanitized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	client, err := New("client", config.AdminAPI{Endpoint: server.URL, Username: "admin", Password: "timeout-secret", Timeout: 20 * time.Millisecond, MaxResponseBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = client.Collect(context.Background(), "summary")
	var target *Error
	if !errors.As(err, &target) || target.Code != agentv1.ErrorCode_ERROR_CODE_ADMIN_API_UNAVAILABLE {
		t.Fatalf("error=%v", err)
	}
	if time.Since(started) > time.Second || strings.Contains(err.Error(), "timeout-secret") {
		t.Fatalf("timeout was not bounded or leaked secret: elapsed=%s error=%v", time.Since(started), err)
	}
}
