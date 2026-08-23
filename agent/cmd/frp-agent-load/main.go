package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/frp-admin/frp-admin/agent/internal/bootstrap"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type options struct {
	httpURL, grpcURL, serverName                     string
	username, passwordFile, bootstrapTokenFile       string
	password, bootstrapToken, stateDir               string
	agents, concurrency, taskConcurrency             int
	heartbeat, reconnectAfter, duration, requestTime time.Duration
	taskInterval, taskTimeout                        time.Duration
}

type apiClient struct {
	base, csrf string
	client     *http.Client
	sequence   atomic.Uint64
}

type virtualAgent struct {
	id, dir string
	seq     atomic.Uint64
}

type session struct {
	conn   *grpc.ClientConn
	stream grpc.BidiStreamingClient[agentv1.AgentToServer, agentv1.ServerToAgent]
	cancel context.CancelFunc
	id     string
	sendMu sync.Mutex
}

type metrics struct {
	Agents                 int     `json:"agents"`
	ProvisionFailures      int64   `json:"provision_failures"`
	InitialConnectFailures int64   `json:"initial_connect_failures"`
	ReconnectFailures      int64   `json:"reconnect_failures"`
	SuccessfulSessions     int64   `json:"successful_sessions"`
	StreamErrors           int64   `json:"stream_errors"`
	HeartbeatsSent         int64   `json:"heartbeats_sent"`
	PeakActiveSessions     int64   `json:"peak_active_sessions"`
	WelcomeLatencyP50Ms    float64 `json:"welcome_latency_p50_ms"`
	WelcomeLatencyP95Ms    float64 `json:"welcome_latency_p95_ms"`
	WelcomeLatencyP99Ms    float64 `json:"welcome_latency_p99_ms"`
	ReconnectLatencyP50Ms  float64 `json:"reconnect_latency_p50_ms"`
	ReconnectLatencyP95Ms  float64 `json:"reconnect_latency_p95_ms"`
	ReconnectLatencyP99Ms  float64 `json:"reconnect_latency_p99_ms"`
	ReconnectWaveElapsedMs float64 `json:"reconnect_wave_elapsed_ms"`
	TasksCreated           int64   `json:"tasks_created"`
	TasksSucceeded         int64   `json:"tasks_succeeded"`
	TasksFailed            int64   `json:"tasks_failed"`
	TasksTimedOut          int64   `json:"tasks_timed_out"`
	TaskLatencyP50Ms       float64 `json:"task_latency_p50_ms"`
	TaskLatencyP95Ms       float64 `json:"task_latency_p95_ms"`
	TaskLatencyP99Ms       float64 `json:"task_latency_p99_ms"`
}

func main() {
	var o options
	flag.StringVar(&o.httpURL, "http-url", "http://127.0.0.1:8080", "control-plane HTTP URL")
	flag.StringVar(&o.grpcURL, "grpc-url", "https://127.0.0.1:8443", "control-plane gRPC URL")
	flag.StringVar(&o.serverName, "server-name", "localhost", "gRPC TLS server name")
	flag.StringVar(&o.username, "username", "load-admin", "admin username")
	flag.StringVar(&o.passwordFile, "password-file", "", "0600 file containing the admin password")
	flag.StringVar(&o.bootstrapTokenFile, "bootstrap-token-file", "", "0600 file containing the optional bootstrap token")
	flag.StringVar(&o.stateDir, "state-dir", "./load-state", "cached virtual Agent credentials")
	flag.IntVar(&o.agents, "agents", 1000, "number of virtual Agents")
	flag.IntVar(&o.concurrency, "concurrency", 50, "provision/connect concurrency")
	flag.IntVar(&o.taskConcurrency, "task-concurrency", 100, "concurrent control-plane task operations")
	flag.DurationVar(&o.heartbeat, "heartbeat", 5*time.Second, "heartbeat interval")
	flag.DurationVar(&o.reconnectAfter, "reconnect-after", 5*time.Second, "delay before the reconnect wave")
	flag.DurationVar(&o.duration, "duration", 15*time.Second, "total connected duration")
	flag.DurationVar(&o.requestTime, "request-timeout", 15*time.Second, "per-request timeout")
	flag.DurationVar(&o.taskInterval, "task-interval", 0, "interval between inspect/runtime task waves; zero disables task churn")
	flag.DurationVar(&o.taskTimeout, "task-timeout", 30*time.Second, "timeout waiting for each task terminal state")
	flag.Parse()
	if o.agents <= 0 || o.concurrency <= 0 || o.taskConcurrency <= 0 || o.heartbeat <= 0 || o.duration < o.reconnectAfter || o.taskInterval < 0 || o.taskTimeout <= 0 {
		fatal("invalid positive agents/concurrency/heartbeat or duration before reconnect")
	}
	var err error
	if o.password, err = readSecretFile(o.passwordFile, true); err != nil {
		fatal(err.Error())
	}
	if o.bootstrapToken, err = readSecretFile(o.bootstrapTokenFile, false); err != nil {
		fatal(err.Error())
	}
	if err := run(o); err != nil {
		fatal(err.Error())
	}
}

func run(o options) error {
	ctx, cancel := context.WithTimeout(context.Background(), o.duration+time.Duration(o.agents)*o.requestTime)
	defer cancel()
	api, err := newAPI(o)
	if err != nil {
		return err
	}
	if err := api.authenticate(ctx, o); err != nil {
		return err
	}
	ca, err := api.request(ctx, http.MethodGet, "/api/v1/system/agent-ca", nil, http.StatusOK, nil)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(o.stateDir, 0700); err != nil {
		return err
	}
	agents := make([]virtualAgent, o.agents)
	var report metrics
	report.Agents = o.agents
	parallel(o.agents, o.concurrency, func(index int) {
		dir := filepath.Join(o.stateDir, fmt.Sprintf("agent-%06d", index))
		id, provisionErr := provision(ctx, api, o, ca, dir)
		if provisionErr != nil {
			atomic.AddInt64(&report.ProvisionFailures, 1)
			return
		}
		agents[index] = virtualAgent{id: id, dir: dir}
	})
	if report.ProvisionFailures != 0 {
		return printReport(report, fmt.Errorf("%d Agent provisions failed", report.ProvisionFailures))
	}

	active := atomic.Int64{}
	var welcomeMu sync.Mutex
	welcomeLatencies := make([]time.Duration, 0, o.agents*2)
	sessions := make([]*session, o.agents)
	connectWave(ctx, o, agents, sessions, &report.InitialConnectFailures, &report, &active, &welcomeMu, &welcomeLatencies)
	if report.InitialConnectFailures != 0 {
		closeSessions(sessions, &active)
		return printReport(report, fmt.Errorf("%d initial connections failed", report.InitialConnectFailures))
	}
	var taskLatencies []time.Duration
	var taskLatencyMu sync.Mutex
	var taskStop chan struct{}
	var tasksDone chan struct{}
	if o.taskInterval > 0 {
		if err := setManaged(ctx, api, agents, o.taskConcurrency); err != nil {
			closeSessions(sessions, &active)
			return printReport(report, err)
		}
		taskStop, tasksDone = make(chan struct{}), make(chan struct{})
		go func() {
			defer close(tasksDone)
			runTaskChurn(ctx, taskStop, api, agents, o, &report, &taskLatencyMu, &taskLatencies)
		}()
	}
	heartbeatCtx, stopHeartbeats := context.WithCancel(ctx)
	heartbeatsDone := make(chan struct{})
	go func() {
		defer close(heartbeatsDone)
		sendHeartbeats(heartbeatCtx, o.heartbeat, agents, sessions, &report)
	}()
	select {
	case <-ctx.Done():
		stopHeartbeats()
		<-heartbeatsDone
		closeSessions(sessions, &active)
		return ctx.Err()
	case <-time.After(o.reconnectAfter):
	}
	stopHeartbeats()
	<-heartbeatsDone
	closeSessions(sessions, &active)

	reconnectStarted := time.Now()
	reconnectLatencies := make([]time.Duration, 0, o.agents)
	connectWave(ctx, o, agents, sessions, &report.ReconnectFailures, &report, &active, &welcomeMu, &reconnectLatencies)
	report.ReconnectWaveElapsedMs = float64(time.Since(reconnectStarted).Microseconds()) / 1000
	heartbeatCtx, stopHeartbeats = context.WithCancel(ctx)
	heartbeatsDone = make(chan struct{})
	go func() {
		defer close(heartbeatsDone)
		sendHeartbeats(heartbeatCtx, o.heartbeat, agents, sessions, &report)
	}()
	remaining := o.duration - o.reconnectAfter
	select {
	case <-ctx.Done():
	case <-time.After(remaining):
	}
	if taskStop != nil {
		close(taskStop)
		<-tasksDone
	}
	stopHeartbeats()
	<-heartbeatsDone
	closeSessions(sessions, &active)
	setPercentiles(welcomeLatencies, &report.WelcomeLatencyP50Ms, &report.WelcomeLatencyP95Ms, &report.WelcomeLatencyP99Ms)
	setPercentiles(reconnectLatencies, &report.ReconnectLatencyP50Ms, &report.ReconnectLatencyP95Ms, &report.ReconnectLatencyP99Ms)
	setPercentiles(taskLatencies, &report.TaskLatencyP50Ms, &report.TaskLatencyP95Ms, &report.TaskLatencyP99Ms)
	if report.ReconnectFailures != 0 || report.StreamErrors != 0 || report.TasksFailed != 0 || report.TasksTimedOut != 0 {
		return printReport(report, fmt.Errorf("load run completed with reconnect or stream failures"))
	}
	return printReport(report, nil)
}

func newAPI(o options) (*apiClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	return &apiClient{base: strings.TrimRight(o.httpURL, "/"), client: &http.Client{Jar: jar, Timeout: o.requestTime}}, nil
}

func readSecretFile(path string, required bool) (string, error) {
	if path == "" {
		if required {
			return "", errors.New("-password-file is required")
		}
		return "", nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("read credential metadata: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
		return "", errors.New("credential file must be a regular non-symlink file, at most 4 KiB, with no group/other permissions")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read credential file: %w", err)
	}
	value := strings.TrimRight(string(data), "\r\n")
	if value == "" || strings.IndexByte(value, 0) >= 0 {
		return "", errors.New("credential file must be non-empty and contain no NUL bytes")
	}
	return value, nil
}

func (a *apiClient) authenticate(ctx context.Context, o options) error {
	_, err := a.request(ctx, http.MethodPost, "/api/v1/auth/login", map[string]string{"username": o.username, "password": o.password}, http.StatusOK, nil)
	if err != nil && o.bootstrapToken != "" {
		_, _ = a.request(ctx, http.MethodPost, "/api/v1/auth/bootstrap", map[string]string{"username": o.username, "password": o.password, "bootstrapToken": o.bootstrapToken}, http.StatusCreated, nil)
		_, err = a.request(ctx, http.MethodPost, "/api/v1/auth/login", map[string]string{"username": o.username, "password": o.password}, http.StatusOK, nil)
	}
	if err != nil {
		return fmt.Errorf("authenticate: %w", err)
	}
	parsed, _ := url.Parse(a.base)
	for _, cookie := range a.client.Jar.Cookies(parsed) {
		if cookie.Name == "csrf_token" {
			a.csrf = cookie.Value
		}
	}
	if a.csrf == "" {
		return errors.New("authentication did not return a CSRF cookie")
	}
	return nil
}

func (a *apiClient) request(ctx context.Context, method, path string, input any, want int, output any) ([]byte, error) {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, body)
	if err != nil {
		return nil, err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && a.csrf != "" {
		req.Header.Set("X-CSRF-Token", a.csrf)
		req.Header.Set("Idempotency-Key", fmt.Sprintf("load-%d-%d", time.Now().UnixNano(), a.sequence.Add(1)))
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != want {
		return nil, fmt.Errorf("%s %s returned %d: %s", method, path, resp.StatusCode, data)
	}
	if output != nil {
		if err := json.Unmarshal(data, output); err != nil {
			return nil, err
		}
	}
	return data, nil
}

func provision(ctx context.Context, api *apiClient, o options, ca []byte, dir string) (string, error) {
	if data, err := os.ReadFile(filepath.Join(dir, "node-id")); err == nil {
		return strings.TrimSpace(string(data)), nil
	}
	var token struct {
		Token string `json:"token"`
	}
	if _, err := api.request(ctx, http.MethodPost, "/api/v1/nodes/enrollment-tokens", map[string]any{"role": "client", "ttlSeconds": 3600}, http.StatusCreated, &token); err != nil {
		return "", err
	}
	target, err := grpcTarget(o.grpcURL)
	if err != nil {
		return "", err
	}
	return bootstrap.Enroll(ctx, bootstrap.Options{Address: target, ServerName: o.serverName, Token: token.Token, Role: "client", StateDir: dir, AgentVersion: "load", RootCA: ca})
}

func grpcTarget(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("invalid gRPC URL %q", value)
	}
	return parsed.Host, nil
}

func connect(ctx context.Context, o options, agent *virtualAgent, report *metrics, active *atomic.Int64) (*session, time.Duration, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(agent.dir, "pki/client.pem"), filepath.Join(agent.dir, "pki/client-key.pem"))
	if err != nil {
		return nil, 0, err
	}
	ca, err := os.ReadFile(filepath.Join(agent.dir, "pki/ca.pem"))
	if err != nil {
		return nil, 0, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, 0, errors.New("invalid cached CA")
	}
	target, err := grpcTarget(o.grpcURL)
	if err != nil {
		return nil, 0, err
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS13, ServerName: o.serverName, RootCAs: pool, Certificates: []tls.Certificate{cert}})))
	if err != nil {
		return nil, 0, err
	}
	streamCtx, cancel := context.WithCancel(ctx)
	stream, err := agentv1.NewAgentControlServiceClient(conn).Connect(streamCtx)
	if err != nil {
		cancel()
		conn.Close()
		return nil, 0, err
	}
	started := time.Now()
	if err := stream.Send(&agentv1.AgentToServer{Payload: &agentv1.AgentToServer_Hello{Hello: &agentv1.Hello{NodeId: agent.id, BootId: "load-" + agent.id, AgentVersion: "load", Role: agentv1.NodeRole_NODE_ROLE_CLIENT, ProtocolVersion: 1}}}); err != nil {
		cancel()
		conn.Close()
		return nil, 0, err
	}
	msg, err := stream.Recv()
	if err != nil || msg.GetWelcome() == nil {
		cancel()
		conn.Close()
		return nil, 0, fmt.Errorf("welcome: %w", err)
	}
	current := active.Add(1)
	for {
		peak := atomic.LoadInt64(&report.PeakActiveSessions)
		if current <= peak || atomic.CompareAndSwapInt64(&report.PeakActiveSessions, peak, current) {
			break
		}
	}
	atomic.AddInt64(&report.SuccessfulSessions, 1)
	s := &session{conn: conn, stream: stream, cancel: cancel, id: msg.GetWelcome().GetSessionId()}
	go func() {
		for {
			message, recvErr := stream.Recv()
			if recvErr != nil {
				if streamCtx.Err() == nil {
					atomic.AddInt64(&report.StreamErrors, 1)
				}
				return
			}
			if command := message.GetCommand(); command != nil {
				if err := respondToSafeCommand(s, agent, command); err != nil && streamCtx.Err() == nil {
					atomic.AddInt64(&report.StreamErrors, 1)
					return
				}
			}
		}
	}()
	return s, time.Since(started), nil
}

func (s *session) send(message *agentv1.AgentToServer) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.stream.Send(message)
}

func respondToSafeCommand(s *session, agent *virtualAgent, command *agentv1.Command) error {
	now := time.Now()
	if err := s.send(&agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CommandAck{CommandAck: &agentv1.CommandAck{CommandId: command.GetCommandId(), ReceivedAtUnixMs: now.UnixMilli()}}}); err != nil {
		return err
	}
	result := &agentv1.CommandResult{CommandId: command.GetCommandId(), IdempotencyKey: command.GetIdempotencyKey(), Status: agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED, StartedAtUnixMs: now.UnixMilli(), FinishedAtUnixMs: time.Now().UnixMilli()}
	switch command.GetAction().(type) {
	case *agentv1.Command_Inspect:
		result.Output = &agentv1.CommandResult_Inspect{Inspect: &agentv1.InspectResult{Inventory: &agentv1.Inventory{Hostname: "load-" + agent.id, OperatingSystem: "virtual", Architecture: "virtual", FrpBinaryPath: "/nonexistent/frpc", FrpVersion: "0.70.0", ServiceName: "frpc.service", Service: &agentv1.ServiceStatus{State: agentv1.ServiceState_SERVICE_STATE_ACTIVE, SubState: "virtual"}, CollectedAtUnixMs: now.UnixMilli()}}}
	case *agentv1.Command_CollectRuntime:
		result.Output = &agentv1.CommandResult_Runtime{Runtime: &agentv1.RuntimeResult{Snapshot: &agentv1.RuntimeSnapshot{Role: agentv1.NodeRole_NODE_ROLE_CLIENT, CollectedAtUnixMs: now.UnixMilli(), FrpVersion: "0.70.0"}}}
	default:
		result.Status = agentv1.CommandStatus_COMMAND_STATUS_FAILED
		result.ErrorCode = agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED_COMMAND
		result.Diagnostic = "virtual load Agent only supports inspect and collect_runtime"
	}
	return s.send(&agentv1.AgentToServer{Payload: &agentv1.AgentToServer_CommandResult{CommandResult: result}})
}

func connectWave(ctx context.Context, o options, agents []virtualAgent, sessions []*session, failures *int64, report *metrics, active *atomic.Int64, mu *sync.Mutex, latencies *[]time.Duration) {
	parallel(len(agents), o.concurrency, func(index int) {
		s, latency, err := connect(ctx, o, &agents[index], report, active)
		if err != nil {
			atomic.AddInt64(failures, 1)
			return
		}
		sessions[index] = s
		mu.Lock()
		*latencies = append(*latencies, latency)
		mu.Unlock()
	})
}

func sendHeartbeats(ctx context.Context, interval time.Duration, agents []virtualAgent, sessions []*session, report *metrics) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			for index, s := range sessions {
				if s == nil {
					continue
				}
				message := &agentv1.AgentToServer{Payload: &agentv1.AgentToServer_Heartbeat{Heartbeat: &agentv1.Heartbeat{SentAtUnixMs: now.UnixMilli(), SessionId: s.id, Sequence: agents[index].seq.Add(1)}}}
				if err := s.send(message); err != nil {
					atomic.AddInt64(&report.StreamErrors, 1)
				} else {
					atomic.AddInt64(&report.HeartbeatsSent, 1)
				}
			}
		}
	}
}

func setManaged(ctx context.Context, api *apiClient, agents []virtualAgent, concurrency int) error {
	var failures atomic.Int64
	parallel(len(agents), concurrency, func(index int) {
		_, err := api.request(ctx, http.MethodPatch, "/api/v1/nodes/"+agents[index].id+"/management-mode", map[string]string{"mode": "managed"}, http.StatusOK, nil)
		if err != nil {
			failures.Add(1)
		}
	})
	if count := failures.Load(); count != 0 {
		return fmt.Errorf("set managed mode failed for %d virtual Agents", count)
	}
	return nil
}

func runTaskChurn(ctx context.Context, stop <-chan struct{}, api *apiClient, agents []virtualAgent, o options, report *metrics, latencyMu *sync.Mutex, latencies *[]time.Duration) {
	wave := uint64(0)
	for {
		runTaskWave(ctx, api, agents, o, wave, report, latencyMu, latencies)
		wave++
		timer := time.NewTimer(o.taskInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-stop:
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func runTaskWave(ctx context.Context, api *apiClient, agents []virtualAgent, o options, wave uint64, report *metrics, latencyMu *sync.Mutex, latencies *[]time.Duration) {
	parallel(len(agents), o.taskConcurrency, func(index int) {
		path := "/api/v1/nodes/" + agents[index].id + "/inspect"
		if (uint64(index)+wave)%2 == 1 {
			path = "/api/v1/nodes/" + agents[index].id + "/runtime-collections"
		}
		var task struct {
			ID string `json:"id"`
		}
		started := time.Now()
		if _, err := api.request(ctx, http.MethodPost, path, nil, http.StatusAccepted, &task); err != nil {
			atomic.AddInt64(&report.TasksFailed, 1)
			return
		}
		atomic.AddInt64(&report.TasksCreated, 1)
		status, err := waitLoadTask(ctx, api, task.ID, o.taskTimeout)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				atomic.AddInt64(&report.TasksTimedOut, 1)
			} else {
				atomic.AddInt64(&report.TasksFailed, 1)
			}
			return
		}
		if status != "succeeded" {
			atomic.AddInt64(&report.TasksFailed, 1)
			return
		}
		atomic.AddInt64(&report.TasksSucceeded, 1)
		latencyMu.Lock()
		*latencies = append(*latencies, time.Since(started))
		latencyMu.Unlock()
	})
}

func waitLoadTask(ctx context.Context, api *apiClient, taskID string, timeout time.Duration) (string, error) {
	taskCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		var task struct {
			Status string `json:"status"`
		}
		if _, err := api.request(taskCtx, http.MethodGet, "/api/v1/tasks/"+taskID, nil, http.StatusOK, &task); err != nil {
			return "", err
		}
		switch task.Status {
		case "succeeded", "failed", "cancelled", "timed_out":
			return task.Status, nil
		}
		select {
		case <-taskCtx.Done():
			return "", taskCtx.Err()
		case <-ticker.C:
		}
	}
}

func closeSessions(sessions []*session, active *atomic.Int64) {
	for index, s := range sessions {
		if s == nil {
			continue
		}
		s.cancel()
		_ = s.conn.Close()
		active.Add(-1)
		sessions[index] = nil
	}
}

func parallel(count, workers int, fn func(int)) {
	jobs := make(chan int)
	var group sync.WaitGroup
	workers = min(workers, count)
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				fn(index)
			}
		}()
	}
	for index := range count {
		jobs <- index
	}
	close(jobs)
	group.Wait()
}

func setPercentiles(values []time.Duration, p50, p95, p99 *float64) {
	if len(values) == 0 {
		return
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	get := func(percent float64) float64 {
		index := int(float64(len(values)-1) * percent)
		return float64(values[index].Microseconds()) / 1000
	}
	*p50, *p95, *p99 = get(.50), get(.95), get(.99)
}

func printReport(report metrics, runErr error) error {
	data, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(data))
	return runErr
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
