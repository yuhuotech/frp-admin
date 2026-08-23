package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/frp-admin/frp-admin/agent/internal/journal"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

const (
	dbFaultStatePath     = "/run/frp-admin-e2e/db-fault-state.json"
	dbFaultOutageRequest = "db-fault-outage-runtime-collection"
	dbFaultMarker        = "frp-db-fault-data-plane-ok"
)

type dbFaultState struct {
	NodeID       string `json:"node_id"`
	TaskID       string `json:"task_id"`
	SessionToken string `json:"session_token"`
	CSRFToken    string `json:"csrf_token"`
}

func requireDBFault(t *testing.T) {
	t.Helper()
	if os.Getenv("FRP_DB_FAULT_E2E") != "1" {
		t.Skip("set FRP_DB_FAULT_E2E=1 inside the database fault fixture")
	}
}

func TestDatabaseFaultSetup(t *testing.T) {
	requireDBFault(t)
	api := newControlAPI(t)
	api.login(t)

	var enrollment struct {
		Token string `json:"token"`
	}
	api.request(t, http.MethodPost, "/api/v1/nodes/enrollment-tokens", map[string]any{"role": "client", "ttlSeconds": 600}, http.StatusCreated, &enrollment)
	ca := api.request(t, http.MethodGet, "/api/v1/system/agent-ca", nil, http.StatusOK, nil)
	for _, dir := range []string{"/etc/frp-agent", "/etc/frp", "/run/frp-admin-e2e"} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile("/tmp/db-fault-ca.pem", ca, 0o600); err != nil {
		t.Fatal(err)
	}
	frpcConfig := fmt.Sprintf(`serverAddr = "127.0.0.1"
serverPort = 7000
loginFailExit = false
webServer.addr = "127.0.0.1"
webServer.port = 7400

[[proxies]]
name = "db-fault-data-plane"
type = "tcp"
localIP = "backend"
localPort = 8080
remotePort = 16000
`)
	if err := os.WriteFile(configPath, []byte(frpcConfig), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/etc/frp/frps.toml", []byte("bindAddr = \"127.0.0.1\"\nbindPort = 7000\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	agentYAML := fmt.Sprintf(`serverURL: %s
role: client
stateDir: %s
tls:
  caFile: %s/pki/ca.pem
  certFile: %s/pki/client.pem
  keyFile: %s/pki/client-key.pem
  serverName: control
frp:
  serviceName: %s
  binaryPath: %s
  configPath: %s
channel:
  heartbeatInterval: 1s
  reconnectMin: 200ms
  reconnectMax: 2s
`, os.Getenv("FRP_CONTROLPLANE_GRPC"), stateDir, stateDir, stateDir, stateDir, serviceName, binaryPath, configPath)
	if err := os.WriteFile("/etc/frp-agent/agent.yaml", []byte(agentYAML), 0o640); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/usr/local/bin/frp-agent", "-config", "/etc/frp-agent/agent.yaml", "-enroll-token", enrollment.Token, "-enroll-ca", "/tmp/db-fault-ca.pem")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("enroll: %v output=%s", err, output)
	}
	nodeID := strings.TrimSpace(string(output))
	if nodeID == "" {
		t.Fatal("enrollment returned an empty node ID")
	}
	if output, err = exec.Command("chown", "-R", "frp-agent:frp-agent", stateDir, "/etc/frp", "/opt/frp/bin").CombinedOutput(); err != nil {
		t.Fatalf("chown Agent paths: %v output=%s", err, output)
	}
	if output, err = exec.Command("chown", "root:frp-agent", "/etc/frp-agent", "/etc/frp-agent/agent.yaml").CombinedOutput(); err != nil {
		t.Fatalf("chown Agent config: %v output=%s", err, output)
	}
	if err = os.Chmod("/etc/frp-agent", 0o750); err != nil {
		t.Fatal(err)
	}

	runSystemctl(t, "daemon-reload")
	runSystemctl(t, "enable", "frps.service", "frpc.service", "frp-agent.service")
	runSystemctl(t, "restart", "frps.service")
	waitTCP(t, "127.0.0.1:7000")
	runSystemctl(t, "restart", "frpc.service")
	runSystemctl(t, "restart", "frp-agent.service")
	waitNodeOnline(t, api, nodeID)
	api.request(t, http.MethodPatch, "/api/v1/nodes/"+nodeID+"/management-mode", map[string]any{"mode": "managed"}, http.StatusOK, nil)
	requireDBFaultCapability(t, api, nodeID, "runtime.collect")
	waitDBFaultDataPlane(t)

	runSystemctl(t, "stop", "frp-agent.service")
	waitNodeStatus(t, api, nodeID, "offline")
	taskID := runtimeCollection(t, api, nodeID)
	if state := taskState(t, api, taskID); state != "queued" {
		t.Fatalf("offline task state=%s want=queued", state)
	}

	state := dbFaultState{NodeID: nodeID, TaskID: taskID, CSRFToken: api.csrf}
	for _, cookie := range api.client.Jar.Cookies(mustURL(t, api.base)) {
		if cookie.Name == "frp_admin_session" {
			state.SessionToken = cookie.Value
		}
	}
	if state.SessionToken == "" {
		t.Fatal("session cookie is missing")
	}
	writeDBFaultState(t, state)
	waitDBFaultDataPlane(t)
}

func TestDatabaseFaultDuringOutage(t *testing.T) {
	requireDBFault(t)
	state := readDBFaultState(t)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(os.Getenv("FRP_CONTROLPLANE_HTTP") + "/health/ready")
	if err != nil {
		t.Fatalf("readiness request failed instead of returning 503: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("readiness status=%d want=503 body=%s", resp.StatusCode, body)
	}

	body := bytes.NewBuffer(nil)
	req, err := http.NewRequest(http.MethodPost, os.Getenv("FRP_CONTROLPLANE_HTTP")+"/api/v1/nodes/"+state.NodeID+"/runtime-collections", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", state.CSRFToken)
	req.Header.Set("Idempotency-Key", dbFaultOutageRequest)
	req.AddCookie(&http.Cookie{Name: "frp_admin_session", Value: state.SessionToken})
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("runtime collection did not return a bounded HTTP failure: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("runtime collection falsely succeeded during database outage: status=%d body=%s", resp.StatusCode, data)
	}
	waitDBFaultDataPlane(t)
}

func TestDatabaseFaultRecovered(t *testing.T) {
	requireDBFault(t)
	state := readDBFaultState(t)
	api := newControlAPI(t)
	api.loginExisting(t)
	waitNodeOnline(t, api, state.NodeID)
	waitTask(t, api, state.TaskID, "succeeded")
	waitDBFaultDataPlane(t)

	runSystemctl(t, "stop", "frp-agent.service")
	j, err := journal.Open(filepath.Join(stateDir, "journal", "commands.db"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	commandResult, commandOK, err := j.Get("command:" + state.TaskID)
	if err != nil || !commandOK || commandResult.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED {
		t.Fatalf("command journal result=%v found=%v err=%v", commandResult, commandOK, err)
	}
	idempotencyResult, idempotencyOK, err := j.Get("idempotency:" + state.TaskID)
	if err != nil || !idempotencyOK || idempotencyResult.GetCommandId() != state.TaskID {
		t.Fatalf("idempotency journal result=%v found=%v err=%v", idempotencyResult, idempotencyOK, err)
	}
}

func requireDBFaultCapability(t *testing.T, api *controlAPI, nodeID, capability string) {
	t.Helper()
	var node struct {
		Capabilities []string `json:"capabilities"`
	}
	api.request(t, http.MethodGet, "/api/v1/nodes/"+nodeID, nil, http.StatusOK, &node)
	for _, advertised := range node.Capabilities {
		if advertised == capability {
			return
		}
	}
	t.Fatalf("node did not advertise required executable capability %q: %v", capability, node.Capabilities)
}

func runtimeCollection(t *testing.T, api *controlAPI, nodeID string) string {
	t.Helper()
	var task struct {
		ID string `json:"id"`
	}
	api.request(t, http.MethodPost, "/api/v1/nodes/"+nodeID+"/runtime-collections", nil, http.StatusAccepted, &task)
	if task.ID == "" {
		t.Fatal("runtime collection returned an empty task ID")
	}
	return task.ID
}

func waitDBFaultDataPlane(t *testing.T) {
	t.Helper()
	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get("http://127.0.0.1:16000/")
		if err == nil {
			data, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr == nil && resp.StatusCode == http.StatusOK && strings.Contains(string(data), dbFaultMarker) {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatal("frp data-plane request did not reach the independent backend")
}

func writeDBFaultState(t *testing.T, state dbFaultState) {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(dbFaultStatePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readDBFaultState(t *testing.T) dbFaultState {
	t.Helper()
	data, err := os.ReadFile(dbFaultStatePath)
	if err != nil {
		t.Fatal(err)
	}
	var state dbFaultState
	if err = json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if state.NodeID == "" || state.TaskID == "" || state.SessionToken == "" || state.CSRFToken == "" {
		t.Fatalf("incomplete database fault state: %+v", state)
	}
	return state
}
