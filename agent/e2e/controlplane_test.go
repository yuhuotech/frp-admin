package e2e

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/frp-admin/frp-admin/agent/internal/managementcap"
	"github.com/frp-admin/frp-admin/agent/internal/roothelper"
)

type controlAPI struct {
	base   string
	client *http.Client
	csrf   string
}

func newControlAPI(t *testing.T) *controlAPI {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &controlAPI{base: os.Getenv("FRP_CONTROLPLANE_HTTP"), client: &http.Client{Jar: jar, Timeout: 10 * time.Second}}
}

func (a *controlAPI) request(t *testing.T, method, path string, body any, want int, out any) []byte {
	t.Helper()
	var input io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		input = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, a.base+path, input)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && a.csrf != "" {
		req.Header.Set("X-CSRF-Token", a.csrf)
		req.Header.Set("Idempotency-Key", fmt.Sprintf("controlplane-e2e-%d", time.Now().UnixNano()))
	}
	resp, err := a.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status=%d body=%s", method, path, resp.StatusCode, data)
	}
	if out != nil && len(data) != 0 {
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("decode %s: %v body=%s", path, err, data)
		}
	}
	return data
}

func (a *controlAPI) login(t *testing.T) {
	t.Helper()
	a.request(t, http.MethodPost, "/api/v1/auth/bootstrap", map[string]any{
		"username": "admin", "password": "controlplane-e2e-password", "bootstrapToken": "controlplane-e2e-bootstrap",
	}, http.StatusCreated, nil)
	a.request(t, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"username": "admin", "password": "controlplane-e2e-password",
	}, http.StatusOK, nil)
	for _, cookie := range a.client.Jar.Cookies(mustURL(t, a.base)) {
		if cookie.Name == "csrf_token" {
			a.csrf = cookie.Value
		}
	}
	if a.csrf == "" {
		t.Fatal("login did not set CSRF cookie")
	}
}

func (a *controlAPI) loginExisting(t *testing.T) {
	t.Helper()
	a.request(t, http.MethodPost, "/api/v1/auth/login", map[string]any{
		"username": "admin", "password": "controlplane-e2e-password",
	}, http.StatusOK, nil)
	for _, cookie := range a.client.Jar.Cookies(mustURL(t, a.base)) {
		if cookie.Name == "csrf_token" {
			a.csrf = cookie.Value
		}
	}
	if a.csrf == "" {
		t.Fatal("login did not set CSRF cookie")
	}
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestControlPlane(t *testing.T) {
	if os.Getenv("FRP_CONTROLPLANE_E2E") != "1" {
		t.Skip("set FRP_CONTROLPLANE_E2E=1 inside the control-plane fixture")
	}
	api := newControlAPI(t)
	api.login(t)

	var enrollment struct {
		Token string `json:"token"`
	}
	api.request(t, http.MethodPost, "/api/v1/nodes/enrollment-tokens", map[string]any{"role": "client", "ttlSeconds": 600}, http.StatusCreated, &enrollment)
	ca := api.request(t, http.MethodGet, "/api/v1/system/agent-ca", nil, http.StatusOK, nil)
	if err := os.MkdirAll("/etc/frp-agent", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("/var/lib/frp-agent-helper", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("/etc/frp", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("/run/frp-admin-e2e", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/tmp/control-ca.pem", ca, 0600); err != nil {
		t.Fatal(err)
	}
	initial := controlConfig("initial")
	if err := os.WriteFile(configPath, initial, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/etc/frp/frps.toml", []byte("bindAddr = \"127.0.0.1\"\nbindPort = 7000\n"), 0640); err != nil {
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
  helperSocket: /run/frp-agent-helper.sock
  adminAPI:
    endpoint: http://127.0.0.1:7400
    username: runtime-user
    passwordFile: /etc/frp-agent/admin-api-password
    timeout: 3s
    maxResponseBytes: 1048576
upgrade:
  allowedHosts: [control, 93.184.216.34]
  maxArtifactBytes: 67108864
`, os.Getenv("FRP_CONTROLPLANE_GRPC"), stateDir, stateDir, stateDir, stateDir, serviceName, binaryPath, configPath)
	if err := os.WriteFile("/etc/frp-agent/agent.yaml", []byte(agentYAML), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/etc/frp-agent/admin-api-password", []byte("runtime-password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	helperConfig := `{"Role":"client","BinaryPath":"/opt/frp/bin/frpc","ConfigPath":"/etc/frp/frpc.toml","ServiceName":"frpc.service","StateDir":"/var/lib/frp-agent-helper"}`
	if err := os.WriteFile("/etc/frp-agent/helper.json", []byte(helperConfig), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/usr/local/bin/frp-agent", "-config", "/etc/frp-agent/agent.yaml", "-enroll-token", enrollment.Token, "-enroll-ca", "/tmp/control-ca.pem")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("enroll: %v output=%s", err, output)
	}
	nodeID := strings.TrimSpace(string(output))
	if nodeID == "" {
		t.Fatal("enrollment returned an empty node ID")
	}
	shortLivedSerial := resignShortLivedCertificate(t, nodeID)
	if output, err := exec.Command("chown", "-R", "frp-agent:frp-agent", stateDir, "/etc/frp", "/opt/frp/bin", "/etc/frp-agent/admin-api-password").CombinedOutput(); err != nil {
		t.Fatalf("chown Agent paths: %v output=%s", err, output)
	}
	if output, err := exec.Command("chown", "-R", "frp-agent:frp-agent", "/run/frp-admin-e2e").CombinedOutput(); err != nil {
		t.Fatalf("chown frp runtime directory: %v output=%s", err, output)
	}
	configureSameUserFRPServices(t)
	if output, err := exec.Command("chown", "root:frp-agent", "/etc/frp-agent/agent.yaml").CombinedOutput(); err != nil {
		t.Fatalf("chown Agent config: %v output=%s", err, output)
	}
	if output, err := exec.Command("chown", "root:frp-agent", "/etc/frp-agent").CombinedOutput(); err != nil {
		t.Fatalf("chown Agent config directory: %v output=%s", err, output)
	}
	if err := os.Chmod("/etc/frp-agent", 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod("/etc/frp-agent/agent.yaml", 0640); err != nil {
		t.Fatal(err)
	}

	runSystemctl(t, "daemon-reload")
	runSystemctl(t, "enable", "--now", "frp-agent-helper.socket")
	assertSameUserFRPModel(t)
	output, err = exec.Command("runuser", "-u", "frp-agent", "--", "/usr/local/bin/frp-agent-systemd-e2e", "-test.run", "^TestControlPlaneCapabilityPreflight$", "-test.v").CombinedOutput()
	if err != nil {
		t.Fatalf("same-user capability preflight: %v output=%s", err, output)
	}
	runSystemctl(t, "enable", "frps.service", "frpc.service", "frp-agent.service")
	runSystemctl(t, "restart", "frps.service")
	waitActive(t, "frps.service")
	waitTCP(t, "127.0.0.1:7000")
	runSystemctl(t, "restart", "frpc.service")
	runSystemctl(t, "restart", "frp-agent.service")
	waitNodeOnline(t, api, nodeID)
	waitCertificateRotation(t, nodeID, shortLivedSerial)
	runSystemctl(t, "restart", "frp-agent.service")
	waitActive(t, "frp-agent.service")
	waitNodeOnline(t, api, nodeID)
	api.request(t, http.MethodPatch, "/api/v1/nodes/"+nodeID+"/management-mode", map[string]any{"mode": "managed"}, http.StatusOK, nil)
	api.request(t, http.MethodPost, "/api/v1/secrets", map[string]any{"name": "RESTORE_TOKEN", "value": "restored-secret-value"}, http.StatusCreated, nil)

	var runtimeTask struct {
		ID string `json:"id"`
	}
	api.request(t, http.MethodPost, "/api/v1/nodes/"+nodeID+"/runtime-collections", nil, http.StatusAccepted, &runtimeTask)
	waitTask(t, api, runtimeTask.ID, "succeeded")
	var runtimeSnapshot struct {
		NodeID  string `json:"node_id"`
		Proxies []struct {
			Name string `json:"name"`
		} `json:"proxies"`
	}
	api.request(t, http.MethodGet, "/api/v1/nodes/"+nodeID+"/runtime", nil, http.StatusOK, &runtimeSnapshot)
	if runtimeSnapshot.NodeID != nodeID || len(runtimeSnapshot.Proxies) != 1 || runtimeSnapshot.Proxies[0].Name != "controlplane-runtime" {
		t.Fatalf("persisted runtime snapshot=%+v", runtimeSnapshot)
	}
	var proxy struct {
		Name string `json:"name"`
	}
	api.request(t, http.MethodGet, "/api/v1/proxies/"+nodeID+"/controlplane-runtime", nil, http.StatusOK, &proxy)
	if proxy.Name != "controlplane-runtime" {
		t.Fatalf("persisted proxy=%+v", proxy)
	}
	testControlPlaneUpgrades(t, api, nodeID)

	taskID := serviceAction(t, api, nodeID, "restart")
	waitTask(t, api, taskID, "succeeded")
	revision1 := createRevision(t, api, nodeID, controlConfig("revision-one"))
	waitTask(t, api, deployRevision(t, api, revision1), "succeeded")
	assertConfig(t, "revision-one")
	revision2 := createRevision(t, api, nodeID, controlConfig("revision-two"))
	waitTask(t, api, deployRevision(t, api, revision2), "succeeded")
	assertConfig(t, "revision-two")
	var rollback struct {
		ID string `json:"id"`
	}
	api.request(t, http.MethodPost, "/api/v1/nodes/"+nodeID+"/config-rollbacks", map[string]any{"revision_id": revision1}, http.StatusAccepted, &rollback)
	waitTask(t, api, rollback.ID, "succeeded")
	assertConfig(t, "revision-one")

	cancelRevision := createRevision(t, api, nodeID, controlConfig("cancel-slow"))
	cancelTaskID := deployRevision(t, api, cancelRevision)
	waitTaskRunning(t, api, cancelTaskID)
	api.request(t, http.MethodPost, "/api/v1/tasks/"+cancelTaskID+"/cancel", nil, http.StatusOK, nil)
	waitTask(t, api, cancelTaskID, "cancelled")
	time.Sleep(4 * time.Second)
	assertTaskState(t, api, cancelTaskID, "cancelled")
}

func TestControlPlaneCapabilityPreflight(t *testing.T) {
	if os.Getenv("FRP_CONTROLPLANE_E2E") != "1" {
		t.Skip("set FRP_CONTROLPLANE_E2E=1 inside the control-plane fixture")
	}
	client := roothelper.Client{SocketPath: "/run/frp-agent-helper.sock"}
	if err := client.ProbeService(context.Background()); err != nil {
		t.Fatalf("privileged service probe: %v", err)
	}
	mutationCapabilities := managementcap.Detect(context.Background(), serviceName, configPath, binaryPath)
	t.Logf("privileged service probe succeeded; mutation capabilities=%v", mutationCapabilities)
	for _, required := range []string{"config.apply", "config.rollback", "frp.upgrade"} {
		if !slices.Contains(mutationCapabilities, required) {
			t.Fatalf("missing mutation capability %s", required)
		}
	}
}

func configureSameUserFRPServices(t *testing.T) {
	t.Helper()
	const override = "[Service]\nUser=frp-agent\nGroup=frp-agent\n"
	for _, serviceName := range []string{"frpc.service", "frps.service"} {
		dir := filepath.Join("/etc/systemd/system", serviceName+".d")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "controlplane-same-user.conf")
		if err := os.WriteFile(path, []byte(override), 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func assertSameUserFRPModel(t *testing.T) {
	t.Helper()
	for _, serviceName := range []string{"frpc.service", "frps.service"} {
		output, err := exec.Command("systemctl", "show", serviceName, "--property=User,Group", "--no-pager").CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte("User=frp-agent")) || !bytes.Contains(output, []byte("Group=frp-agent")) {
			t.Fatalf("unsafe %s identity: %v output=%s", serviceName, err, output)
		}
	}
	for _, path := range []string{"/etc/frp", "/opt/frp/bin", configPath, "/etc/frp/frps.toml", binaryPath, "/opt/frp/bin/frps"} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("unsafe managed resource %s: mode=%v err=%v", path, info, err)
		}
		output, ownerErr := exec.Command("stat", "-c", "%U:%G", path).CombinedOutput()
		if ownerErr != nil || strings.TrimSpace(string(output)) != "frp-agent:frp-agent" {
			t.Fatalf("unsafe managed owner %s: %v output=%s", path, ownerErr, output)
		}
	}
}

func TestControlPlaneAfterServerRestart(t *testing.T) {
	if os.Getenv("FRP_CONTROLPLANE_E2E") != "1" {
		t.Skip("set FRP_CONTROLPLANE_E2E=1 inside the control-plane fixture")
	}
	api := newControlAPI(t)
	api.loginExisting(t)
	var page struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	api.request(t, http.MethodGet, "/api/v1/nodes", nil, http.StatusOK, &page)
	if len(page.Items) != 1 || page.Items[0].ID == "" {
		t.Fatalf("persisted nodes after restart=%+v", page.Items)
	}
	nodeID := page.Items[0].ID
	waitNodeOnline(t, api, nodeID)
	serverCA := api.request(t, http.MethodGet, "/api/v1/system/agent-ca", nil, http.StatusOK, nil)
	localCA, err := os.ReadFile(filepath.Join(stateDir, "pki/ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if digest(serverCA) != digest(localCA) {
		t.Fatal("restored Server CA fingerprint differs from the enrolled Agent CA")
	}
	var task struct {
		ID string `json:"id"`
	}
	api.request(t, http.MethodPost, "/api/v1/nodes/"+nodeID+"/runtime-collections", nil, http.StatusAccepted, &task)
	waitTask(t, api, task.ID, "succeeded")
	var snapshot struct {
		NodeID      string `json:"node_id"`
		CollectedAt string `json:"collected_at"`
		Proxies     []struct {
			Name string `json:"name"`
		} `json:"proxies"`
	}
	api.request(t, http.MethodGet, "/api/v1/nodes/"+nodeID+"/runtime", nil, http.StatusOK, &snapshot)
	if snapshot.NodeID != nodeID || snapshot.CollectedAt == "" {
		t.Fatalf("runtime after Server restart=%+v", snapshot)
	}
	var restoredNode struct {
		DesiredRevision string `json:"desired_revision"`
	}
	api.request(t, http.MethodGet, "/api/v1/nodes/"+nodeID, nil, http.StatusOK, &restoredNode)
	if restoredNode.DesiredRevision == "" {
		t.Fatal("restored node has no rollback revision")
	}
	rollbackRevision := restoredNode.DesiredRevision
	secretConfig := append(controlConfig("revision-two"), []byte("\n[auth]\ntoken = \"${secret:RESTORE_TOKEN}\"\n")...)
	secretRevision := createRevision(t, api, nodeID, secretConfig)
	waitTask(t, api, deployRevision(t, api, secretRevision), "succeeded")
	deployed, err := os.ReadFile(configPath)
	if err != nil || !bytes.Contains(deployed, []byte("restored-secret-value")) || bytes.Contains(deployed, []byte("${secret:")) {
		t.Fatalf("restored Secret was not materialized into deployed config: %q err=%v", deployed, err)
	}
	var rollback struct {
		ID string `json:"id"`
	}
	api.request(t, http.MethodPost, "/api/v1/nodes/"+nodeID+"/config-rollbacks", map[string]any{"revision_id": rollbackRevision}, http.StatusAccepted, &rollback)
	waitTask(t, api, rollback.ID, "succeeded")
	newNodeID, stopNewAgent := startRestoredNewAgent(t, api, serverCA)
	defer stopNewAgent()
	waitNodeOnline(t, api, newNodeID)
	api.request(t, http.MethodPatch, "/api/v1/nodes/"+newNodeID+"/management-mode", map[string]any{"mode": "managed"}, http.StatusOK, nil)
	api.request(t, http.MethodPost, "/api/v1/nodes/"+newNodeID+"/runtime-collections", nil, http.StatusAccepted, &task)
	waitTask(t, api, task.ID, "succeeded")
}

func startRestoredNewAgent(t *testing.T, api *controlAPI, ca []byte) (string, func()) {
	t.Helper()
	var enrollment struct {
		Token string `json:"token"`
	}
	api.request(t, http.MethodPost, "/api/v1/nodes/enrollment-tokens", map[string]any{"role": "client", "ttlSeconds": 600}, http.StatusCreated, &enrollment)
	newState := "/var/lib/frp-agent-restored-new"
	if err := os.MkdirAll(newState, 0700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("chown", "-R", "frp-agent:frp-agent", newState).CombinedOutput(); err != nil {
		t.Fatalf("chown new Agent state: %v output=%s", err, output)
	}
	caPath, configFile := "/tmp/restored-control-ca.pem", "/etc/frp-agent/restored-new.yaml"
	if err := os.WriteFile(caPath, ca, 0644); err != nil {
		t.Fatal(err)
	}
	configData := fmt.Sprintf(`serverURL: %s
role: client
stateDir: %s
tls:
  caFile: %s/pki/ca.pem
  certFile: %s/pki/client.pem
  keyFile: %s/pki/client-key.pem
  serverName: control
frp:
  serviceName: frpc.service
  binaryPath: %s
  configPath: %s
  adminAPI:
    endpoint: http://127.0.0.1:7400
    username: runtime-user
    passwordFile: /etc/frp-agent/admin-api-password
`, os.Getenv("FRP_CONTROLPLANE_GRPC"), newState, newState, newState, newState, binaryPath, configPath)
	if err := os.WriteFile(configFile, []byte(configData), 0640); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("chown", "root:frp-agent", configFile).CombinedOutput(); err != nil {
		t.Fatalf("chown new Agent config: %v output=%s", err, output)
	}
	enroll := exec.Command("runuser", "-u", "frp-agent", "--", "/usr/local/bin/frp-agent", "-config", configFile, "-enroll-token", enrollment.Token, "-enroll-ca", caPath)
	output, err := enroll.CombinedOutput()
	if err != nil {
		t.Fatalf("enroll restored new Agent: %v output=%s", err, output)
	}
	nodeID := strings.TrimSpace(string(output))
	ctx, cancel := context.WithCancel(context.Background())
	process := exec.CommandContext(ctx, "runuser", "-u", "frp-agent", "--", "/usr/local/bin/frp-agent", "-config", configFile)
	if err := process.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	return nodeID, func() {
		cancel()
		_ = process.Wait()
	}
}

func testControlPlaneUpgrades(t *testing.T, api *controlAPI, nodeID string) {
	t.Helper()
	artifact := makeArchive(t, "-controlplane-upgrade")
	server := newUpgradeArtifactServer(t, artifact)
	defer server.Close()
	certificate, err := os.ReadFile("/control-data/pki/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("/usr/local/share/ca-certificates/frp-upgrade-e2e.crt", certificate, 0644); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("update-ca-certificates").CombinedOutput(); err != nil {
		t.Fatalf("update CA certificates: %v output=%s", err, output)
	}
	runSystemctl(t, "restart", "frp-agent.service")
	waitActive(t, "frp-agent.service")
	waitNodeOnline(t, api, nodeID)

	before := fileDigest(t, binaryPath)
	runSystemctl(t, "stop", "frp-agent.service")
	waitNodeStatus(t, api, nodeID, "offline")
	successTask := createUpgrade(t, api, nodeID, server.URL, digest(artifact), "v0.70.0")
	if got := taskState(t, api, successTask); got != "queued" {
		t.Fatalf("offline upgrade task state=%s want=queued", got)
	}
	runSystemctl(t, "start", "frp-agent.service")
	waitActive(t, "frp-agent.service")
	waitNodeOnline(t, api, nodeID)
	waitTask(t, api, successTask, "succeeded")
	after := fileDigest(t, binaryPath)
	if after == before {
		t.Fatal("successful control-plane upgrade did not replace frpc")
	}

	checksumTask := createUpgrade(t, api, nodeID, server.URL, strings.Repeat("0", 64), "v0.70.0")
	waitTaskFailure(t, api, checksumTask, "CHECKSUM_MISMATCH")
	if fileDigest(t, binaryPath) != after {
		t.Fatal("checksum failure changed frpc binary")
	}

	if err := os.WriteFile("/run/frp-admin-e2e/fail-upgrade-start", []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	failureTask := createUpgrade(t, api, nodeID, server.URL, digest(artifact), "v0.70.0")
	waitTaskFailure(t, api, failureTask, "SERVICE_OPERATION_FAILED")
	if fileDigest(t, binaryPath) != after {
		t.Fatal("start failure did not restore previous frpc binary")
	}
	waitActive(t, serviceName)
}

func newUpgradeArtifactServer(t *testing.T, artifact []byte) *httptest.Server {
	t.Helper()
	const artifactIP = "93.184.216.34"
	if output, err := exec.Command("ip", "address", "add", artifactIP+"/32", "dev", "lo").CombinedOutput(); err != nil {
		t.Fatalf("add artifact TEST-NET address: %v output=%s", err, output)
	}
	t.Cleanup(func() {
		_ = exec.Command("ip", "address", "del", artifactIP+"/32", "dev", "lo").Run()
	})
	dir := t.TempDir()
	key, csr := filepath.Join(dir, "server.key"), filepath.Join(dir, "server.csr")
	cert, serial, ext := filepath.Join(dir, "server.crt"), filepath.Join(dir, "ca.srl"), filepath.Join(dir, "server.ext")
	if err := os.WriteFile(ext, []byte("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:"+artifactIP+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	commands := [][]string{
		{"genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", key},
		{"req", "-new", "-key", key, "-subj", "/CN=" + artifactIP, "-out", csr},
		{"x509", "-req", "-in", csr, "-CA", "/control-data/pki/ca.crt", "-CAkey", "/control-data/pki/ca.key", "-CAserial", serial, "-CAcreateserial", "-days", "1", "-sha256", "-extfile", ext, "-out", cert},
	}
	for _, args := range commands {
		if output, err := exec.Command("openssl", args...).CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %v output=%s", args, err, output)
		}
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(artifact)
	}))
	if err := server.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(artifactIP, "0"))
	if err != nil {
		t.Fatalf("listen on artifact TEST-NET address: %v", err)
	}
	server.Listener = listener
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	return server
}

func createUpgrade(t *testing.T, api *controlAPI, nodeID, artifactURL, checksum, version string) string {
	t.Helper()
	var response struct {
		Task struct {
			ID string `json:"id"`
		} `json:"task"`
	}
	api.request(t, http.MethodPost, "/api/v1/upgrade-plans", map[string]any{
		"node_id": nodeID, "version": version, "artifact_url": artifactURL, "sha256": checksum,
	}, http.StatusAccepted, &response)
	return response.Task.ID
}

func waitTaskFailure(t *testing.T, api *controlAPI, taskID, errorCode string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var task struct {
			Status    string `json:"status"`
			ErrorCode string `json:"error_code"`
		}
		api.request(t, http.MethodGet, "/api/v1/tasks/"+taskID, nil, http.StatusOK, &task)
		if task.Status == "failed" {
			if task.ErrorCode != errorCode {
				t.Fatalf("task %s error=%s want=%s", taskID, task.ErrorCode, errorCode)
			}
			return
		}
		if task.Status == "succeeded" || task.Status == "cancelled" {
			t.Fatalf("task %s unexpectedly ended as %s", taskID, task.Status)
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("task %s did not fail", taskID)
}

func controlConfig(label string) []byte {
	port := map[string]int{"initial": 7000, "revision-one": 65531, "revision-two": 65532, "cancel-slow": 65530}[label]
	return []byte(fmt.Sprintf(`serverAddr = "127.0.0.1"
serverPort = %d
loginFailExit = false
webServer.addr = "127.0.0.1"
webServer.port = 7400
webServer.user = "runtime-user"
webServer.password = "runtime-password"

[[proxies]]
name = "controlplane-runtime"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 16000
`, port))
}

func resignShortLivedCertificate(t *testing.T, nodeID string) string {
	t.Helper()
	key, cert := filepath.Join(stateDir, "pki/client-key.pem"), filepath.Join(stateDir, "pki/client.pem")
	tempDir := t.TempDir()
	csr := filepath.Join(tempDir, "client.csr")
	serial := filepath.Join(tempDir, "ca.srl")
	args := [][]string{
		{"req", "-new", "-key", key, "-subj", "/CN=" + nodeID, "-addext", "subjectAltName=DNS:" + nodeID + ",URI:spiffe://frp-admin/client/" + nodeID, "-out", csr},
		{"x509", "-req", "-in", csr, "-CA", "/control-data/pki/ca.crt", "-CAkey", "/control-data/pki/ca.key", "-CAserial", serial, "-CAcreateserial", "-days", "1", "-sha256", "-copy_extensions", "copy", "-out", cert},
	}
	for _, commandArgs := range args {
		if output, err := exec.Command("openssl", commandArgs...).CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %v output=%s", commandArgs, err, output)
		}
	}
	return readCertificate(t).SerialNumber.String()
}

func readCertificate(t *testing.T) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(stateDir, "pki/client.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("client certificate is not PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func waitCertificateRotation(t *testing.T, nodeID, oldSerial string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		certificate := readCertificate(t)
		if certificate.SerialNumber.String() != oldSerial && time.Until(certificate.NotAfter) > 20*24*time.Hour {
			if len(certificate.DNSNames) != 1 || certificate.DNSNames[0] != nodeID || len(certificate.URIs) != 1 || certificate.URIs[0].String() != "spiffe://frp-admin/client/"+nodeID {
				t.Fatalf("rotated certificate identity mismatch: DNS=%v URI=%v", certificate.DNSNames, certificate.URIs)
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("certificate serial %s was not rotated", oldSerial)
}

func runSystemctl(t *testing.T, args ...string) {
	t.Helper()
	output, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("systemctl %v: %v output=%s", args, err, output)
	}
}

func waitNodeOnline(t *testing.T, api *controlAPI, nodeID string) {
	t.Helper()
	waitNodeStatus(t, api, nodeID, "online")
}

func waitNodeStatus(t *testing.T, api *controlAPI, nodeID, want string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var node struct {
			Status string `json:"status"`
		}
		api.request(t, http.MethodGet, "/api/v1/nodes/"+nodeID, nil, http.StatusOK, &node)
		if node.Status == want {
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("node did not become %s", want)
}

func serviceAction(t *testing.T, api *controlAPI, nodeID, action string) string {
	t.Helper()
	var task struct {
		ID string `json:"id"`
	}
	api.request(t, http.MethodPost, "/api/v1/nodes/"+nodeID+"/service-actions", map[string]any{"action": action}, http.StatusAccepted, &task)
	return task.ID
}

func createRevision(t *testing.T, api *controlAPI, nodeID string, content []byte) string {
	t.Helper()
	var revision struct {
		ID string `json:"id"`
	}
	api.request(t, http.MethodPost, "/api/v1/nodes/"+nodeID+"/config-revisions", map[string]any{
		"content": string(content), "format": "toml", "strategy": "restart",
	}, http.StatusCreated, &revision)
	return revision.ID
}

func deployRevision(t *testing.T, api *controlAPI, revisionID string) string {
	t.Helper()
	var task struct {
		ID string `json:"id"`
	}
	api.request(t, http.MethodPost, "/api/v1/config-revisions/"+revisionID+"/deploy", nil, http.StatusAccepted, &task)
	return task.ID
}

func waitTask(t *testing.T, api *controlAPI, taskID, want string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var task struct {
			Status       string `json:"status"`
			ErrorCode    string `json:"error_code"`
			ErrorMessage string `json:"error_message"`
		}
		api.request(t, http.MethodGet, "/api/v1/tasks/"+taskID, nil, http.StatusOK, &task)
		if task.Status == want {
			return
		}
		if task.Status == "failed" || task.Status == "cancelled" {
			t.Fatalf("task %s ended as %s: %s %s", taskID, task.Status, task.ErrorCode, task.ErrorMessage)
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("task %s did not reach %s", taskID, want)
}

func taskState(t *testing.T, api *controlAPI, taskID string) string {
	t.Helper()
	var task struct {
		Status       string `json:"status"`
		ErrorCode    string `json:"error_code"`
		ErrorMessage string `json:"error_message"`
	}
	api.request(t, http.MethodGet, "/api/v1/tasks/"+taskID, nil, http.StatusOK, &task)
	return task.Status
}

func waitTaskRunning(t *testing.T, api *controlAPI, taskID string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		state := taskState(t, api, taskID)
		if state == "running" {
			return
		}
		if state == "failed" || state == "cancelled" || state == "succeeded" {
			t.Fatalf("task %s became terminal before cancellation: %s", taskID, state)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("task %s did not enter running", taskID)
}

func assertTaskState(t *testing.T, api *controlAPI, taskID, want string) {
	t.Helper()
	if got := taskState(t, api, taskID); got != want {
		t.Fatalf("task %s state=%s want=%s", taskID, got, want)
	}
}

func assertConfig(t *testing.T, label string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		t.Fatal(err)
	}
	port := map[string]int{"revision-one": 65531, "revision-two": 65532}[label]
	if !bytes.Contains(data, []byte(fmt.Sprintf("serverPort = %d", port))) {
		t.Fatalf("config does not contain %q: %s", label, data)
	}
}
