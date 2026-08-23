package e2e

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	agentconfig "github.com/frp-admin/frp-admin/agent/internal/config"
	"github.com/frp-admin/frp-admin/agent/internal/configmgr"
	"github.com/frp-admin/frp-admin/agent/internal/executor"
	"github.com/frp-admin/frp-admin/agent/internal/frpadmin"
	"github.com/frp-admin/frp-admin/agent/internal/inventory"
	"github.com/frp-admin/frp-admin/agent/internal/journal"
	"github.com/frp-admin/frp-admin/agent/internal/roothelper"
	"github.com/frp-admin/frp-admin/agent/internal/service"
	"github.com/frp-admin/frp-admin/agent/internal/upgrader"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

const (
	binaryPath  = "/opt/frp/bin/frpc"
	configPath  = "/etc/frp/frpc.toml"
	stateDir    = "/var/lib/frp-agent"
	serviceName = "frpc.service"
)

func requireSystemd(t *testing.T) {
	t.Helper()
	if os.Getenv("FRP_SYSTEMD_E2E") != "1" {
		t.Skip("set FRP_SYSTEMD_E2E=1 inside the privileged systemd fixture")
	}
}

func Test07PrivilegedHelperProbe(t *testing.T) {
	requireSystemd(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := roothelper.Client{SocketPath: "/run/frp-agent-helper.sock"}
	if err := client.Probe(ctx); err != nil {
		response, requestErr := client.Execute(ctx, roothelper.Request{Operation: roothelper.OperationProbe})
		identity, _ := exec.Command("systemctl", "show", "frpc.service", "--property=User,Group,DynamicUser", "--no-pager").CombinedOutput()
		stat, _ := exec.Command("stat", "-c", "%u:%g %a", configPath, binaryPath).CombinedOutput()
		t.Fatalf("probe=%v response=%+v request_err=%v identity=%q stat=%q", err, response, requestErr, identity, stat)
	}
	if err := client.ProbeService(ctx); err != nil {
		t.Fatalf("service probe: %v", err)
	}
	response, err := client.Execute(ctx, roothelper.Request{Operation: roothelper.OperationServiceRestart})
	if err != nil || response.ErrorCode != 0 || response.ServiceStatus.GetState() != agentv1.ServiceState_SERVICE_STATE_ACTIVE {
		t.Fatalf("typed service restart response=%+v err=%v", response, err)
	}
}

func Test08PrivilegedHelperScanAndPermissionRepair(t *testing.T) {
	requireSystemd(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client := roothelper.Client{SocketPath: "/run/frp-agent-helper.sock"}
	scan := client.Collect(ctx)
	if len(scan.CompletedKinds) == 0 {
		t.Fatalf("scan=%+v", scan)
	}
	sha, err := client.InspectSHA(ctx)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Execute(ctx, roothelper.Request{Operation: roothelper.OperationRestrictPermissions, ExpectedCurrentSHA: sha})
	if err != nil || response.ErrorCode != 0 || !response.Changed {
		identity, _ := exec.Command("systemctl", "show", "frpc.service", "--property=User,Group,DynamicUser", "--no-pager").CombinedOutput()
		stat, _ := exec.Command("stat", "-c", "%u:%g %a", configPath).CombinedOutput()
		t.Fatalf("response=%+v err=%v identity=%q stat=%q", response, err, identity, stat)
	}
	after := client.Collect(ctx)
	for _, finding := range after.Findings {
		if finding.GetKind() == agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_CONFIG_TOKEN_PERMISSIONS {
			t.Fatalf("permission risk remains after repair: %+v", finding)
		}
	}
}

func Test09PrivilegedHelperAdminLoopbackRepair(t *testing.T) {
	requireSystemd(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := roothelper.Client{SocketPath: "/run/frp-agent-helper.sock"}
	if err := client.Probe(ctx); err != nil {
		t.Fatal(err)
	}
	oldSHA, err := client.InspectSHA(ctx)
	if err != nil {
		t.Fatal(err)
	}
	candidate := []byte("bindAddr = \"127.0.0.1\"\nbindPort = 17000\nwebServer.addr = \"127.0.0.1\"\nwebServer.port = 17500\n")
	response, err := client.Execute(ctx, roothelper.Request{Operation: roothelper.OperationApplyAdminLoopback,
		ExpectedCurrentSHA: oldSHA, CandidateRevision: "e2e-admin-loopback", CandidateSHA: digest(candidate),
		CandidateContent: candidate, CandidateStrategy: "restart"})
	if err != nil || response.ErrorCode != 0 || !response.Changed || !response.BackupCreated {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	after := client.Collect(ctx)
	for _, finding := range after.Findings {
		if finding.GetKind() == agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_ADMIN_API_NON_LOOPBACK {
			t.Fatalf("admin API risk remains: %+v", finding)
		}
	}
	if out, err := exec.Command("systemctl", "is-active", "frps.service").CombinedOutput(); err != nil {
		t.Fatalf("frps not active: %v %s", err, out)
	}
}

func Test10PrivilegedHelperAdminRollback(t *testing.T) {
	requireSystemd(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := roothelper.Client{SocketPath: "/run/frp-agent-helper.sock"}
	oldSHA, err := client.InspectSHA(ctx)
	if err != nil {
		t.Fatal(err)
	}
	candidate := []byte("# E2E_FAIL_START_ONCE\nbindAddr = \"127.0.0.1\"\nbindPort = 17000\nwebServer.addr = \"127.0.0.1\"\nwebServer.port = 17500\n")
	response, err := client.Execute(ctx, roothelper.Request{Operation: roothelper.OperationApplyAdminLoopback,
		ExpectedCurrentSHA: oldSHA, CandidateRevision: "e2e-admin-rollback", CandidateSHA: digest(candidate),
		CandidateContent: candidate, CandidateStrategy: "restart"})
	if err != nil || response.ErrorCode != agentv1.ErrorCode_ERROR_CODE_SERVICE_OPERATION_FAILED ||
		!response.Changed || !response.RollbackAttempted || !response.RollbackSucceeded {
		t.Fatalf("response=%+v err=%v", response, err)
	}
	afterSHA, err := client.InspectSHA(ctx)
	if err != nil || afterSHA != oldSHA {
		t.Fatalf("rollback sha=%s want=%s err=%v", afterSHA, oldSHA, err)
	}
	if out, err := exec.Command("systemctl", "is-active", "frps.service").CombinedOutput(); err != nil {
		t.Fatalf("frps not active after rollback: %v %s", err, out)
	}
}

func systemd() *service.Systemd {
	return service.NewSystemd(serviceName, binaryPath, configPath, "client")
}
func validConfig(label string) []byte {
	return []byte("# " + label + "\nserverAddr = \"127.0.0.1\"\nserverPort = 65534\nloginFailExit = false\n")
}
func digest(data []byte) string { value := sha256.Sum256(data); return hex.EncodeToString(value[:]) }

func Test01ServiceLifecycle(t *testing.T) {
	requireSystemd(t)
	ctx := context.Background()
	manager := systemd()
	status, err := manager.Status(ctx)
	if err != nil || status.GetState() != agentv1.ServiceState_SERVICE_STATE_ACTIVE {
		t.Fatalf("initial status=%v err=%v", status, err)
	}
	if _, err := manager.Act(ctx, agentv1.ServiceAction_SERVICE_ACTION_STOP); err != nil {
		t.Fatal(err)
	}
	status, err = manager.Status(ctx)
	if err != nil || status.GetState() != agentv1.ServiceState_SERVICE_STATE_INACTIVE {
		t.Fatalf("stopped status=%v err=%v", status, err)
	}
	if _, err := manager.Act(ctx, agentv1.ServiceAction_SERVICE_ACTION_START); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Act(ctx, agentv1.ServiceAction_SERVICE_ACTION_RESTART); err != nil {
		t.Fatal(err)
	}
	if err := manager.Healthy(ctx); err != nil {
		t.Fatal(err)
	}
}

func configManager(t *testing.T, lifecycle configmgr.Lifecycle) *configmgr.Manager {
	t.Helper()
	m, err := configmgr.New(configmgr.Options{Role: "client", BinaryPath: binaryPath, ConfigPath: configPath, StateDir: stateDir, Verifier: configmgr.CLIVerifier{}, Lifecycle: lifecycle, HealthTimeout: 10 * time.Second, HealthPoll: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func Test02ConfigTransactions(t *testing.T) {
	requireSystemd(t)
	ctx := context.Background()
	lifecycle := systemd()
	manager := configManager(t, lifecycle)
	valid := validConfig("valid-apply")
	if err := manager.Apply(ctx, "e2e-valid", digest(valid), valid, "restart"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(configPath)
	if string(got) != string(valid) {
		t.Fatal("valid config was not installed")
	}
	invalid := []byte("[[[ invalid toml")
	err := manager.Apply(ctx, "e2e-invalid", digest(invalid), invalid, "restart")
	var configErr *configmgr.Error
	if !errors.As(err, &configErr) || configErr.Code != agentv1.ErrorCode_ERROR_CODE_VERIFY_FAILED {
		t.Fatalf("verify error=%v", err)
	}
	got, _ = os.ReadFile(configPath)
	if string(got) != string(valid) {
		t.Fatal("invalid config replaced current config")
	}
	failing := append([]byte("# E2E_FAIL_START_ONCE\n"), valid...)
	err = manager.Apply(ctx, "e2e-health-fail", digest(failing), failing, "restart")
	if err == nil {
		t.Fatal("expected restart failure")
	}
	got, _ = os.ReadFile(configPath)
	if string(got) != string(valid) {
		t.Fatalf("previous config was not restored: %q", got)
	}
	if err := lifecycle.Healthy(ctx); err != nil {
		t.Fatal(err)
	}
}

type blockingLifecycle struct {
	delegate         *service.Systemd
	entered, release chan struct{}
	once             sync.Once
}

func (b *blockingLifecycle) ApplyConfigStrategy(ctx context.Context, strategy string) error {
	b.once.Do(func() { close(b.entered); <-b.release })
	return b.delegate.ApplyConfigStrategy(ctx, strategy)
}
func (b *blockingLifecycle) Healthy(ctx context.Context) error { return b.delegate.Healthy(ctx) }
func (b *blockingLifecycle) Controllable(ctx context.Context) error {
	return b.delegate.Controllable(ctx)
}

func Test03ConcurrentMutationRejected(t *testing.T) {
	requireSystemd(t)
	ctx := context.Background()
	target := systemd()
	blocking := &blockingLifecycle{delegate: target, entered: make(chan struct{}), release: make(chan struct{})}
	configs := configManager(t, blocking)
	j, err := journal.Open(filepath.Join(stateDir, "e2e-commands.db"), 100)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	commands := executor.New(j, inventory.New(binaryPath, configPath, serviceName, "configured", nil, target), target).WithConfigManager(configs)
	content := validConfig("concurrent")
	first := &agentv1.Command{CommandId: "e2e-concurrent-1", Action: &agentv1.Command_ApplyConfig{ApplyConfig: &agentv1.ApplyConfigCommand{Revision: "e2e-concurrent", Sha256: digest(content), Content: content, Strategy: "restart"}}}
	done := make(chan *agentv1.CommandResult, 1)
	go func() { done <- commands.Execute(ctx, first) }()
	select {
	case <-blocking.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("first command did not enter mutation")
	}
	second := commands.Execute(ctx, &agentv1.Command{CommandId: "e2e-concurrent-2", Action: &agentv1.Command_Service{Service: &agentv1.ServiceCommand{Action: agentv1.ServiceAction_SERVICE_ACTION_RESTART}}})
	if second.GetErrorCode() != agentv1.ErrorCode_ERROR_CODE_OPERATION_IN_PROGRESS {
		t.Fatalf("second result=%v", second)
	}
	close(blocking.release)
	if result := <-done; result.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED {
		t.Fatalf("first result=%v", result)
	}
}

func makeArchive(t *testing.T, suffix string) []byte {
	t.Helper()
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	binary = append(binary, []byte(suffix)...)
	tmp, err := os.CreateTemp(t.TempDir(), "*.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(tmp)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "frp_0.70.0_linux/frpc", Mode: 0755, Size: int64(len(binary)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(binary); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func upgradeManager(t *testing.T, artifact []byte) (*upgrader.Manager, func()) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(artifact) }))
	parsed, _ := url.Parse(server.URL)
	downloader := upgrader.HTTPDownloader{
		Client: server.Client(),
		LookupIP: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.1.1.1")}, nil
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, parsed.Host)
		},
	}
	m, err := upgrader.New(upgrader.Options{Role: "client", BinaryPath: binaryPath, ConfigPath: configPath, StateDir: stateDir, AllowedHosts: []string{parsed.Hostname()}, MaxArtifactBytes: 256 << 20, Downloader: downloader, Runner: upgrader.CLIRunner{}, Lifecycle: systemd(), HealthTimeout: 10 * time.Second, HealthPoll: 100 * time.Millisecond, StableWindow: 500 * time.Millisecond})
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	managerURLs[m] = server.URL
	return m, func() { delete(managerURLs, m); server.Close() }
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return digest(data)
}

func Test04HTTPSUpgradeAndRollback(t *testing.T) {
	requireSystemd(t)
	ctx := context.Background()
	artifact := makeArchive(t, "success")
	manager, closeServer := upgradeManager(t, artifact)
	before := fileDigest(t, binaryPath)
	if err := manager.Upgrade(ctx, "v0.70.0", managerURL(t, manager), digest(artifact)); err != nil {
		closeServer()
		t.Fatal(err)
	}
	closeServer()
	after := fileDigest(t, binaryPath)
	if after == before {
		t.Fatal("successful upgrade did not replace binary")
	}
	badArtifact := makeArchive(t, "bad-checksum")
	badManager, badClose := upgradeManager(t, badArtifact)
	err := badManager.Upgrade(ctx, "v0.70.0", managerURL(t, badManager), "bad")
	badClose()
	var upgradeErr *upgrader.Error
	if !errors.As(err, &upgradeErr) || upgradeErr.Code != agentv1.ErrorCode_ERROR_CODE_CHECKSUM_MISMATCH {
		t.Fatalf("checksum error=%v", err)
	}
	if fileDigest(t, binaryPath) != after {
		t.Fatal("bad checksum changed binary")
	}
	failArtifact := makeArchive(t, "start-failure")
	failManager, failClose := upgradeManager(t, failArtifact)
	if err := os.WriteFile("/run/frp-admin-e2e/fail-upgrade-start", []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	err = failManager.Upgrade(ctx, "v0.70.0", managerURL(t, failManager), digest(failArtifact))
	failClose()
	if err == nil {
		t.Fatal("expected start failure")
	}
	if fileDigest(t, binaryPath) != after {
		t.Fatal("start failure did not restore previous binary")
	}
	if err := systemd().Healthy(ctx); err != nil {
		t.Fatal(err)
	}
}

var managerURLs = map[*upgrader.Manager]string{}

func managerURL(t *testing.T, m *upgrader.Manager) string {
	t.Helper()
	url := managerURLs[m]
	if url == "" {
		t.Fatal("missing fixture URL")
	}
	return url
}

func Test05StartupCrashRecovery(t *testing.T) {
	requireSystemd(t)
	t.Cleanup(func() {
		if out, err := exec.Command("chown", "-R", "root:root", "/etc/frp", "/opt/frp/bin").CombinedOutput(); err != nil {
			t.Errorf("restore root managed ownership: %v: %s", err, out)
		}
	})
	ctx := context.Background()
	if out, err := exec.Command("systemctl", "stop", "frp-agent.service").CombinedOutput(); err != nil {
		t.Fatalf("stop agent: %v: %s", err, out)
	}
	originalConfig, _ := os.ReadFile(configPath)
	configBackup := filepath.Join(stateDir, "backups", "config", "e2e-crash.toml")
	if err := os.MkdirAll(filepath.Dir(configBackup), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configBackup, originalConfig, 0640); err != nil {
		t.Fatal(err)
	}
	configTx := map[string]any{"backup": map[string]any{"path": configBackup}, "strategy": "restart", "mode": 416, "previous": map[string]any{}}
	writeJSON(t, filepath.Join(stateDir, "transactions", "config.json"), configTx)
	if err := os.WriteFile(configPath, []byte("partial config"), 0640); err != nil {
		t.Fatal(err)
	}
	chownAgentManagedPaths(t)
	if out, err := exec.Command("systemctl", "start", "frp-agent.service").CombinedOutput(); err != nil {
		t.Fatalf("start agent config recovery: %v: %s", err, out)
	}
	waitActive(t, "frp-agent.service")
	waitFileContent(t, configPath, originalConfig)
	if out, err := exec.Command("systemctl", "stop", "frp-agent.service").CombinedOutput(); err != nil {
		t.Fatalf("stop agent: %v: %s", err, out)
	}
	originalBinary, _ := os.ReadFile(binaryPath)
	binaryBackup := filepath.Join(stateDir, "backups", "bin", "previous")
	if err := os.MkdirAll(filepath.Dir(binaryBackup), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binaryBackup, originalBinary, 0755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("systemctl", "stop", serviceName).CombinedOutput(); err != nil {
		t.Fatalf("stop frpc before simulated crash: %v: %s", err, out)
	}
	writeJSON(t, filepath.Join(stateDir, "transactions", "upgrade.json"), map[string]any{"backup": binaryBackup, "mode": 493})
	if err := os.WriteFile(binaryPath, []byte("partial binary"), 0755); err != nil {
		t.Fatal(err)
	}
	chownAgentManagedPaths(t)
	if out, err := exec.Command("systemctl", "start", "frp-agent.service").CombinedOutput(); err != nil {
		t.Fatalf("start agent binary recovery: %v: %s", err, out)
	}
	waitActive(t, "frp-agent.service")
	waitFileContent(t, binaryPath, originalBinary)
	if err := systemd().Healthy(ctx); err != nil {
		t.Fatal(err)
	}
}

func chownAgentManagedPaths(t *testing.T) {
	t.Helper()
	if out, err := exec.Command("chown", "-R", "frp-agent:frp-agent", stateDir, "/etc/frp", "/opt/frp/bin").CombinedOutput(); err != nil {
		t.Fatalf("restore simulated agent ownership: %v: %s", err, out)
	}
}

func Test06RealFrpAdminAPIRuntime(t *testing.T) {
	requireSystemd(t)
	frpsConfig := []byte(`bindAddr = "127.0.0.1"
bindPort = 7000
webServer.addr = "127.0.0.1"
webServer.port = 7500
webServer.user = "runtime-user"
webServer.password = "runtime-password"
`)
	frpcConfig := []byte(`serverAddr = "127.0.0.1"
serverPort = 7000
loginFailExit = true
webServer.addr = "127.0.0.1"
webServer.port = 7400
webServer.user = "runtime-user"
webServer.password = "runtime-password"

[[proxies]]
name = "runtime-tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 16000
`)
	if err := os.WriteFile("/etc/frp/frps.toml", frpsConfig, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, frpcConfig, 0640); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"restart", "frps.service"}} {
		if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
			t.Fatalf("systemctl %v: %v: %s", args, err, out)
		}
	}
	waitActive(t, "frps.service")
	waitTCP(t, "127.0.0.1:7000")
	if out, err := exec.Command("systemctl", "restart", serviceName).CombinedOutput(); err != nil {
		t.Fatalf("restart %s: %v: %s", serviceName, err, out)
	}
	waitActive(t, serviceName)

	collect := func(role, endpoint string) *agentv1.RuntimeSnapshot {
		client, err := frpadmin.New(role, agentconfig.AdminAPI{Endpoint: endpoint, Username: "runtime-user", Password: "runtime-password", Timeout: 3 * time.Second, MaxResponseBytes: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if snapshot, collectErr := client.Collect(context.Background(), "full"); collectErr == nil && len(snapshot.GetProxies()) > 0 {
				return snapshot
			}
			time.Sleep(200 * time.Millisecond)
		}
		snapshot, err := client.Collect(context.Background(), "full")
		t.Fatalf("collect %s runtime: snapshot=%v err=%v", role, snapshot, err)
		return nil
	}
	clientSnapshot := collect("client", "http://127.0.0.1:7400")
	if clientSnapshot.GetProxies()[0].GetName() != "runtime-tcp" || clientSnapshot.GetProxies()[0].GetStatus() != agentv1.RuntimeProxyStatus_RUNTIME_PROXY_STATUS_RUNNING {
		t.Fatalf("client runtime=%v", clientSnapshot)
	}
	serverSnapshot := collect("server", "http://127.0.0.1:7500")
	if serverSnapshot.GetServer().GetProxyCount() == 0 || serverSnapshot.GetProxies()[0].GetTraffic() == nil {
		t.Fatalf("server runtime=%v", serverSnapshot)
	}

	badAuth, err := frpadmin.New("client", agentconfig.AdminAPI{Endpoint: "http://127.0.0.1:7400", Username: "runtime-user", Password: "do-not-leak-this", Timeout: time.Second, MaxResponseBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	_, err = badAuth.Collect(context.Background(), "summary")
	var runtimeErr *frpadmin.Error
	if !errors.As(err, &runtimeErr) || runtimeErr.Code != agentv1.ErrorCode_ERROR_CODE_ADMIN_API_UNAVAILABLE || strings.Contains(err.Error(), "do-not-leak-this") {
		t.Fatalf("bad-auth error=%v", err)
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func waitActive(t *testing.T, unit string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if exec.Command("systemctl", "is-active", "--quiet", unit).Run() == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	out, _ := exec.Command("systemctl", "status", unit, "--no-pager").CombinedOutput()
	t.Fatalf("unit did not become active: %s", out)
}

func waitTCP(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("TCP endpoint %s did not become ready", address)
}

func waitFileContent(t *testing.T, path string, expected []byte) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if content, err := os.ReadFile(path); err == nil && string(content) == string(expected) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	content, err := os.ReadFile(path)
	t.Fatalf("file did not recover: path=%s content=%q err=%v", path, content, err)
}
