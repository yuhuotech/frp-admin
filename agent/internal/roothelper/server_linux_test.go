//go:build linux

package roothelper

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/frp-admin/frp-admin/agent/internal/configmgr"
	"github.com/frp-admin/frp-admin/agent/internal/service"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

type helperRunner struct {
	calls      []string
	failReset  bool
	finalState string
	states     []string
	showCount  int
}

func (r *helperRunner) CombinedOutput(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if len(args) > 0 && args[0] == "reset-failed" && r.failReset {
		return nil, errors.New("reset failed")
	}
	if len(args) > 0 && args[0] == "show" {
		state := r.finalState
		if r.showCount < len(r.states) {
			state = r.states[r.showCount]
		}
		r.showCount++
		if state == "" {
			state = "active"
		}
		return []byte("ActiveState=" + state + "\nSubState=running\nExecMainPID=1\nExecMainStatus=0\n"), nil
	}
	return nil, nil
}

func stableTestServer(config Config, runner service.Runner) Server {
	current := time.Unix(1, 0)
	return Server{
		Config: config, Runner: runner, stableWindow: 200 * time.Millisecond, pollInterval: 100 * time.Millisecond,
		now: func() time.Time { return current },
		wait: func(ctx context.Context, delay time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				current = current.Add(delay)
				return nil
			}
		},
	}
}

func TestExactLoopbackChangeRejectsAdditionalMutation(t *testing.T) {
	current := []byte("bindPort=7000\n[webServer]\naddr=\"0.0.0.0\"\nport=7500\n")
	valid := []byte("bindPort=7000\n[webServer]\naddr=\"127.0.0.1\"\nport=7500\n")
	invalid := []byte("bindPort=7001\n[webServer]\naddr=\"127.0.0.1\"\nport=7500\n")
	if !exactLoopbackChange(current, valid) || exactLoopbackChange(current, invalid) {
		t.Fatal("loopback semantic allowlist failed")
	}
}

func TestPermissionMarkerRecoveryRestoresModeDurably(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "frps.toml")
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("x=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(configPath)
	stat := info.Sys().(*syscall.Stat_t)
	marker := permissionMarker{Device: uint64(stat.Dev), Inode: uint64(stat.Ino), Mode: 0644}
	if err := writeMarker(filepath.Join(stateDir, "permission-mode.json"), marker); err != nil {
		t.Fatal(err)
	}
	server := Server{Config: Config{ConfigPath: configPath, StateDir: stateDir}}
	if err := server.recoverPermission(); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(configPath)
	if info.Mode().Perm() != 0644 {
		t.Fatalf("mode=%04o", info.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(stateDir, "permission-mode.json")); !os.IsNotExist(err) {
		t.Fatalf("marker remains: %v", err)
	}
}

func TestConfigErrorResponsePreservesTransactionOutcome(t *testing.T) {
	response := configErrorResponse(&configmgr.Error{
		Code:              agentv1.ErrorCode_ERROR_CODE_SERVICE_OPERATION_FAILED,
		Err:               errors.New("restart failed"),
		BackupCreated:     true,
		Changed:           true,
		RollbackAttempted: true,
		RollbackSucceeded: true,
	})
	if response.ErrorCode != agentv1.ErrorCode_ERROR_CODE_SERVICE_OPERATION_FAILED ||
		!response.BackupCreated || !response.Changed || !response.RollbackAttempted || !response.RollbackSucceeded {
		t.Fatalf("response=%+v", response)
	}
}

func TestSecureManagedParentRejectsWritableDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	if err := secureManagedParent(dir); err == nil {
		t.Fatal("world-writable managed parent was accepted")
	}
}

func TestTypedServiceRestartReturnsVerifiedStatus(t *testing.T) {
	runner := &helperRunner{finalState: "active"}
	server := stableTestServer(Config{Role: "client", ServiceName: "frpc.service", BinaryPath: "/opt/frp/bin/frpc", ConfigPath: "/etc/frp/frpc.toml"}, runner)
	response := server.Handle(context.Background(), Request{Operation: OperationServiceRestart})
	if response.ErrorCode != 0 || response.ServiceStatus.GetState() != agentv1.ServiceState_SERVICE_STATE_ACTIVE {
		t.Fatalf("response=%+v", response)
	}
	want := []string{
		"systemctl reset-failed frpc.service",
		"systemctl restart frpc.service",
		"systemctl show frpc.service --property=ActiveState,SubState,ExecMainPID,ExecMainStatus --no-pager",
		"systemctl show frpc.service --property=ActiveState,SubState,ExecMainPID,ExecMainStatus --no-pager",
		"systemctl show frpc.service --property=ActiveState,SubState,ExecMainPID,ExecMainStatus --no-pager",
	}
	if !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls=%v want=%v", runner.calls, want)
	}
}

func TestServiceResetFailureStopsBeforeMutation(t *testing.T) {
	runner := &helperRunner{failReset: true}
	server := Server{Config: Config{Role: "server", ServiceName: "frps.service"}, Runner: runner}
	response := server.Handle(context.Background(), Request{Operation: OperationServiceStart})
	if response.ErrorCode != agentv1.ErrorCode_ERROR_CODE_SERVICE_OPERATION_FAILED {
		t.Fatalf("response=%+v", response)
	}
	if want := []string{"systemctl reset-failed frps.service", "systemctl show frps.service --property=ActiveState,SubState,ExecMainPID,ExecMainStatus --no-pager"}; !reflect.DeepEqual(runner.calls, want) {
		t.Fatalf("calls=%v want=%v", runner.calls, want)
	}
	if response.ServiceStatus == nil {
		t.Fatal("failure response omitted best-effort service status")
	}
}

func TestServiceActionRejectsUnexpectedFinalState(t *testing.T) {
	runner := &helperRunner{finalState: "inactive"}
	server := stableTestServer(Config{Role: "client", ServiceName: "frpc.service"}, runner)
	server.wait = func(context.Context, time.Duration) error { return context.DeadlineExceeded }
	response := server.Handle(context.Background(), Request{Operation: OperationServiceRestart})
	if response.ErrorCode != agentv1.ErrorCode_ERROR_CODE_SERVICE_OPERATION_FAILED ||
		response.Diagnostic != "service did not reach the requested state" ||
		response.ServiceStatus.GetState() != agentv1.ServiceState_SERVICE_STATE_INACTIVE {
		t.Fatalf("response=%+v", response)
	}
}

func TestServiceActionRequiresContinuousStableWindow(t *testing.T) {
	runner := &helperRunner{states: []string{"active", "inactive", "active", "active", "active"}}
	server := stableTestServer(Config{Role: "client", ServiceName: "frpc.service"}, runner)
	response := server.Handle(context.Background(), Request{Operation: OperationServiceRestart})
	if response.ErrorCode != 0 || response.ServiceStatus.GetState() != agentv1.ServiceState_SERVICE_STATE_ACTIVE {
		t.Fatalf("response=%+v", response)
	}
	if runner.showCount != 5 {
		t.Fatalf("show count=%d want=5", runner.showCount)
	}
}

func TestServiceProbeIsDedicatedAndReadOnly(t *testing.T) {
	runner := &helperRunner{finalState: "inactive"}
	server := Server{Config: Config{Role: "client", ServiceName: "frpc.service"}, Runner: runner}
	response := server.Handle(context.Background(), Request{Operation: OperationProbeService})
	if response.ErrorCode != 0 || response.ServiceStatus.GetState() != agentv1.ServiceState_SERVICE_STATE_INACTIVE {
		t.Fatalf("response=%+v", response)
	}
	if len(runner.calls) != 1 || !strings.HasPrefix(runner.calls[0], "systemctl show frpc.service ") {
		t.Fatalf("probe calls=%v", runner.calls)
	}
}

func TestServiceOperationRejectsUnrelatedRequestFields(t *testing.T) {
	runner := &helperRunner{finalState: "active"}
	server := Server{Config: Config{Role: "client", ServiceName: "frpc.service"}, Runner: runner}
	response := server.Handle(context.Background(), Request{Operation: OperationServiceStart, CandidateStrategy: "restart"})
	if response.ErrorCode != agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND || len(runner.calls) != 0 {
		t.Fatalf("response=%+v calls=%v", response, runner.calls)
	}
}

func TestServiceProbeRejectsUnknownState(t *testing.T) {
	runner := &helperRunner{finalState: "mystery"}
	server := Server{Config: Config{Role: "client", ServiceName: "frpc.service"}, Runner: runner}
	response := server.Handle(context.Background(), Request{Operation: OperationProbeService})
	if response.ErrorCode != agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED {
		t.Fatalf("response=%+v", response)
	}
}

func TestDecodeConfigRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {
	valid := `{"Role":"client","BinaryPath":"/opt/frp/bin/frpc","ConfigPath":"/etc/frp/frpc.toml","ServiceName":"frpc.service","StateDir":"/var/lib/frp-agent-helper"}`
	for name, content := range map[string]string{
		"unknown":  strings.TrimSuffix(valid, "}") + `,"Unit":"frpc.service"}`,
		"trailing": valid + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeConfig(strings.NewReader(content)); err == nil {
				t.Fatal("unsafe helper config was accepted")
			}
		})
	}
}
