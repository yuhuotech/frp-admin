package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/frp-admin/frp-admin/agent/internal/configmgr"
	"github.com/frp-admin/frp-admin/agent/internal/frpadmin"
	"github.com/frp-admin/frp-admin/agent/internal/journal"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

type fakeTarget struct{ actions int }

type acceptingVerifier struct{}
type rejectingVerifier struct{ err error }

type fakeRuntimeCollector struct {
	snapshot *agentv1.RuntimeSnapshot
	err      error
}

type fakeRemediator struct {
	entered chan struct{}
	release chan struct{}
	calls   int
}

func (f *fakeRemediator) Repair(context.Context, *agentv1.RepairDeploymentRiskCommand) (*agentv1.RepairDeploymentRiskResult, error) {
	f.calls++
	if f.entered != nil {
		close(f.entered)
		<-f.release
	}
	return &agentv1.RepairDeploymentRiskResult{PrecheckPassed: true, Changed: true}, nil
}

func (f fakeRuntimeCollector) Collect(context.Context, string) (*agentv1.RuntimeSnapshot, error) {
	return f.snapshot, f.err
}

func (acceptingVerifier) Verify(context.Context, string, string) error   { return nil }
func (v rejectingVerifier) Verify(context.Context, string, string) error { return v.err }

func (f *fakeTarget) Status(context.Context) (*agentv1.ServiceStatus, error) {
	return &agentv1.ServiceStatus{State: agentv1.ServiceState_SERVICE_STATE_ACTIVE}, nil
}

func (f *fakeTarget) Act(context.Context, agentv1.ServiceAction) (*agentv1.ServiceStatus, error) {
	f.actions++
	return &agentv1.ServiceStatus{State: agentv1.ServiceState_SERVICE_STATE_ACTIVE}, nil
}

func (f *fakeTarget) Collect(context.Context) (*agentv1.Inventory, error) {
	return &agentv1.Inventory{Hostname: "node-a"}, nil
}

func (f *fakeTarget) ApplyConfigStrategy(context.Context, string) error { return nil }
func (f *fakeTarget) Healthy(context.Context) error                     { return nil }
func (f *fakeTarget) Controllable(context.Context) error                { return nil }

func TestIdempotentReplayDoesNotRepeatAction(t *testing.T) {
	j, err := journal.Open(filepath.Join(t.TempDir(), "commands.db"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	target := &fakeTarget{}
	e := New(j, target, target)
	first := &agentv1.Command{CommandId: "command-1", IdempotencyKey: "request-1", Action: &agentv1.Command_Service{
		Service: &agentv1.ServiceCommand{Action: agentv1.ServiceAction_SERVICE_ACTION_RESTART},
	}}
	if got := e.Execute(context.Background(), first); got.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED {
		t.Fatalf("first: %v", got)
	}
	second := &agentv1.Command{CommandId: "command-2", IdempotencyKey: "request-1", Action: &agentv1.Command_Service{
		Service: &agentv1.ServiceCommand{Action: agentv1.ServiceAction_SERVICE_ACTION_RESTART},
	}}
	if got := e.Execute(context.Background(), second); got.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED || got.GetCommandId() != "command-2" {
		t.Fatalf("replay: %v", got)
	}
	if target.actions != 1 {
		t.Fatalf("action executed %d times", target.actions)
	}
}

func TestRejectExpiredCommand(t *testing.T) {
	j, err := journal.Open(filepath.Join(t.TempDir(), "commands.db"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	target := &fakeTarget{}
	e := New(j, target, target)
	result := e.Execute(context.Background(), &agentv1.Command{CommandId: "expired", ExpiresAtUnixMs: 1,
		Action: &agentv1.Command_Inspect{Inspect: &agentv1.InspectCommand{}}})
	if result.GetErrorCode() != agentv1.ErrorCode_ERROR_CODE_COMMAND_EXPIRED {
		t.Fatalf("result: %v", result)
	}
}

func TestApplyConfigErrorCodeIsMapped(t *testing.T) {
	dir := t.TempDir()
	j, err := journal.Open(filepath.Join(dir, "commands.db"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	target := &fakeTarget{}
	configs, err := configmgr.New(configmgr.Options{Role: "client", BinaryPath: "/bin/frpc", ConfigPath: filepath.Join(dir, "frpc.toml"),
		StateDir: filepath.Join(dir, "state"), Verifier: acceptingVerifier{}, Lifecycle: target})
	if err != nil {
		t.Fatal(err)
	}
	e := New(j, target, target).WithConfigManager(configs)
	result := e.Execute(context.Background(), &agentv1.Command{CommandId: "apply-invalid-checksum", Action: &agentv1.Command_ApplyConfig{
		ApplyConfig: &agentv1.ApplyConfigCommand{Revision: "r1", Sha256: "wrong", Content: []byte("x"), Strategy: "restart"},
	}})
	if result.GetErrorCode() != agentv1.ErrorCode_ERROR_CODE_CHECKSUM_MISMATCH {
		t.Fatalf("result: %v", result)
	}
}

func TestConfigVerifierOutputDoesNotReachResultOrJournal(t *testing.T) {
	dir := t.TempDir()
	j, err := journal.Open(filepath.Join(dir, "commands.db"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	target := &fakeTarget{}
	configPath := filepath.Join(dir, "frpc.toml")
	if err := os.WriteFile(configPath, []byte("old = true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	secret := "token=top-secret"
	configs, err := configmgr.New(configmgr.Options{Role: "client", BinaryPath: "/bin/frpc", ConfigPath: configPath,
		StateDir: filepath.Join(dir, "state"), Verifier: rejectingVerifier{err: errors.New("verify output: " + secret)}, Lifecycle: target})
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("token = \"materialized-secret\"\n")
	sum := sha256.Sum256(content)
	command := &agentv1.Command{CommandId: "apply-secret", IdempotencyKey: "apply-secret-once", Action: &agentv1.Command_ApplyConfig{
		ApplyConfig: &agentv1.ApplyConfigCommand{Revision: "r1", Sha256: hex.EncodeToString(sum[:]), Content: content, Strategy: "restart"},
	}}
	result := New(j, target, target).WithConfigManager(configs).Execute(context.Background(), command)
	if result.GetErrorCode() != agentv1.ErrorCode_ERROR_CODE_VERIFY_FAILED || strings.Contains(result.GetDiagnostic(), secret) {
		t.Fatalf("unsafe result=%v", result)
	}
	cached, ok, err := j.Get("command:" + command.GetCommandId())
	if err != nil || !ok || strings.Contains(cached.GetDiagnostic(), secret) {
		t.Fatalf("unsafe journal result=%v ok=%v err=%v", cached, ok, err)
	}
}

func TestCollectRuntimeReturnsTypedSnapshot(t *testing.T) {
	j, err := journal.Open(filepath.Join(t.TempDir(), "commands.db"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	target := &fakeTarget{}
	snapshot := &agentv1.RuntimeSnapshot{Role: agentv1.NodeRole_NODE_ROLE_CLIENT, Proxies: []*agentv1.RuntimeProxy{{Name: "ssh", Type: "tcp"}}}
	e := New(j, target, target).WithRuntimeCollector(fakeRuntimeCollector{snapshot: snapshot})
	result := e.Execute(context.Background(), &agentv1.Command{CommandId: "runtime", Action: &agentv1.Command_CollectRuntime{
		CollectRuntime: &agentv1.CollectRuntimeCommand{DetailLevel: "full"},
	}})
	if result.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED || result.GetRuntime().GetSnapshot().GetProxies()[0].GetName() != "ssh" {
		t.Fatalf("result=%v", result)
	}
}

func TestCollectRuntimeMapsAdminAPIError(t *testing.T) {
	j, err := journal.Open(filepath.Join(t.TempDir(), "commands.db"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	target := &fakeTarget{}
	e := New(j, target, target).WithRuntimeCollector(fakeRuntimeCollector{err: frpadmin.NewError(agentv1.ErrorCode_ERROR_CODE_ADMIN_API_UNAVAILABLE, errors.New("Admin API unavailable"))})
	result := e.Execute(context.Background(), &agentv1.Command{CommandId: "runtime-error", Action: &agentv1.Command_CollectRuntime{
		CollectRuntime: &agentv1.CollectRuntimeCommand{},
	}})
	if result.GetErrorCode() != agentv1.ErrorCode_ERROR_CODE_ADMIN_API_UNAVAILABLE {
		t.Fatalf("result=%v", result)
	}
}

func TestRepairDeploymentRiskIsIdempotentAndReturnsTypedResult(t *testing.T) {
	j, err := journal.Open(filepath.Join(t.TempDir(), "commands.db"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	target := &fakeTarget{}
	repairer := &fakeRemediator{}
	e := New(j, target, target).WithRemediator(repairer)
	command := func(id string) *agentv1.Command {
		return &agentv1.Command{CommandId: id, IdempotencyKey: "repair-once", Action: &agentv1.Command_RepairDeploymentRisk{
			RepairDeploymentRisk: &agentv1.RepairDeploymentRiskCommand{FindingId: "finding-1"},
		}}
	}
	first := e.Execute(context.Background(), command("repair-1"))
	second := e.Execute(context.Background(), command("repair-2"))
	if first.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED || !first.GetRepairDeploymentRisk().GetChanged() ||
		second.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_SUCCEEDED || repairer.calls != 1 {
		t.Fatalf("first=%v second=%v calls=%d", first, second, repairer.calls)
	}
}

func TestRepairDeploymentRiskUsesNodeMutationLock(t *testing.T) {
	j, err := journal.Open(filepath.Join(t.TempDir(), "commands.db"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	target := &fakeTarget{}
	repairer := &fakeRemediator{entered: make(chan struct{}), release: make(chan struct{})}
	e := New(j, target, target).WithRemediator(repairer)
	repair := &agentv1.Command{CommandId: "repair-blocking", Action: &agentv1.Command_RepairDeploymentRisk{
		RepairDeploymentRisk: &agentv1.RepairDeploymentRiskCommand{FindingId: "finding-1"}}}
	done := make(chan *agentv1.CommandResult, 1)
	go func() { done <- e.Execute(context.Background(), repair) }()
	<-repairer.entered
	concurrent := e.Execute(context.Background(), &agentv1.Command{CommandId: "concurrent-apply", Action: &agentv1.Command_ApplyConfig{
		ApplyConfig: &agentv1.ApplyConfigCommand{}}})
	if concurrent.GetErrorCode() != agentv1.ErrorCode_ERROR_CODE_OPERATION_IN_PROGRESS {
		t.Fatalf("concurrent=%v", concurrent)
	}
	close(repairer.release)
	<-done
}

type blockingTarget struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockingTarget) Status(context.Context) (*agentv1.ServiceStatus, error) {
	return &agentv1.ServiceStatus{State: agentv1.ServiceState_SERVICE_STATE_ACTIVE}, nil
}
func (b *blockingTarget) Act(context.Context, agentv1.ServiceAction) (*agentv1.ServiceStatus, error) {
	close(b.entered)
	<-b.release
	return b.Status(context.Background())
}
func (b *blockingTarget) Collect(context.Context) (*agentv1.Inventory, error) {
	return &agentv1.Inventory{}, nil
}

func TestConcurrentMutationIsRejectedAndJournaled(t *testing.T) {
	j, err := journal.Open(filepath.Join(t.TempDir(), "commands.db"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	target := &blockingTarget{entered: make(chan struct{}), release: make(chan struct{})}
	e := New(j, target, target)
	command := func(id string) *agentv1.Command {
		return &agentv1.Command{CommandId: id, Action: &agentv1.Command_Service{Service: &agentv1.ServiceCommand{Action: agentv1.ServiceAction_SERVICE_ACTION_RESTART}}}
	}
	done := make(chan *agentv1.CommandResult, 1)
	go func() { done <- e.Execute(context.Background(), command("first")) }()
	select {
	case <-target.entered:
	case <-time.After(time.Second):
		t.Fatal("first mutation did not start")
	}
	second := e.Execute(context.Background(), command("second"))
	if second.GetErrorCode() != agentv1.ErrorCode_ERROR_CODE_OPERATION_IN_PROGRESS {
		t.Fatalf("second=%v", second)
	}
	if cached, ok, err := e.Cached(command("second")); err != nil || !ok || cached.GetErrorCode() != agentv1.ErrorCode_ERROR_CODE_OPERATION_IN_PROGRESS {
		t.Fatalf("cached=%v ok=%v err=%v", cached, ok, err)
	}
	close(target.release)
	<-done
}

type cancellingTarget struct{ entered chan struct{} }

func (c *cancellingTarget) Status(context.Context) (*agentv1.ServiceStatus, error) {
	return &agentv1.ServiceStatus{State: agentv1.ServiceState_SERVICE_STATE_ACTIVE}, nil
}
func (c *cancellingTarget) Act(ctx context.Context, _ agentv1.ServiceAction) (*agentv1.ServiceStatus, error) {
	close(c.entered)
	<-ctx.Done()
	return nil, ctx.Err()
}
func (c *cancellingTarget) Collect(context.Context) (*agentv1.Inventory, error) {
	return &agentv1.Inventory{}, nil
}

func TestExplicitCancellationOverridesOperationError(t *testing.T) {
	j, err := journal.Open(filepath.Join(t.TempDir(), "commands.db"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	target := &cancellingTarget{entered: make(chan struct{})}
	e := New(j, target, target)
	ctx, cancel := context.WithCancelCause(context.Background())
	done := make(chan *agentv1.CommandResult, 1)
	go func() {
		done <- e.Execute(ctx, &agentv1.Command{CommandId: "cancelled", Action: &agentv1.Command_Service{
			Service: &agentv1.ServiceCommand{Action: agentv1.ServiceAction_SERVICE_ACTION_RESTART},
		}})
	}()
	<-target.entered
	cancel(ErrCommandCancelled)
	result := <-done
	if result.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_CANCELLED || result.GetErrorCode() != agentv1.ErrorCode_ERROR_CODE_CANCELLED {
		t.Fatalf("result=%v", result)
	}
}

func TestDeadlineExpiryOverridesOperationError(t *testing.T) {
	j, err := journal.Open(filepath.Join(t.TempDir(), "commands.db"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	target := &cancellingTarget{entered: make(chan struct{})}
	e := New(j, target, target)
	ctx, cancel := context.WithDeadlineCause(context.Background(), time.Now().Add(10*time.Millisecond), ErrCommandExpired)
	defer cancel()
	result := e.Execute(ctx, &agentv1.Command{CommandId: "deadline", Action: &agentv1.Command_Service{
		Service: &agentv1.ServiceCommand{Action: agentv1.ServiceAction_SERVICE_ACTION_RESTART},
	}})
	if result.GetStatus() != agentv1.CommandStatus_COMMAND_STATUS_FAILED || result.GetErrorCode() != agentv1.ErrorCode_ERROR_CODE_COMMAND_EXPIRED {
		t.Fatalf("result=%v", result)
	}
}

func TestJournalFailureOverridesSuccess(t *testing.T) {
	j, err := journal.Open(filepath.Join(t.TempDir(), "commands.db"), 1000)
	if err != nil {
		t.Fatal(err)
	}
	target := &fakeTarget{}
	e := New(j, target, target)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	result := e.Execute(context.Background(), &agentv1.Command{CommandId: "inspect", Action: &agentv1.Command_Inspect{Inspect: &agentv1.InspectCommand{}}})
	if result.GetErrorCode() != agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED {
		t.Fatalf("result=%v", result)
	}
}
