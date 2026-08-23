package remediation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/frp-admin/frp-admin/agent/internal/configmgr"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

type fakeInventory struct{ fingerprint string }

func (f fakeInventory) Collect(context.Context) (*agentv1.Inventory, error) {
	return &agentv1.Inventory{DeploymentRiskScanComplete: false,
		DeploymentRiskCompletedKinds: []agentv1.DeploymentRiskKind{agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_CONFIG_TOKEN_PERMISSIONS}, DeploymentRisks: []*agentv1.DeploymentRisk{{
			Kind: agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_CONFIG_TOKEN_PERMISSIONS, ResourceFingerprint: f.fingerprint,
		}}}, nil
}

type adminInventory struct{ fingerprint string }

func (f adminInventory) Collect(context.Context) (*agentv1.Inventory, error) {
	return &agentv1.Inventory{DeploymentRiskCompletedKinds: []agentv1.DeploymentRiskKind{
		agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_ADMIN_API_NON_LOOPBACK}, DeploymentRisks: []*agentv1.DeploymentRisk{{
		Kind: agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_ADMIN_API_NON_LOOPBACK, ResourceFingerprint: f.fingerprint,
	}}}, nil
}

type fakeRunner struct{ output string }

func (f fakeRunner) Output(context.Context, string, ...string) ([]byte, error) {
	return []byte(f.output), nil
}

type modeVerifier struct{ fail bool }

type acceptVerifier struct{}

func (acceptVerifier) Verify(context.Context, string, string) error { return nil }

func (v modeVerifier) Verify(_ context.Context, _, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm() != 0600 {
		return errors.New("mode was not restricted before verification")
	}
	if v.fail {
		return errors.New("secret verifier output")
	}
	return nil
}

type lifecycle struct{}

func (lifecycle) ApplyConfigStrategy(context.Context, string) error { return nil }
func (lifecycle) Healthy(context.Context) error                     { return nil }
func (lifecycle) Controllable(context.Context) error                { return nil }

func testRemediator(t *testing.T, verifier configmgr.Verifier) (*Remediator, string, string) {
	t.Helper()
	dir := t.TempDir()
	configPath := filepath.Join(dir, "frps.toml")
	if err := os.WriteFile(configPath, []byte("bindPort = 7000\n[auth]\ntoken = \"secret\"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(dir, "state")
	configs, err := configmgr.New(configmgr.Options{Role: "server", BinaryPath: "/bin/frps", ConfigPath: configPath,
		StateDir: stateDir, Verifier: verifier, Lifecycle: lifecycle{}})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Repeat("a", 64)
	r, err := New(Options{Role: "server", BinaryPath: "/bin/frps", ConfigPath: configPath, ServiceName: "frps.service",
		StateDir: stateDir, Configs: configs, Verifier: verifier, Inventory: fakeInventory{fingerprint: fingerprint},
		Runner: fakeRunner{output: "User=" + strconv.Itoa(os.Geteuid()) + "\nDynamicUser=no\n"}})
	if err != nil {
		t.Fatal(err)
	}
	r.platform = "linux"
	return r, configPath, fingerprint
}

func permissionCommand(fingerprint string) *agentv1.RepairDeploymentRiskCommand {
	return &agentv1.RepairDeploymentRiskCommand{FindingId: "finding-1", ExpectedResourceFingerprint: fingerprint,
		Kind:   agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_CONFIG_TOKEN_PERMISSIONS,
		Action: agentv1.DeploymentRiskRepairAction_DEPLOYMENT_RISK_REPAIR_ACTION_RESTRICT_CONFIG_PERMISSIONS}
}

func TestRestrictPermissionsUsesDescriptorAndVerifies(t *testing.T) {
	r, path, fingerprint := testRemediator(t, modeVerifier{})
	result, err := r.Repair(context.Background(), permissionCommand(fingerprint))
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if !result.GetChanged() || !result.GetBackupCreated() || result.GetBackupId() == "" || info.Mode().Perm() != 0600 {
		t.Fatalf("result=%v mode=%04o", result, info.Mode().Perm())
	}
	if _, err := os.Stat(r.permissionTransactionPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("transaction was not removed: %v", err)
	}
}

func TestRestrictPermissionsSupportsOwnerDarwinLaunchAgent(t *testing.T) {
	r, path, fingerprint := testRemediator(t, modeVerifier{})
	r.platform = "darwin"
	r.runner = fakeRunner{output: "-rw-r--r--  1 owner  staff  42 Jul 29 00:00 frpc.toml\n"}
	result, err := r.Repair(context.Background(), permissionCommand(fingerprint))
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if !result.GetChanged() || info.Mode().Perm() != 0600 {
		t.Fatalf("result=%v mode=%04o", result, info.Mode().Perm())
	}
}

func TestRestrictPermissionsRejectsDarwinExtendedACL(t *testing.T) {
	r, path, fingerprint := testRemediator(t, modeVerifier{})
	r.platform = "darwin"
	r.runner = fakeRunner{output: "-rw-r--r--  1 owner  staff  42 Jul 29 00:00 frpc.toml\n 0: user:someone allow read\n"}
	_, err := r.Repair(context.Background(), permissionCommand(fingerprint))
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED {
		t.Fatalf("error=%v", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0644 {
		t.Fatalf("ACL rejection mutated mode=%04o", info.Mode().Perm())
	}
}

func TestRestrictPermissionsRestoresModeWhenVerifyFails(t *testing.T) {
	r, path, fingerprint := testRemediator(t, modeVerifier{fail: true})
	_, err := r.Repair(context.Background(), permissionCommand(fingerprint))
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != agentv1.ErrorCode_ERROR_CODE_VERIFY_FAILED {
		t.Fatalf("error=%v", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0644 {
		t.Fatalf("mode was not restored: %04o", info.Mode().Perm())
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("verifier detail leaked: %v", err)
	}
}

func TestRecoverInterruptedPermissionRepair(t *testing.T) {
	r, path, _ := testRemediator(t, modeVerifier{})
	info, _ := os.Stat(path)
	stat := info.Sys().(*syscall.Stat_t)
	tx := permissionTransaction{Device: uint64(stat.Dev), Inode: uint64(stat.Ino), OriginalMode: 0644}
	if err := r.savePermissionTransaction(tx); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.Recover(); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(path)
	if info.Mode().Perm() != 0644 {
		t.Fatalf("mode=%04o", info.Mode().Perm())
	}
}

func TestValidateLoopbackCandidateAllowsOnlyExactSemanticChange(t *testing.T) {
	tests := []struct {
		name, path, input, candidate string
		wantErr                      bool
	}{
		{"toml", "frps.toml", "bindPort = 7000\n[webServer]\naddr = \"0.0.0.0\"\nport = 7500\n", "bindPort=7000\n[webServer]\naddr=\"127.0.0.1\"\nport=7500\n", false},
		{"yaml", "frps.yaml", "bindPort: 7000\nwebServer:\n  addr: 0.0.0.0\n  port: 7500\n", "webServer: {addr: 127.0.0.1, port: 7500}\nbindPort: 7000\n", true},
		{"json", "frps.json", `{"bindPort":7000,"webServer":{"addr":"0.0.0.0","port":7500}}`, `{"webServer":{"port":7500,"addr":"127.0.0.1"},"bindPort":7000}`, true},
		{"extra-change", "frps.toml", "bindPort=7000\n[webServer]\naddr=\"0.0.0.0\"\n", "bindPort=7001\n[webServer]\naddr=\"127.0.0.1\"\n", true},
		{"ini", "frps.ini", "[common]\ndashboard_addr=0.0.0.0\n", "[common]\ndashboard_addr=127.0.0.1\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLoopbackCandidate(tt.path, []byte(tt.input), []byte(tt.candidate))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestRepairRejectsStaleFingerprintBeforeMutation(t *testing.T) {
	r, path, _ := testRemediator(t, modeVerifier{})
	_, err := r.Repair(context.Background(), permissionCommand(strings.Repeat("b", 64)))
	var typed *Error
	if !errors.As(err, &typed) || typed.Code != agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED {
		t.Fatalf("error=%v", err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0644 {
		t.Fatalf("stale command mutated mode=%04o", info.Mode().Perm())
	}
}

func TestBindAdminLoopbackAppliesControlPlaneCandidate(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "frps.toml")
	current := []byte("bindPort=7000\n[webServer]\naddr=\"0.0.0.0\"\nport=7500\n")
	candidate := []byte("bindPort = 7000\n[webServer]\naddr = \"127.0.0.1\"\nport = 7500\n")
	if err := os.WriteFile(configPath, current, 0600); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(dir, "state")
	manager, err := configmgr.New(configmgr.Options{Role: "server", BinaryPath: "/bin/frps", ConfigPath: configPath,
		StateDir: stateDir, Verifier: acceptVerifier{}, Lifecycle: lifecycle{}})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Repeat("c", 64)
	r, err := New(Options{Role: "server", BinaryPath: "/bin/frps", ConfigPath: configPath, ServiceName: "frps.service",
		StateDir: stateDir, Configs: manager, Verifier: acceptVerifier{}, Inventory: adminInventory{fingerprint: fingerprint}})
	if err != nil {
		t.Fatal(err)
	}
	r.platform = "linux"
	command := &agentv1.RepairDeploymentRiskCommand{FindingId: "finding-admin", ExpectedResourceFingerprint: fingerprint,
		Kind:                 agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_ADMIN_API_NON_LOOPBACK,
		Action:               agentv1.DeploymentRiskRepairAction_DEPLOYMENT_RISK_REPAIR_ACTION_BIND_ADMIN_API_LOOPBACK,
		MaintenanceConfirmed: true, CandidateRevision: "control-plane-r42", CandidateSha256: digest(candidate),
		CandidateContent: candidate, CandidateStrategy: "restart"}
	result, err := r.Repair(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if !result.GetChanged() || result.GetAppliedRevision() != command.GetCandidateRevision() ||
		result.GetAppliedSha256() != command.GetCandidateSha256() {
		t.Fatalf("result=%v", result)
	}
	got, _ := os.ReadFile(configPath)
	if string(got) != string(candidate) {
		t.Fatalf("candidate was not applied: %q", got)
	}
}

func TestPermissionRepairRejectsConfigCandidateFields(t *testing.T) {
	r, path, fingerprint := testRemediator(t, modeVerifier{})
	command := permissionCommand(fingerprint)
	command.CandidateRevision = "must-not-be-used"
	result, err := r.Repair(context.Background(), command)
	var typed *Error
	if result == nil || !errors.As(err, &typed) || typed.Code != agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND {
		t.Fatalf("result=%v error=%v", result, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0644 {
		t.Fatalf("invalid permission repair mutated mode=%04o", info.Mode().Perm())
	}
}

func TestBindAdminLoopbackRejectsNonTOML(t *testing.T) {
	r := &Remediator{configPath: "/local/frps.json"}
	result, err := r.bindAdminLoopback(context.Background(), &agentv1.RepairDeploymentRiskCommand{})
	var typed *Error
	if result != nil || !errors.As(err, &typed) || typed.Code != agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED_COMMAND {
		t.Fatalf("result=%v error=%v", result, err)
	}
}
