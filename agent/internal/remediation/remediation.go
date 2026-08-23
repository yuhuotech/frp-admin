package remediation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/frp-admin/frp-admin/agent/internal/configmgr"
	"github.com/frp-admin/frp-admin/agent/internal/inventory"
	"github.com/frp-admin/frp-admin/agent/internal/preflight"
	"github.com/frp-admin/frp-admin/agent/internal/roothelper"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/sys/unix"
)

type Error struct {
	Code   agentv1.ErrorCode
	Err    error
	Result *agentv1.RepairDeploymentRiskResult
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

type Runner interface {
	Output(context.Context, string, ...string) ([]byte, error)
}

type commandRunner struct{}

func (commandRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

type Options struct {
	Role, BinaryPath, ConfigPath, ServiceName, StateDir string
	Configs                                             *configmgr.Manager
	Verifier                                            configmgr.Verifier
	Inventory                                           inventory.Collector
	Runner                                              Runner
	Helper                                              privilegedHelper
}

type privilegedHelper interface {
	Execute(context.Context, roothelper.Request) (roothelper.Response, error)
	InspectSHA(context.Context) (string, error)
}

type Remediator struct {
	role, binaryPath, configPath, serviceName, stateDir string
	configs                                             *configmgr.Manager
	verifier                                            configmgr.Verifier
	inventory                                           inventory.Collector
	runner                                              Runner
	platform                                            string
	helper                                              privilegedHelper
}

type permissionTransaction struct {
	Device       uint64 `json:"device"`
	Inode        uint64 `json:"inode"`
	OriginalMode uint32 `json:"originalMode"`
}

func New(o Options) (*Remediator, error) {
	if o.Role != "client" && o.Role != "server" {
		return nil, errors.New("remediator role must be client or server")
	}
	if !filepath.IsAbs(o.BinaryPath) || !filepath.IsAbs(o.ConfigPath) || !filepath.IsAbs(o.StateDir) {
		return nil, errors.New("remediator paths must be absolute")
	}
	if o.ServiceName == "" || o.Configs == nil || o.Verifier == nil || o.Inventory == nil {
		return nil, errors.New("remediator dependencies are required")
	}
	if o.Runner == nil {
		o.Runner = commandRunner{}
	}
	return &Remediator{role: o.Role, binaryPath: o.BinaryPath, configPath: o.ConfigPath,
		serviceName: o.ServiceName, stateDir: o.StateDir, configs: o.Configs,
		verifier: o.Verifier, inventory: o.Inventory, runner: o.Runner, platform: runtime.GOOS, helper: o.Helper}, nil
}

func (r *Remediator) Repair(ctx context.Context, command *agentv1.RepairDeploymentRiskCommand) (*agentv1.RepairDeploymentRiskResult, error) {
	empty := &agentv1.RepairDeploymentRiskResult{}
	if err := r.validate(command); err != nil {
		return empty, attachResult(err, empty)
	}
	if err := r.precheckFinding(ctx, command); err != nil {
		return empty, attachResult(err, empty)
	}
	var result *agentv1.RepairDeploymentRiskResult
	var err error
	switch command.GetAction() {
	case agentv1.DeploymentRiskRepairAction_DEPLOYMENT_RISK_REPAIR_ACTION_RESTRICT_CONFIG_PERMISSIONS:
		result, err = r.restrictPermissions(ctx, command)
	case agentv1.DeploymentRiskRepairAction_DEPLOYMENT_RISK_REPAIR_ACTION_BIND_ADMIN_API_LOOPBACK:
		result, err = r.bindAdminLoopback(ctx, command)
	default:
		return empty, attachResult(repairError(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "repair action is not allowlisted"), empty)
	}
	if err != nil {
		if result == nil {
			result = empty
		}
		return result, attachResult(err, result)
	}
	updated, err := r.inventory.Collect(ctx)
	if err == nil {
		result.Inventory = updated
	}
	return result, nil
}

func (r *Remediator) CanRepairPermissions(ctx context.Context) bool {
	if r.platform != "darwin" {
		return false
	}
	info, err := os.Lstat(r.configPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Uid) != uint64(os.Geteuid()) {
		return false
	}
	fd, err := unix.Open(r.configPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)
	if r.ensureNoExtendedACL(fd) != nil || r.ensureNoDarwinACL(ctx) != nil {
		return false
	}
	return true
}

func (r *Remediator) validate(c *agentv1.RepairDeploymentRiskCommand) error {
	if c == nil || c.GetFindingId() == "" || len(c.GetFindingId()) > 128 || len(c.GetExpectedResourceFingerprint()) != 64 {
		return repairError(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "finding id and expected fingerprint are required")
	}
	if _, err := hex.DecodeString(c.GetExpectedResourceFingerprint()); err != nil {
		return repairError(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "expected fingerprint must be hexadecimal")
	}
	switch c.GetAction() {
	case agentv1.DeploymentRiskRepairAction_DEPLOYMENT_RISK_REPAIR_ACTION_RESTRICT_CONFIG_PERMISSIONS:
		if c.GetKind() != agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_CONFIG_TOKEN_PERMISSIONS {
			return repairError(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "repair action does not match risk kind")
		}
		if c.GetCandidateRevision() != "" || c.GetCandidateSha256() != "" || len(c.GetCandidateContent()) != 0 || c.GetCandidateStrategy() != "" {
			return repairError(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "permission repair must not include configuration candidate fields")
		}
	case agentv1.DeploymentRiskRepairAction_DEPLOYMENT_RISK_REPAIR_ACTION_BIND_ADMIN_API_LOOPBACK:
		if c.GetKind() != agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_ADMIN_API_NON_LOOPBACK {
			return repairError(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "repair action does not match risk kind")
		}
		if r.role != "server" || !c.GetMaintenanceConfirmed() {
			return repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "server role and maintenance confirmation are required")
		}
		if !validRevision(c.GetCandidateRevision()) || len(c.GetCandidateContent()) == 0 || len(c.GetCandidateContent()) > 16<<20 ||
			c.GetCandidateStrategy() != "restart" || len(c.GetCandidateSha256()) != 64 {
			return repairError(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "complete restart candidate fields are required")
		}
		if _, err := hex.DecodeString(c.GetCandidateSha256()); err != nil {
			return repairError(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "candidate checksum must be hexadecimal")
		}
	default:
		return repairError(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "repair action is not allowlisted")
	}
	return nil
}

func (r *Remediator) precheckFinding(ctx context.Context, command *agentv1.RepairDeploymentRiskCommand) error {
	inv, err := r.inventory.Collect(ctx)
	if err != nil {
		return repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "deployment risk precheck is incomplete")
	}
	completed := false
	for _, kind := range inv.GetDeploymentRiskCompletedKinds() {
		if kind == command.GetKind() {
			completed = true
			break
		}
	}
	if !completed {
		return repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "deployment risk rule precheck is incomplete")
	}
	for _, finding := range inv.GetDeploymentRisks() {
		if finding.GetKind() == command.GetKind() && strings.EqualFold(finding.GetResourceFingerprint(), command.GetExpectedResourceFingerprint()) {
			return nil
		}
	}
	return repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "deployment risk changed after approval")
}

func (r *Remediator) restrictPermissions(ctx context.Context, command *agentv1.RepairDeploymentRiskCommand) (*agentv1.RepairDeploymentRiskResult, error) {
	result := &agentv1.RepairDeploymentRiskResult{PrecheckPassed: true}
	if r.platform != "linux" && r.platform != "darwin" {
		return nil, repairError(agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED_COMMAND, "permission repair is unsupported on this platform")
	}
	if r.platform == "linux" && r.helper != nil {
		currentSHA, err := r.helper.InspectSHA(ctx)
		if err != nil {
			return result, repairErrorWithResult(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "current configuration could not be read", result)
		}
		if err := r.precheckFinding(ctx, command); err != nil {
			return result, attachResult(err, result)
		}
		response, err := r.helper.Execute(ctx, roothelper.Request{Operation: roothelper.OperationRestrictPermissions, ExpectedCurrentSHA: currentSHA})
		return privilegedResult(result, response, err)
	}
	before, err := os.Lstat(r.configPath)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, repairError(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, "configured frp config is not a regular non-symlink file")
	}
	fd, err := unix.Open(r.configPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, repairError(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, "configured frp config could not be opened safely")
	}
	file := os.NewFile(uintptr(fd), r.configPath)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, repairError(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, "configured frp config changed during precheck")
	}
	if err := r.precheckFinding(ctx, command); err != nil {
		return nil, err
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, repairError(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, "configured frp config ownership is unavailable")
	}
	if err := r.ensureNoExtendedACL(fd); err != nil {
		return nil, err
	}
	if r.platform == "linux" {
		if err := r.ensureServiceCanRead(ctx, uint64(stat.Uid)); err != nil {
			return nil, err
		}
	} else {
		if uint64(stat.Uid) != uint64(os.Geteuid()) {
			return nil, repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "macOS config must be owned by the agent user")
		}
		if err := r.ensureNoDarwinACL(ctx); err != nil {
			return nil, err
		}
	}
	original := opened.Mode().Perm()
	if original == 0600 {
		return result, nil
	}
	tx := permissionTransaction{Device: uint64(stat.Dev), Inode: uint64(stat.Ino), OriginalMode: uint32(original)}
	backupID := permissionBackupID(tx)
	if err := r.savePermissionTransaction(tx); err != nil {
		return result, repairErrorWithResult(agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED, "permission recovery transaction could not be saved", result)
	}
	result.BackupCreated, result.BackupId = true, backupID
	if err := file.Chmod(0600); err != nil {
		_ = r.removePermissionTransaction()
		return result, repairErrorWithResult(agentv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "config permissions could not be restricted", result)
	}
	result.Changed = true
	if err := file.Sync(); err != nil {
		return result, r.restoreMode(file, original, agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED, result)
	}
	if err := r.ensurePathStillFile(file); err != nil {
		return result, r.restoreMode(file, original, agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, result)
	}
	if err := r.verifier.Verify(ctx, r.binaryPath, r.configPath); err != nil {
		return result, r.restoreMode(file, original, agentv1.ErrorCode_ERROR_CODE_VERIFY_FAILED, result)
	}
	if err := r.ensurePathStillFile(file); err != nil {
		return result, r.restoreMode(file, original, agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, result)
	}
	if err := r.removePermissionTransaction(); err != nil {
		return result, r.restoreMode(file, original, agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED, result)
	}
	return result, nil
}

func (r *Remediator) ensureNoDarwinACL(ctx context.Context) error {
	out, err := r.runner.Output(ctx, "/bin/ls", "-lde", r.configPath)
	if err != nil {
		return repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "macOS ACL state could not be verified")
	}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines[1:] {
		trimmed := strings.TrimSpace(line)
		if len(trimmed) >= 2 && trimmed[0] >= '0' && trimmed[0] <= '9' && strings.Contains(trimmed, ":") {
			return repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "extended ACL requires manual review")
		}
	}
	return nil
}

func (r *Remediator) ensurePathStillFile(opened *os.File) error {
	pathInfo, err := os.Lstat(r.configPath)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("configured frp config path changed")
	}
	openedInfo, err := opened.Stat()
	if err != nil || !os.SameFile(pathInfo, openedInfo) {
		return errors.New("configured frp config inode changed")
	}
	return nil
}

func (r *Remediator) ensureNoExtendedACL(fd int) error {
	size, err := unix.Flistxattr(fd, nil)
	if err != nil {
		return repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "extended ACL state could not be verified")
	}
	if size == 0 {
		return nil
	}
	buffer := make([]byte, size)
	n, err := unix.Flistxattr(fd, buffer)
	if err != nil {
		return repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "extended ACL state could not be verified")
	}
	for _, name := range strings.Split(string(buffer[:n]), "\x00") {
		if strings.Contains(strings.ToLower(name), "posix_acl") || strings.Contains(strings.ToLower(name), "extendedsecurity") {
			return repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "extended ACL requires manual review")
		}
	}
	return nil
}

func (r *Remediator) ensureServiceCanRead(ctx context.Context, ownerUID uint64) error {
	out, err := r.runner.Output(ctx, "systemctl", "show", r.serviceName, "--property=User,DynamicUser", "--no-pager")
	if err != nil {
		return repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "systemd effective user could not be determined")
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			values[key] = strings.TrimSpace(value)
		}
	}
	if strings.EqualFold(values["DynamicUser"], "yes") {
		return repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "dynamic systemd user requires manual review")
	}
	name := values["User"]
	if name == "" || name == "root" || name == "0" {
		return nil
	}
	var uid uint64
	if parsed, parseErr := strconv.ParseUint(name, 10, 32); parseErr == nil {
		uid = parsed
	} else {
		account, lookupErr := user.Lookup(name)
		if lookupErr != nil {
			return repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "systemd effective user could not be resolved")
		}
		uid, err = strconv.ParseUint(account.Uid, 10, 32)
		if err != nil {
			return repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "systemd effective user could not be resolved")
		}
	}
	if uid != ownerUID {
		return repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "mode 0600 would make the config unreadable by the service")
	}
	return nil
}

func (r *Remediator) bindAdminLoopback(ctx context.Context, command *agentv1.RepairDeploymentRiskCommand) (*agentv1.RepairDeploymentRiskResult, error) {
	if r.platform != "linux" {
		return nil, repairError(agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED_COMMAND, "admin API automatic repair requires Linux")
	}
	if !strings.EqualFold(filepath.Ext(r.configPath), ".toml") {
		return nil, repairError(agentv1.ErrorCode_ERROR_CODE_UNSUPPORTED_COMMAND, "admin API automatic repair currently requires TOML")
	}
	if r.helper != nil {
		if err := r.precheckFinding(ctx, command); err != nil {
			return nil, err
		}
		oldSHA, err := r.helper.InspectSHA(ctx)
		if err != nil {
			return nil, repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "current configuration could not be inspected")
		}
		response, helperErr := r.helper.Execute(ctx, roothelper.Request{Operation: roothelper.OperationApplyAdminLoopback,
			ExpectedCurrentSHA: oldSHA, CandidateRevision: command.GetCandidateRevision(), CandidateSHA: command.GetCandidateSha256(),
			CandidateContent: command.GetCandidateContent(), CandidateStrategy: command.GetCandidateStrategy()})
		result := &agentv1.RepairDeploymentRiskResult{PrecheckPassed: true}
		result, helperErr = privilegedResult(result, response, helperErr)
		if helperErr != nil {
			return result, helperErr
		}
		result.AppliedRevision, result.AppliedSha256 = command.GetCandidateRevision(), strings.ToLower(command.GetCandidateSha256())
		return result, nil
	}
	current, err := os.ReadFile(r.configPath)
	if err != nil {
		return nil, repairError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "current configuration could not be read")
	}
	if err := r.precheckFinding(ctx, command); err != nil {
		return nil, err
	}
	if err := validateLoopbackCandidate(r.configPath, current, command.GetCandidateContent()); err != nil {
		return nil, repairError(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "candidate is not an exact admin API loopback repair")
	}
	oldSHA := digest(current)
	if err := r.configs.ApplyCAS(ctx, command.GetCandidateRevision(), command.GetCandidateSha256(), command.GetCandidateContent(),
		command.GetCandidateStrategy(), oldSHA); err != nil {
		result := &agentv1.RepairDeploymentRiskResult{PrecheckPassed: true}
		var configErr *configmgr.Error
		if errors.As(err, &configErr) {
			result.BackupCreated = configErr.BackupCreated
			if result.BackupCreated {
				result.BackupId = "config-" + oldSHA[:12]
			}
			result.Changed = configErr.Changed
			result.RollbackAttempted = configErr.RollbackAttempted
			result.RollbackSucceeded = configErr.RollbackSucceeded
			return result, repairErrorWithResult(configErr.Code, "admin API repair transaction failed", result)
		}
		return result, repairErrorWithResult(agentv1.ErrorCode_ERROR_CODE_INTERNAL, "admin API repair transaction failed", result)
	}
	// The generated revision records that central desired configuration may now
	// differ; a later central apply remains authoritative and will be rescanned.
	return &agentv1.RepairDeploymentRiskResult{PrecheckPassed: true, BackupCreated: true,
		BackupId: "config-" + oldSHA[:12], Changed: true, AppliedRevision: command.GetCandidateRevision(),
		AppliedSha256: strings.ToLower(command.GetCandidateSha256())}, nil
}

func privilegedResult(result *agentv1.RepairDeploymentRiskResult, response roothelper.Response, err error) (*agentv1.RepairDeploymentRiskResult, error) {
	if err != nil {
		return result, repairErrorWithResult(agentv1.ErrorCode_ERROR_CODE_INTERNAL, "privileged helper is unavailable", result)
	}
	result.BackupCreated = response.BackupCreated
	result.BackupId = response.BackupID
	result.Changed = response.Changed
	result.RollbackAttempted = response.RollbackAttempted
	result.RollbackSucceeded = response.RollbackSucceeded
	if response.ErrorCode != agentv1.ErrorCode_ERROR_CODE_UNSPECIFIED {
		return result, repairErrorWithResult(response.ErrorCode, "privileged helper operation failed", result)
	}
	return result, nil
}

func validRevision(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func validateLoopbackCandidate(path string, current, candidate []byte) error {
	oldValue, err := structuredConfig(path, current)
	if err != nil {
		return err
	}
	newValue, err := structuredConfig(path, candidate)
	if err != nil {
		return err
	}
	oldWeb, oldOK := oldValue["webServer"].(map[string]any)
	newWeb, newOK := newValue["webServer"].(map[string]any)
	if !oldOK || !newOK || strings.TrimSpace(fmt.Sprint(newWeb["addr"])) != "127.0.0.1" {
		return errors.New("candidate admin address is not loopback")
	}
	oldWeb["addr"] = "127.0.0.1"
	if !reflect.DeepEqual(oldValue, newValue) {
		return errors.New("candidate changes fields outside the admin address")
	}
	return nil
}

func structuredConfig(path string, content []byte) (map[string]any, error) {
	// Automatic repair is TOML-only in the first production release. JSON and
	// YAML duplicate-key behavior is parser-dependent and cannot prove an exact
	// one-field semantic change fail-closed.
	var value map[string]any
	switch strings.ToLower(filepath.Ext(path)) {
	case ".toml":
		if err := toml.Unmarshal(content, &value); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("only TOML supports automatic admin API repair")
	}
	return value, nil
}

func (r *Remediator) permissionTransactionPath() string {
	return filepath.Join(r.stateDir, "transactions", "risk-permissions.json")
}

func (r *Remediator) savePermissionTransaction(tx permissionTransaction) error {
	dir := filepath.Dir(r.permissionTransactionPath())
	if err := preflight.SecureStateDir(dir); err != nil {
		return err
	}
	data, err := json.Marshal(tx)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".risk-permissions-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(name, r.permissionTransactionPath()); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func (r *Remediator) removePermissionTransaction() error {
	err := os.Remove(r.permissionTransactionPath())
	if errors.Is(err, os.ErrNotExist) {
		return syncDirectory(filepath.Dir(r.permissionTransactionPath()))
	}
	if err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(r.permissionTransactionPath()))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (r *Remediator) restoreMode(file *os.File, mode os.FileMode, code agentv1.ErrorCode, result *agentv1.RepairDeploymentRiskResult) error {
	result.RollbackAttempted = true
	if err := file.Chmod(mode); err != nil {
		return repairErrorWithResult(agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED, "permission repair and automatic restore failed", result)
	}
	if err := file.Sync(); err != nil {
		return repairErrorWithResult(agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED, "permission repair restore could not be made durable", result)
	}
	if err := r.removePermissionTransaction(); err != nil {
		return repairErrorWithResult(agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED, "permission repair recovery could not be finalized", result)
	}
	result.RollbackSucceeded = true
	return repairErrorWithResult(code, "permission repair verification failed and original mode was restored", result)
}

// Recover restores the original mode from an interrupted permission repair.
func (r *Remediator) Recover() error {
	data, err := os.ReadFile(r.permissionTransactionPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var tx permissionTransaction
	if err := json.Unmarshal(data, &tx); err != nil {
		return err
	}
	fd, err := unix.Open(r.configPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), r.configPath)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("permission repair recovery target is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != tx.Device || uint64(stat.Ino) != tx.Inode {
		return errors.New("permission repair recovery target changed")
	}
	if err := file.Chmod(os.FileMode(tx.OriginalMode)); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return r.removePermissionTransaction()
}

func permissionBackupID(tx permissionTransaction) string {
	return "mode-" + digest([]byte(fmt.Sprintf("%d:%d:%04o", tx.Device, tx.Inode, tx.OriginalMode)))[:12]
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func repairError(code agentv1.ErrorCode, message string) error {
	return &Error{Code: code, Err: errors.New(message)}
}

func repairErrorWithResult(code agentv1.ErrorCode, message string, result *agentv1.RepairDeploymentRiskResult) error {
	return &Error{Code: code, Err: errors.New(message), Result: result}
}

func attachResult(err error, result *agentv1.RepairDeploymentRiskResult) error {
	var target *Error
	if errors.As(err, &target) && target.Result == nil {
		target.Result = result
	}
	return err
}
