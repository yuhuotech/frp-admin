package upgrader

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/frp-admin/frp-admin/agent/internal/preflight"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

type Lifecycle interface {
	Stop(context.Context) error
	Start(context.Context) error
	Healthy(context.Context) error
	Controllable(context.Context) error
}

type Error struct {
	Code agentv1.ErrorCode
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

type Options struct {
	Role, BinaryPath, ConfigPath, StateDir  string
	AllowedHosts                            []string
	MaxArtifactBytes                        int64
	Downloader                              Downloader
	Runner                                  BinaryRunner
	Lifecycle                               Lifecycle
	HealthTimeout, HealthPoll, StableWindow time.Duration
}

type Manager struct{ options Options }
type transactionState struct {
	Backup string `json:"backup"`
	Mode   uint32 `json:"mode"`
}

var versionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?$`)

func New(o Options) (*Manager, error) {
	if o.Role != "client" && o.Role != "server" {
		return nil, errors.New("upgrade role must be client or server")
	}
	if !filepath.IsAbs(o.BinaryPath) || !filepath.IsAbs(o.ConfigPath) || !filepath.IsAbs(o.StateDir) {
		return nil, errors.New("upgrade paths must be absolute")
	}
	if len(o.AllowedHosts) == 0 || o.MaxArtifactBytes <= 0 || o.Downloader == nil || o.Runner == nil || o.Lifecycle == nil {
		return nil, errors.New("upgrade security policy and adapters are required")
	}
	if o.MaxArtifactBytes > 4<<30 {
		return nil, errors.New("upgrade artifact limit must not exceed 4 GiB")
	}
	if o.HealthTimeout <= 0 {
		o.HealthTimeout = 30 * time.Second
	}
	if o.HealthPoll <= 0 {
		o.HealthPoll = 250 * time.Millisecond
	}
	if o.StableWindow <= 0 {
		o.StableWindow = 5 * time.Second
	}
	return &Manager{options: o}, nil
}

func (m *Manager) Upgrade(ctx context.Context, targetVersion, artifactURL, expectedSHA string) error {
	if !versionPattern.MatchString(targetVersion) {
		return upgradeError(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "invalid target version")
	}
	if err := preflight.SecureStateDir(m.options.StateDir); err != nil {
		return upgradeError(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, err.Error())
	}
	if _, err := preflight.ManagedFile(m.options.BinaryPath); err != nil {
		return upgradeError(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, err.Error())
	}
	if _, err := preflight.ManagedFile(m.options.ConfigPath); err != nil {
		return upgradeError(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, err.Error())
	}
	if err := preflight.DiskSpace(m.options.StateDir, m.options.MaxArtifactBytes*2); err != nil {
		return upgradeError(agentv1.ErrorCode_ERROR_CODE_DISK_SPACE_INSUFFICIENT, err.Error())
	}
	if err := preflight.DiskSpace(filepath.Dir(m.options.BinaryPath), m.options.MaxArtifactBytes); err != nil {
		return upgradeError(agentv1.ErrorCode_ERROR_CODE_DISK_SPACE_INSUFFICIENT, err.Error())
	}
	if err := m.options.Lifecycle.Controllable(ctx); err != nil {
		return upgradeError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, fmt.Sprintf("service is not controllable: %v", err))
	}
	stagedDir := filepath.Join(m.options.StateDir, "staged")
	if err := preflight.SecureStateDir(stagedDir); err != nil {
		return internal("create staged directory", err)
	}
	artifact, err := os.CreateTemp(stagedDir, ".frp-artifact-*")
	if err != nil {
		return internal("create artifact file", err)
	}
	artifactPath := artifact.Name()
	artifact.Close()
	os.Remove(artifactPath)
	defer os.Remove(artifactPath)
	actualSHA, err := m.options.Downloader.Download(ctx, artifactURL, artifactPath, m.options.MaxArtifactBytes, m.options.AllowedHosts)
	if err != nil {
		return upgradeError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, fmt.Sprintf("download artifact: %v", err))
	}
	if !strings.EqualFold(actualSHA, expectedSHA) {
		return upgradeError(agentv1.ErrorCode_ERROR_CODE_CHECKSUM_MISMATCH, "artifact checksum does not match command")
	}

	candidate, err := os.CreateTemp(filepath.Dir(m.options.BinaryPath), ".frp-agent-binary-*")
	if err != nil {
		return internal("create binary candidate", err)
	}
	candidatePath := candidate.Name()
	candidate.Close()
	os.Remove(candidatePath)
	defer os.Remove(candidatePath)
	binaryName := "frpc"
	if m.options.Role == "server" {
		binaryName = "frps"
	}
	if err := ExtractBinary(artifactPath, binaryName, candidatePath, m.options.MaxArtifactBytes); err != nil {
		return upgradeError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, fmt.Sprintf("extract artifact: %v", err))
	}
	if err := preflight.SameFilesystem(candidatePath, m.options.BinaryPath); err != nil {
		return upgradeError(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, err.Error())
	}
	version, err := m.options.Runner.Version(ctx, candidatePath)
	if err != nil {
		return upgradeError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "read upgrade candidate version failed")
	}
	if strings.TrimPrefix(strings.TrimSpace(version), "v") != strings.TrimPrefix(targetVersion, "v") {
		return upgradeError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, fmt.Sprintf("artifact version %q does not match %q", version, targetVersion))
	}
	if err := m.options.Runner.Verify(ctx, candidatePath, m.options.ConfigPath); err != nil {
		return upgradeError(agentv1.ErrorCode_ERROR_CODE_VERIFY_FAILED, "upgrade candidate configuration verification failed")
	}
	info, err := os.Stat(m.options.BinaryPath)
	if err != nil {
		return internal("stat current binary", err)
	}
	if err := os.Chmod(candidatePath, info.Mode().Perm()); err != nil {
		return internal("set candidate permissions", err)
	}
	backupPath, err := m.backup(info.Mode().Perm())
	if err != nil {
		return internal("backup current binary", err)
	}
	if err := m.saveTransaction(transactionState{Backup: backupPath, Mode: uint32(info.Mode().Perm())}); err != nil {
		return upgradeError(agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED, fmt.Sprintf("save upgrade transaction: %v", err))
	}
	if err := m.options.Lifecycle.Stop(ctx); err != nil {
		return m.recoverService(upgradeError(agentv1.ErrorCode_ERROR_CODE_SERVICE_OPERATION_FAILED, fmt.Sprintf("stop service: %v", err)))
	}
	if err := replace(candidatePath, m.options.BinaryPath); err != nil {
		return m.restore(upgradeError(agentv1.ErrorCode_ERROR_CODE_INTERNAL, fmt.Sprintf("replace binary: %v", err)), backupPath, info.Mode().Perm())
	}
	if err := m.options.Lifecycle.Start(ctx); err != nil {
		return m.restore(upgradeError(agentv1.ErrorCode_ERROR_CODE_SERVICE_OPERATION_FAILED, fmt.Sprintf("start service: %v", err)), backupPath, info.Mode().Perm())
	}
	if err := m.waitHealthy(ctx); err != nil {
		return m.restore(upgradeError(agentv1.ErrorCode_ERROR_CODE_HEALTHCHECK_FAILED, fmt.Sprintf("health check: %v", err)), backupPath, info.Mode().Perm())
	}
	_ = os.Remove(m.transactionPath())
	return nil
}

func (m *Manager) Recover(ctx context.Context) error {
	b, err := os.ReadFile(m.transactionPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var tx transactionState
	if err := json.Unmarshal(b, &tx); err != nil {
		return err
	}
	recovery, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := m.options.Lifecycle.Stop(recovery); err != nil {
		return err
	}
	candidate, err := os.CreateTemp(filepath.Dir(m.options.BinaryPath), ".frp-agent-recover-*")
	if err != nil {
		return err
	}
	candidate.Close()
	os.Remove(candidate.Name())
	defer os.Remove(candidate.Name())
	if err := copyFile(tx.Backup, candidate.Name(), os.FileMode(tx.Mode)); err != nil {
		return err
	}
	if err := replace(candidate.Name(), m.options.BinaryPath); err != nil {
		return err
	}
	if err := m.options.Lifecycle.Start(recovery); err != nil {
		return err
	}
	if err := m.waitHealthy(recovery); err != nil {
		return err
	}
	return os.Remove(m.transactionPath())
}

func (m *Manager) transactionPath() string {
	return filepath.Join(m.options.StateDir, "transactions", "upgrade.json")
}
func (m *Manager) saveTransaction(value transactionState) error {
	dir := filepath.Dir(m.transactionPath())
	if err := preflight.SecureStateDir(dir); err != nil {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".upgrade-tx-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return replace(name, m.transactionPath())
}

func (m *Manager) backup(mode os.FileMode) (string, error) {
	dir := filepath.Join(m.options.StateDir, "backups", "bin")
	if err := preflight.SecureStateDir(dir); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "previous")
	if err := copyAtomic(m.options.BinaryPath, path, mode); err != nil {
		return "", err
	}
	return path, nil
}

func (m *Manager) restore(original error, backup string, mode os.FileMode) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := m.options.Lifecycle.Stop(ctx)
	var candidate *os.File
	if err == nil {
		candidate, err = os.CreateTemp(filepath.Dir(m.options.BinaryPath), ".frp-agent-restore-*")
	}
	if err == nil {
		candidate.Close()
		os.Remove(candidate.Name())
		defer os.Remove(candidate.Name())
		err = copyFile(backup, candidate.Name(), mode)
	}
	if err == nil {
		err = replace(candidate.Name(), m.options.BinaryPath)
	}
	if err == nil {
		err = m.options.Lifecycle.Start(ctx)
	}
	if err == nil {
		err = m.waitHealthy(ctx)
	}
	if err != nil {
		return upgradeError(codeOf(original), fmt.Sprintf("%v; automatic restore failed: %v", original, err))
	}
	_ = os.Remove(m.transactionPath())
	return original
}

func (m *Manager) recoverService(original error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := m.options.Lifecycle.Start(ctx)
	if err == nil {
		err = m.waitHealthy(ctx)
	}
	if err != nil {
		return upgradeError(codeOf(original), fmt.Sprintf("%v; service recovery failed: %v", original, err))
	}
	_ = os.Remove(m.transactionPath())
	return original
}

func (m *Manager) waitHealthy(ctx context.Context) error {
	deadline := time.Now().Add(m.options.HealthTimeout)
	var stableSince time.Time
	var last error
	for time.Now().Before(deadline) {
		last = m.options.Lifecycle.Healthy(ctx)
		if last == nil {
			if stableSince.IsZero() {
				stableSince = time.Now()
			}
			if time.Since(stableSince) >= m.options.StableWindow {
				return nil
			}
		} else {
			stableSince = time.Time{}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.options.HealthPoll):
		}
	}
	if last == nil {
		last = errors.New("service did not remain healthy for the stable window")
	}
	return last
}

func copyAtomic(source, target string, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(target), ".frp-backup-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	tmp.Close()
	os.Remove(name)
	defer os.Remove(name)
	if err := copyFile(source, name, mode); err != nil {
		return err
	}
	return replace(name, target)
}

func copyFile(source, target string, mode os.FileMode) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		out.Close()
		if !ok {
			os.Remove(target)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func replace(source, target string) error {
	if err := os.Rename(source, target); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func upgradeError(code agentv1.ErrorCode, message string) error {
	return &Error{Code: code, Err: errors.New(message)}
}
func internal(stage string, err error) error {
	return upgradeError(agentv1.ErrorCode_ERROR_CODE_INTERNAL, fmt.Sprintf("%s: %v", stage, err))
}
func codeOf(err error) agentv1.ErrorCode {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return agentv1.ErrorCode_ERROR_CODE_INTERNAL
}
