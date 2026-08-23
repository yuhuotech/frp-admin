package configmgr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/frp-admin/frp-admin/agent/internal/preflight"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
	"golang.org/x/sys/unix"
)

type Verifier interface {
	Verify(context.Context, string, string) error
}

type Lifecycle interface {
	ApplyConfigStrategy(context.Context, string) error
	Healthy(context.Context) error
	Controllable(context.Context) error
}

type Error struct {
	Code              agentv1.ErrorCode
	Err               error
	RollbackAttempted bool
	RollbackSucceeded bool
	BackupCreated     bool
	Changed           bool
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

type Options struct {
	Role           string
	BinaryPath     string
	ConfigPath     string
	StateDir       string
	Verifier       Verifier
	Lifecycle      Lifecycle
	HealthTimeout  time.Duration
	HealthPoll     time.Duration
	MaxBackups     int
	ConfigOwnerUID *uint32
}

type Manager struct {
	role                             string
	binaryPath, configPath, stateDir string
	verifier                         Verifier
	lifecycle                        Lifecycle
	healthTimeout, healthPoll        time.Duration
	maxBackups                       int
	finalizeTransaction              func(string) error
	useAtomicExchange                bool
	exchange                         func(string, string) (bool, error)
	beforeExchange                   func()
	configOwnerUID                   *uint32
}

type metadata struct {
	CurrentRevision string        `json:"currentRevision"`
	CurrentSHA256   string        `json:"currentSHA256"`
	History         []backupEntry `json:"history"`
}

type backupEntry struct {
	Revision        string `json:"revision"`
	SHA256          string `json:"sha256"`
	Path            string `json:"path"`
	CreatedAtUnixMs int64  `json:"createdAtUnixMs"`
}

type transactionState struct {
	Backup         backupEntry `json:"backup"`
	Strategy       string      `json:"strategy"`
	Mode           uint32      `json:"mode"`
	Previous       metadata    `json:"previous"`
	OriginalDevice uint64      `json:"originalDevice,omitempty"`
	OriginalInode  uint64      `json:"originalInode,omitempty"`
	OriginalSHA    string      `json:"originalSHA,omitempty"`
	CandidateSHA   string      `json:"candidateSHA,omitempty"`
	OwnerUID       uint32      `json:"ownerUID,omitempty"`
	OwnerGID       uint32      `json:"ownerGID,omitempty"`
}

type fileIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
	gid    uint32
}

func New(o Options) (*Manager, error) {
	if o.BinaryPath == "" || o.ConfigPath == "" || o.StateDir == "" || o.Verifier == nil || o.Lifecycle == nil {
		return nil, errors.New("config manager paths, verifier and lifecycle are required")
	}
	if o.Role != "client" && o.Role != "server" {
		return nil, errors.New("role must be client or server")
	}
	if !filepath.IsAbs(o.BinaryPath) || !filepath.IsAbs(o.ConfigPath) {
		return nil, errors.New("binary and config paths must be absolute")
	}
	if o.HealthTimeout <= 0 {
		o.HealthTimeout = 10 * time.Second
	}
	if o.HealthPoll <= 0 {
		o.HealthPoll = 250 * time.Millisecond
	}
	if o.MaxBackups <= 0 {
		o.MaxBackups = 10
	}
	m := &Manager{role: o.Role, binaryPath: o.BinaryPath, configPath: o.ConfigPath, stateDir: o.StateDir,
		verifier: o.Verifier, lifecycle: o.Lifecycle, healthTimeout: o.HealthTimeout,
		healthPoll: o.HealthPoll, maxBackups: o.MaxBackups, configOwnerUID: o.ConfigOwnerUID}
	m.finalizeTransaction = removeSynced
	m.useAtomicExchange = platformAtomicExchange()
	m.exchange = exchangeFiles
	return m, nil
}

func (m *Manager) Apply(ctx context.Context, revision, expectedSHA string, content []byte, strategy string) error {
	return m.ApplyCAS(ctx, revision, expectedSHA, content, strategy, "")
}

// ApplyCAS applies a candidate only when the current on-disk content still
// matches expectedCurrentSHA. It protects locally generated repairs from
// overwriting a concurrent configuration-management update.
func (m *Manager) ApplyCAS(ctx context.Context, revision, expectedSHA string, content []byte, strategy, expectedCurrentSHA string) error {
	if revision == "" {
		return commandError(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "revision is required")
	}
	if strategy != "reload" && strategy != "restart" {
		return commandError(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "strategy must be reload or restart")
	}
	if strategy == "reload" && m.role != "client" {
		return commandError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "reload is only supported for frpc nodes")
	}
	actualSHA := sum(content)
	if !strings.EqualFold(actualSHA, expectedSHA) {
		return commandError(agentv1.ErrorCode_ERROR_CODE_CHECKSUM_MISMATCH, "candidate checksum does not match command")
	}
	if err := preflight.SecureStateDir(m.stateDir); err != nil {
		return commandError(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, err.Error())
	}
	if err := m.validateManagedFileOwner(); err != nil {
		return commandError(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, err.Error())
	}
	if err := preflight.DiskSpace(filepath.Dir(m.configPath), int64(len(content))*3+(1<<20)); err != nil {
		return commandError(agentv1.ErrorCode_ERROR_CODE_DISK_SPACE_INSUFFICIENT, err.Error())
	}
	if err := m.lifecycle.Controllable(ctx); err != nil {
		return commandError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "service controllability check failed")
	}
	current, mode, identity, err := readManagedSnapshot(m.configPath)
	if err != nil {
		return commandError(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, "current configuration could not be opened safely")
	}
	if expectedCurrentSHA != "" && !strings.EqualFold(sum(current), expectedCurrentSHA) {
		return commandError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "current configuration changed after repair precheck")
	}
	candidate, err := m.stage(content, mode, identity.uid, identity.gid)
	if err != nil {
		return commandError(agentv1.ErrorCode_ERROR_CODE_INTERNAL, fmt.Sprintf("stage config: %v", err))
	}
	removeCandidate := true
	defer func() {
		if removeCandidate {
			_ = os.Remove(candidate)
		}
	}()
	if err := preflight.SameFilesystem(candidate, m.configPath); err != nil {
		return commandError(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, err.Error())
	}
	if err := m.verifier.Verify(ctx, m.binaryPath, candidate); err != nil {
		return commandError(agentv1.ErrorCode_ERROR_CODE_VERIFY_FAILED, "candidate configuration verification failed")
	}
	meta, err := m.loadMetadata()
	if err != nil {
		return commandError(agentv1.ErrorCode_ERROR_CODE_INTERNAL, fmt.Sprintf("load config metadata: %v", err))
	}
	previousMeta := meta
	backup, err := m.backupCurrent(current, mode, meta)
	if err != nil {
		return commandError(agentv1.ErrorCode_ERROR_CODE_INTERNAL, fmt.Sprintf("backup current config: %v", err))
	}
	if err := verifyManagedSnapshot(m.configPath, identity, sum(current)); err != nil {
		backupRemains := removeSynced(backup.Path) != nil
		var target *Error
		if errors.As(err, &target) && backupRemains {
			target.BackupCreated = true
		}
		return err
	}
	tx := transactionState{Backup: backup, Strategy: strategy, Mode: uint32(mode), Previous: meta,
		OriginalDevice: identity.device, OriginalInode: identity.inode, OriginalSHA: sum(current), CandidateSHA: actualSHA,
		OwnerUID: identity.uid, OwnerGID: identity.gid}
	if err := m.saveTransaction(tx); err != nil {
		_, markerErr := os.Stat(m.transactionPath())
		backupRemains := !errors.Is(markerErr, os.ErrNotExist)
		if !backupRemains {
			backupRemains = removeSynced(backup.Path) != nil
		}
		return &Error{Code: agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED,
			Err: errors.New("save config transaction failed"), BackupCreated: backupRemains}
	}
	if err := verifyManagedSnapshot(m.configPath, identity, sum(current)); err != nil {
		return m.abortPreparedTransaction(backup, err)
	}
	if m.beforeExchange != nil {
		m.beforeExchange()
	}
	if m.useAtomicExchange {
		swapped, exchangeErr := m.exchange(candidate, m.configPath)
		if exchangeErr != nil {
			if !swapped {
				return m.abortPreparedTransaction(backup, commandError(agentv1.ErrorCode_ERROR_CODE_INTERNAL, "atomic config exchange failed"))
			}
			removeCandidate = false
			return &Error{Code: agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED, Err: errors.New("atomic config exchange durability failed"),
				BackupCreated: true, Changed: true, RollbackAttempted: true}
		}
		if verifyErr := verifyManagedSnapshot(candidate, identity, sum(current)); verifyErr != nil {
			rolledBack, rollbackErr := m.exchange(candidate, m.configPath)
			if rollbackErr != nil || !rolledBack {
				removeCandidate = false
				return &Error{Code: agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED,
					Err: errors.New("config exchange race detected and atomic restore failed"), BackupCreated: true,
					Changed: true, RollbackAttempted: true}
			}
			return m.abortPreparedTransaction(backup, verifyErr)
		}
	} else if err := replace(candidate, m.configPath); err != nil {
		// Rename can succeed while the following directory fsync fails. Treat an
		// unreadable or non-original target as changed so callers never understate
		// a mutation that requires recovery confirmation.
		changed := true
		if onDisk, readErr := os.ReadFile(m.configPath); readErr == nil && bytes.Equal(onDisk, current) {
			changed = false
		}
		return m.restoreAfterFailure(ctx, strategy, backup, mode, previousMeta, changed,
			commandError(agentv1.ErrorCode_ERROR_CODE_INTERNAL, fmt.Sprintf("replace config: %v", err)))
	}

	if err := m.lifecycle.ApplyConfigStrategy(ctx, strategy); err != nil {
		return m.restoreAfterFailure(ctx, strategy, backup, mode, previousMeta, true,
			commandError(agentv1.ErrorCode_ERROR_CODE_SERVICE_OPERATION_FAILED, "apply configuration service strategy failed"))
	}
	if err := m.waitHealthy(ctx); err != nil {
		return m.restoreAfterFailure(ctx, strategy, backup, mode, previousMeta, true,
			commandError(agentv1.ErrorCode_ERROR_CODE_HEALTHCHECK_FAILED, "configuration health check failed"))
	}
	meta.CurrentRevision, meta.CurrentSHA256 = revision, actualSHA
	meta.History = append([]backupEntry{backup}, meta.History...)
	var stale []backupEntry
	if len(meta.History) > m.maxBackups {
		stale = append(stale, meta.History[m.maxBackups:]...)
		meta.History = meta.History[:m.maxBackups]
	}
	if err := m.saveMetadata(meta); err != nil {
		return m.restoreAfterFailure(ctx, strategy, backup, mode, previousMeta, true,
			commandError(agentv1.ErrorCode_ERROR_CODE_INTERNAL, fmt.Sprintf("save config metadata: %v", err)))
	}
	if err := m.finalizeTransaction(m.transactionPath()); err != nil {
		return m.restoreAfterFailure(ctx, strategy, backup, mode, previousMeta, true,
			&Error{Code: agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED, Err: errors.New("finalize config transaction failed")})
	}
	for _, entry := range stale {
		_ = os.Remove(entry.Path)
	}
	return nil
}

func (m *Manager) validateManagedFileOwner() error {
	if m.configOwnerUID == nil {
		_, err := preflight.ManagedFile(m.configPath)
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("alternate config owner is only valid for the root helper")
	}
	info, err := os.Lstat(m.configPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return errors.New("managed config is not a safe regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != *m.configOwnerUID {
		return errors.New("managed config owner is not allowlisted")
	}
	parent, err := os.Lstat(filepath.Dir(m.configPath))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || parent.Mode().Perm()&0002 != 0 {
		return errors.New("managed config parent is unsafe")
	}
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
	if tx.OriginalSHA != "" {
		content, _, _, snapshotErr := readManagedSnapshot(m.configPath)
		if snapshotErr != nil {
			return errors.New("config recovery target could not be opened safely")
		}
		currentSHA := sum(content)
		// A completed restore uses a new inode but retains the exact original content.
		if strings.EqualFold(currentSHA, tx.OriginalSHA) {
			if err := m.finalizeTransaction(m.transactionPath()); err != nil {
				return err
			}
			_ = os.Remove(tx.Backup.Path)
			return nil
		}
		if !strings.EqualFold(currentSHA, tx.CandidateSHA) {
			return errors.New("config recovery target contains an unknown external change")
		}
	}
	content, err := os.ReadFile(tx.Backup.Path)
	if err != nil {
		return err
	}
	staged, err := m.stage(content, os.FileMode(tx.Mode), tx.OwnerUID, tx.OwnerGID)
	if err != nil {
		return err
	}
	if err := replace(staged, m.configPath); err != nil {
		return err
	}
	recovery, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := m.lifecycle.ApplyConfigStrategy(recovery, tx.Strategy); err != nil {
		return err
	}
	if err := m.waitHealthy(recovery); err != nil {
		return err
	}
	if err := m.saveMetadata(tx.Previous); err != nil {
		return err
	}
	if err := m.finalizeTransaction(m.transactionPath()); err != nil {
		return err
	}
	_ = os.Remove(tx.Backup.Path)
	return nil
}

func (m *Manager) abortPreparedTransaction(backup backupEntry, original error) error {
	if err := m.finalizeTransaction(m.transactionPath()); err != nil {
		return &Error{Code: agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED,
			Err: errors.New("prepared config transaction could not be finalized"), BackupCreated: true}
	}
	backupRemains := removeSynced(backup.Path) != nil
	var target *Error
	if errors.As(original, &target) {
		target.BackupCreated = backupRemains
		return target
	}
	return &Error{Code: codeOf(original), Err: original, BackupCreated: backupRemains}
}

func (m *Manager) transactionPath() string {
	return filepath.Join(m.stateDir, "transactions", "config.json")
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
	tmp, err := os.CreateTemp(dir, ".config-tx-*")
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

func (m *Manager) Rollback(ctx context.Context, revision, strategy string) error {
	meta, err := m.loadMetadata()
	if err != nil {
		return commandError(agentv1.ErrorCode_ERROR_CODE_INTERNAL, fmt.Sprintf("load config metadata: %v", err))
	}
	for _, entry := range meta.History {
		if entry.Revision != revision {
			continue
		}
		content, err := os.ReadFile(entry.Path)
		if err != nil {
			return commandError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, fmt.Sprintf("read rollback revision: %v", err))
		}
		return m.Apply(ctx, revision, entry.SHA256, content, strategy)
	}
	return commandError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "rollback revision is not available locally")
}

func (m *Manager) stage(content []byte, mode os.FileMode, ownerUID, ownerGID uint32) (string, error) {
	dir := filepath.Dir(m.configPath)
	// frp uses the filename extension to select TOML/YAML/JSON parsing.
	f, err := os.CreateTemp(dir, ".frp-agent-candidate-*"+filepath.Ext(m.configPath))
	if err != nil {
		return "", err
	}
	path := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(path)
		}
	}()
	if err := f.Chmod(mode); err != nil {
		return "", err
	}
	if os.Geteuid() == 0 {
		if err := f.Chown(int(ownerUID), int(ownerGID)); err != nil {
			return "", err
		}
		if err := f.Chmod(mode); err != nil {
			return "", err
		}
	}
	if _, err := f.Write(content); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ok = true
	return path, nil
}

func (m *Manager) backupCurrent(content []byte, mode os.FileMode, meta metadata) (backupEntry, error) {
	revision := meta.CurrentRevision
	sha := sum(content)
	if revision == "" {
		revision = "unmanaged-" + sha[:12]
	}
	dir := filepath.Join(m.stateDir, "backups", "config")
	if err := preflight.SecureStateDir(dir); err != nil {
		return backupEntry{}, err
	}
	name := fmt.Sprintf("%d-%s%s", time.Now().UnixNano(), safeName(revision), filepath.Ext(m.configPath))
	path := filepath.Join(dir, name)
	if err := writeSynced(path, content, mode); err != nil {
		return backupEntry{}, err
	}
	if err := syncDir(dir); err != nil {
		return backupEntry{}, err
	}
	return backupEntry{Revision: revision, SHA256: sha, Path: path, CreatedAtUnixMs: time.Now().UnixMilli()}, nil
}

func (m *Manager) restoreAfterFailure(_ context.Context, strategy string, backup backupEntry, mode os.FileMode, previous metadata, changed bool, original error) error {
	// Recovery must outlive a cancelled command context.
	recoveryCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	content, err := os.ReadFile(backup.Path)
	if err == nil {
		var staged string
		_, _, currentIdentity, identityErr := readManagedSnapshot(m.configPath)
		if identityErr != nil {
			err = identityErr
		} else {
			staged, err = m.stage(content, mode, currentIdentity.uid, currentIdentity.gid)
		}
		if err == nil {
			err = replace(staged, m.configPath)
		}
		if err == nil {
			err = m.lifecycle.ApplyConfigStrategy(recoveryCtx, strategy)
		}
		if err == nil {
			err = m.waitHealthy(recoveryCtx)
		}
		if err == nil {
			err = m.saveMetadata(previous)
		}
		if err == nil {
			err = m.finalizeTransaction(m.transactionPath())
		}
	}
	if err != nil {
		return &Error{Code: agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED,
			Err: errors.New("configuration operation and automatic restore failed"), RollbackAttempted: true,
			BackupCreated: true, Changed: changed}
	}
	_ = os.Remove(backup.Path)
	var target *Error
	if errors.As(original, &target) {
		target.RollbackAttempted = true
		target.RollbackSucceeded = true
		target.BackupCreated = true
		target.Changed = changed
		return target
	}
	return &Error{Code: codeOf(original), Err: original, RollbackAttempted: true, RollbackSucceeded: true,
		BackupCreated: true, Changed: changed}
}

func (m *Manager) waitHealthy(ctx context.Context) error {
	deadline := time.Now().Add(m.healthTimeout)
	var last error
	for {
		last = m.lifecycle.Healthy(ctx)
		if last == nil {
			return nil
		}
		if time.Now().Add(m.healthPoll).After(deadline) {
			return last
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.healthPoll):
		}
	}
}

func (m *Manager) loadMetadata() (metadata, error) {
	b, err := os.ReadFile(filepath.Join(m.stateDir, "config-state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return metadata{}, nil
	}
	if err != nil {
		return metadata{}, err
	}
	var v metadata
	if err := json.Unmarshal(b, &v); err != nil {
		return metadata{}, err
	}
	return v, nil
}

func (m *Manager) saveMetadata(v metadata) error {
	if err := preflight.SecureStateDir(m.stateDir); err != nil {
		return err
	}
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	path := filepath.Join(m.stateDir, "config-state.json")
	tmp, err := os.CreateTemp(m.stateDir, ".config-state-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
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
	return replace(tmpPath, path)
}

func replace(source, target string) error {
	if err := os.Rename(source, target); err != nil {
		return err
	}
	return syncDir(filepath.Dir(target))
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func removeSynced(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return syncDir(filepath.Dir(path))
	}
	if err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func writeSynced(path string, content []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, err := io.Copy(f, bytes.NewReader(content)); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

func readManagedSnapshot(path string) ([]byte, os.FileMode, fileIdentity, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() {
		return nil, 0, fileIdentity{}, errors.New("managed config is not a regular non-symlink file")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, fileIdentity{}, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(pathInfo, opened) {
		return nil, 0, fileIdentity{}, errors.New("managed config changed while opening")
	}
	stat, ok := opened.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, 0, fileIdentity{}, errors.New("managed config identity is unavailable")
	}
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, 0, fileIdentity{}, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, 0, fileIdentity{}, err
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok || uint64(afterStat.Dev) != uint64(stat.Dev) || uint64(afterStat.Ino) != uint64(stat.Ino) {
		return nil, 0, fileIdentity{}, errors.New("managed config changed while reading")
	}
	return content, opened.Mode().Perm(), fileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino), uid: stat.Uid, gid: stat.Gid}, nil
}

func verifyManagedSnapshot(path string, expected fileIdentity, expectedSHA string) error {
	content, _, actual, err := readManagedSnapshot(path)
	if err != nil || actual != expected {
		return commandError(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, "managed configuration identity changed before commit")
	}
	if !strings.EqualFold(sum(content), expectedSHA) {
		return commandError(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "managed configuration content changed before commit")
	}
	return nil
}

func sum(content []byte) string { value := sha256.Sum256(content); return hex.EncodeToString(value[:]) }
func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, s)
}
func commandError(code agentv1.ErrorCode, message string) error {
	return &Error{Code: code, Err: errors.New(message)}
}
func codeOf(err error) agentv1.ErrorCode {
	var target *Error
	if errors.As(err, &target) {
		return target.Code
	}
	return agentv1.ErrorCode_ERROR_CODE_INTERNAL
}
