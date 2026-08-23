//go:build linux

package roothelper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/frp-admin/frp-admin/agent/internal/configmgr"
	"github.com/frp-admin/frp-admin/agent/internal/securitycheck"
	"github.com/frp-admin/frp-admin/agent/internal/service"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/sys/unix"
)

type Config struct {
	Role, BinaryPath, ConfigPath, ServiceName string
	StateDir                                  string
}

func LoadConfig(path string) (Config, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Size() > 64<<10 {
		return Config{}, errors.New("helper config must be a root-only regular file")
	}
	if err := secureManagedParent(filepath.Dir(path)); err != nil {
		return Config{}, errors.New("helper config parent is unsafe")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return Config{}, errors.New("helper config could not be opened safely")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return Config{}, errors.New("helper config could not be inspected")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || !os.SameFile(pathInfo, info) || info.Mode().Perm() != 0600 || stat.Uid != 0 || stat.Gid != 0 {
		return Config{}, errors.New("helper config must be root-owned root-group mode 0600")
	}
	config, err := decodeConfig(file)
	if err != nil {
		return Config{}, err
	}
	if config.Role != "client" && config.Role != "server" || !filepath.IsAbs(config.BinaryPath) || !filepath.IsAbs(config.ConfigPath) ||
		config.StateDir != "/var/lib/frp-agent-helper" || config.ServiceName != "frpc.service" && config.ServiceName != "frps.service" {
		return Config{}, errors.New("helper allowlist is invalid")
	}
	executable, serviceName := "frpc", "frpc.service"
	if config.Role == "server" {
		executable, serviceName = "frps", "frps.service"
	}
	if config.ConfigPath != filepath.Join("/etc/frp", executable+".toml") || config.BinaryPath != filepath.Join("/opt/frp/bin", executable) || config.ServiceName != serviceName {
		return Config{}, errors.New("helper resources are outside the fixed allowlist")
	}
	return config, nil
}

func decodeConfig(reader io.Reader) (Config, error) {
	decoder := json.NewDecoder(io.LimitReader(reader, 64<<10+1))
	decoder.DisallowUnknownFields()
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return Config{}, errors.New("helper config is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, errors.New("helper config is invalid")
	}
	return config, nil
}

type Server struct {
	Config       Config
	Runner       service.Runner
	stableWindow time.Duration
	pollInterval time.Duration
	now          func() time.Time
	wait         func(context.Context, time.Duration) error
}
type permissionMarker struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mode   uint32 `json:"mode"`
}

func (s Server) Handle(ctx context.Context, request Request) Response {
	switch request.Operation {
	case OperationProbe:
		if err := s.probe(ctx); err != nil {
			return failure(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "privileged helper preflight failed")
		}
		return Response{}
	case OperationProbeService:
		if !serviceRequestOnly(request) {
			return failure(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "service request contains unsupported fields")
		}
		return s.probeService(ctx)
	case OperationServiceStart:
		if !serviceRequestOnly(request) {
			return failure(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "service request contains unsupported fields")
		}
		return s.serviceAction(ctx, agentv1.ServiceAction_SERVICE_ACTION_START)
	case OperationServiceStop:
		if !serviceRequestOnly(request) {
			return failure(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "service request contains unsupported fields")
		}
		return s.serviceAction(ctx, agentv1.ServiceAction_SERVICE_ACTION_STOP)
	case OperationServiceRestart:
		if !serviceRequestOnly(request) {
			return failure(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "service request contains unsupported fields")
		}
		return s.serviceAction(ctx, agentv1.ServiceAction_SERVICE_ACTION_RESTART)
	case OperationScan:
		scan := securitycheck.New(s.Config.Role, s.Config.ConfigPath, s.Config.ServiceName).Collect(ctx)
		return Response{Findings: scan.Findings, CompletedKinds: scan.CompletedKinds, ScanErrorCode: scan.ErrorCode}
	case OperationReadConfig:
		file, _, err := openFixed(s.Config.ConfigPath)
		if err != nil {
			return failure(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, "config read failed")
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
		if err != nil || len(data) == 0 || len(data) > 1<<20 {
			return failure(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "config read failed")
		}
		return Response{ConfigContent: data, ResourceSHA: hash(data)}
	case OperationInspect:
		file, _, err := openFixed(s.Config.ConfigPath)
		if err != nil {
			return failure(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, "config inspection failed")
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, 16<<20+1))
		if err != nil || len(data) > 16<<20 {
			return failure(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "config inspection failed")
		}
		return Response{ResourceSHA: hash(data)}
	case OperationRestrictPermissions:
		return s.restrict(ctx, request)
	case OperationApplyAdminLoopback:
		return s.apply(ctx, request)
	default:
		return failure(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "operation is not allowlisted")
	}
}

func serviceRequestOnly(request Request) bool {
	return request.ExpectedCurrentSHA == "" && request.CandidateRevision == "" && request.CandidateSHA == "" &&
		len(request.CandidateContent) == 0 && request.CandidateStrategy == ""
}

func (s Server) systemd() *service.Systemd {
	if s.Runner != nil {
		return service.NewSystemdWithRunner(s.Config.ServiceName, s.Config.BinaryPath, s.Config.ConfigPath, s.Config.Role, s.Runner)
	}
	return service.NewSystemd(s.Config.ServiceName, s.Config.BinaryPath, s.Config.ConfigPath, s.Config.Role)
}

func (s Server) probeService(ctx context.Context) Response {
	status, err := s.systemd().Status(ctx)
	if err != nil || status.GetState() == agentv1.ServiceState_SERVICE_STATE_UNKNOWN {
		return failure(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "privileged service preflight failed")
	}
	return Response{ServiceStatus: status}
}

func (s Server) serviceAction(ctx context.Context, action agentv1.ServiceAction) Response {
	status, err := s.systemd().Act(ctx, action)
	if err != nil {
		response := failure(agentv1.ErrorCode_ERROR_CODE_SERVICE_OPERATION_FAILED, "privileged service operation failed")
		response.ServiceStatus, _ = s.systemd().Status(ctx)
		return response
	}
	want := agentv1.ServiceState_SERVICE_STATE_ACTIVE
	if action == agentv1.ServiceAction_SERVICE_ACTION_STOP {
		want = agentv1.ServiceState_SERVICE_STATE_INACTIVE
	}
	status, err = s.waitForStableState(ctx, want, status)
	if err != nil {
		response := failure(agentv1.ErrorCode_ERROR_CODE_SERVICE_OPERATION_FAILED, "service did not reach the requested state")
		response.ServiceStatus = status
		return response
	}
	return Response{ServiceStatus: status, Changed: true}
}

func (s Server) waitForStableState(ctx context.Context, want agentv1.ServiceState, status *agentv1.ServiceStatus) (*agentv1.ServiceStatus, error) {
	window, poll := s.stableWindow, s.pollInterval
	if window <= 0 {
		window = 2 * time.Second
	}
	if poll <= 0 {
		poll = 100 * time.Millisecond
	}
	now := s.now
	if now == nil {
		now = time.Now
	}
	wait := s.wait
	if wait == nil {
		wait = waitContext
	}
	var stableSince time.Time
	for {
		current := now()
		if status.GetState() == want {
			if stableSince.IsZero() {
				stableSince = current
			}
			if current.Sub(stableSince) >= window {
				return status, nil
			}
		} else {
			stableSince = time.Time{}
		}
		if err := wait(ctx, poll); err != nil {
			return status, err
		}
		var err error
		status, err = s.systemd().Status(ctx)
		if err != nil {
			return status, err
		}
	}
}

func waitContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (s Server) probe(ctx context.Context) error {
	if err := secureManagedParent(filepath.Dir(s.Config.ConfigPath)); err != nil {
		return err
	}
	if err := secureManagedParent(filepath.Dir(s.Config.BinaryPath)); err != nil {
		return err
	}
	identity, err := systemdIdentity(ctx, s.Config.ServiceName)
	if err != nil {
		return err
	}
	file, info, err := openFixed(s.Config.ConfigPath)
	if err != nil {
		return err
	}
	defer file.Close()
	stat := info.Sys().(*syscall.Stat_t)
	if stat.Uid != identity.uid || info.Mode().Perm()&0022 != 0 || hasACL(int(file.Fd())) {
		return errors.New("managed config preflight failed")
	}
	binary, err := os.Lstat(s.Config.BinaryPath)
	if err != nil || !binary.Mode().IsRegular() || binary.Mode()&os.ModeSymlink != 0 || binary.Mode().Perm()&0022 != 0 {
		return errors.New("binary preflight failed")
	}
	binaryStat := binary.Sys().(*syscall.Stat_t)
	if binaryStat.Uid != 0 || binaryStat.Gid != 0 {
		return errors.New("binary must be root-owned")
	}
	if err := os.MkdirAll(s.Config.StateDir, 0700); err != nil {
		return err
	}
	if err := s.recoverPermission(); err != nil {
		return err
	}
	if err := (restrictedVerifier{uid: identity.uid, gid: identity.gid}).Verify(ctx, s.Config.BinaryPath, s.Config.ConfigPath); err != nil {
		return err
	}
	_, err = exec.CommandContext(ctx, "systemctl", "show", s.Config.ServiceName, "--property=LoadState", "--no-pager").Output()
	return err
}

func secureManagedParent(path string) error {
	for {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("managed parent directory is unsafe")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("managed parent directory must be root-owned")
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

func (s Server) apply(ctx context.Context, request Request) Response {
	if s.Config.Role != "server" || filepath.Ext(s.Config.ConfigPath) != ".toml" || request.CandidateStrategy != "restart" ||
		request.CandidateRevision == "" || len(request.CandidateRevision) > 128 || len(request.CandidateContent) == 0 || len(request.CandidateContent) > 16<<20 {
		return failure(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "candidate is invalid")
	}
	current, err := os.ReadFile(s.Config.ConfigPath)
	if err != nil || !strings.EqualFold(hash(current), request.ExpectedCurrentSHA) {
		return failure(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "current config changed")
	}
	if !exactLoopbackChange(current, request.CandidateContent) {
		return failure(agentv1.ErrorCode_ERROR_CODE_INVALID_COMMAND, "candidate changes non-allowlisted fields")
	}
	lifecycle := service.NewSystemd(s.Config.ServiceName, s.Config.BinaryPath, s.Config.ConfigPath, s.Config.Role)
	identity, ownerErr := systemdIdentity(ctx, s.Config.ServiceName)
	if ownerErr != nil {
		return failure(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "managed owner is unavailable")
	}
	manager, err := configmgr.New(configmgr.Options{Role: s.Config.Role, BinaryPath: s.Config.BinaryPath, ConfigPath: s.Config.ConfigPath,
		StateDir: s.Config.StateDir, Verifier: restrictedVerifier{uid: identity.uid, gid: identity.gid}, Lifecycle: lifecycle, ConfigOwnerUID: &identity.uid})
	if err != nil {
		return failure(agentv1.ErrorCode_ERROR_CODE_INTERNAL, "helper initialization failed")
	}
	if err := manager.Recover(ctx); err != nil {
		return failure(agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED, "config recovery failed")
	}
	err = manager.ApplyCAS(ctx, request.CandidateRevision, request.CandidateSHA, request.CandidateContent, request.CandidateStrategy, request.ExpectedCurrentSHA)
	if err == nil {
		return Response{BackupCreated: true, BackupID: "config-" + request.ExpectedCurrentSHA[:12], Changed: true}
	}
	var typed *configmgr.Error
	if errors.As(err, &typed) {
		return configErrorResponse(typed)
	}
	return failure(agentv1.ErrorCode_ERROR_CODE_INTERNAL, "config helper operation failed")
}

func configErrorResponse(typed *configmgr.Error) Response {
	return Response{ErrorCode: typed.Code, Diagnostic: "config helper operation failed", BackupCreated: typed.BackupCreated,
		Changed: typed.Changed, RollbackAttempted: typed.RollbackAttempted, RollbackSucceeded: typed.RollbackSucceeded}
}

func (s Server) restrict(ctx context.Context, request Request) Response {
	if err := s.recoverPermission(); err != nil {
		return failure(agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED, "permission recovery failed")
	}
	file, info, err := openFixed(s.Config.ConfigPath)
	if err != nil {
		return failure(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, "config path is unsafe")
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil || !strings.EqualFold(hash(data), request.ExpectedCurrentSHA) {
		return failure(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "current config changed")
	}
	if hasACL(int(file.Fd())) {
		return failure(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "extended ACL requires manual review")
	}
	identity, identityErr := systemdIdentity(ctx, s.Config.ServiceName)
	if identityErr != nil || info.Sys().(*syscall.Stat_t).Uid != identity.uid {
		return failure(agentv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED, "service user cannot read mode 0600")
	}
	original := info.Mode().Perm()
	if original == 0600 {
		return Response{}
	}
	stat := info.Sys().(*syscall.Stat_t)
	marker := filepath.Join(s.Config.StateDir, "permission-mode.json")
	if err := os.MkdirAll(s.Config.StateDir, 0700); err != nil {
		return failure(agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED, "permission transaction failed")
	}
	if err := writeMarker(marker, permissionMarker{Device: uint64(stat.Dev), Inode: uint64(stat.Ino), Mode: uint32(original)}); err != nil {
		return failure(agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED, "permission transaction failed")
	}
	result := Response{BackupCreated: true, BackupID: "mode-" + request.ExpectedCurrentSHA[:12]}
	if !samePath(s.Config.ConfigPath, info) {
		return failure(agentv1.ErrorCode_ERROR_CODE_UNSAFE_PATH, "config inode changed")
	}
	if err := file.Chmod(0600); err != nil {
		return failure(agentv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED, "chmod failed")
	}
	result.Changed = true
	if err := file.Sync(); err == nil {
		if !samePath(s.Config.ConfigPath, info) {
			err = errors.New("config inode changed")
		} else {
			err = (restrictedVerifier{uid: identity.uid, gid: identity.gid}).Verify(ctx, s.Config.BinaryPath, s.Config.ConfigPath)
		}
	}
	if err == nil && !samePath(s.Config.ConfigPath, info) {
		err = errors.New("config inode changed")
	}
	if err == nil {
		err = removeDurable(marker)
	}
	if err == nil {
		return result
	}
	result.RollbackAttempted = true
	if restoreErr := file.Chmod(original); restoreErr == nil {
		_ = file.Sync()
		_ = removeDurable(marker)
		result.RollbackSucceeded = true
		result.ErrorCode = agentv1.ErrorCode_ERROR_CODE_VERIFY_FAILED
		result.Diagnostic = "permission verification failed"
		return result
	}
	result.ErrorCode = agentv1.ErrorCode_ERROR_CODE_RECOVERY_FAILED
	result.Diagnostic = "permission rollback failed"
	return result
}

func (s Server) recoverPermission() error {
	markerPath := filepath.Join(s.Config.StateDir, "permission-mode.json")
	data, err := os.ReadFile(markerPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var marker permissionMarker
	if json.Unmarshal(data, &marker) != nil {
		return errors.New("invalid permission marker")
	}
	file, info, err := openFixed(s.Config.ConfigPath)
	if err != nil {
		return err
	}
	defer file.Close()
	stat := info.Sys().(*syscall.Stat_t)
	if uint64(stat.Dev) != marker.Device || uint64(stat.Ino) != marker.Inode {
		return errors.New("permission recovery inode changed")
	}
	if err := file.Chmod(os.FileMode(marker.Mode)); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	return removeDurable(markerPath)
}

func writeMarker(path string, value permissionMarker) error {
	data, _ := json.Marshal(value)
	tmp, err := os.CreateTemp(filepath.Dir(path), ".permission-*")
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
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func removeDurable(path string) error {
	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func openFixed(path string) (*os.File, os.FileInfo, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("unsafe file")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(pathInfo, info) {
		file.Close()
		return nil, nil, errors.New("unsafe file")
	}
	return file, info, nil
}

func samePath(path string, opened os.FileInfo) bool {
	current, err := os.Lstat(path)
	return err == nil && current.Mode()&os.ModeSymlink == 0 && current.Mode().IsRegular() && os.SameFile(current, opened)
}

func hasACL(fd int) bool {
	size, err := unix.Flistxattr(fd, nil)
	if err != nil {
		return true
	}
	buf := make([]byte, size)
	n, err := unix.Flistxattr(fd, buf)
	return err != nil || strings.Contains(string(buf[:n]), "posix_acl")
}

type effectiveIdentity struct{ uid, gid uint32 }

func systemdIdentity(ctx context.Context, serviceName string) (effectiveIdentity, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "show", serviceName, "--property=User,Group,DynamicUser", "--no-pager").Output()
	if err != nil || strings.Contains(string(out), "DynamicUser=yes") {
		return effectiveIdentity{}, errors.New("systemd identity unavailable")
	}
	userName, groupName := "", ""
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "User=") {
			userName = strings.TrimPrefix(line, "User=")
		}
		if strings.HasPrefix(line, "Group=") {
			groupName = strings.TrimPrefix(line, "Group=")
		}
	}
	if userName == "" {
		userName = "root"
	}
	account, err := user.Lookup(userName)
	if err != nil {
		return effectiveIdentity{}, err
	}
	uidValue, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		return effectiveIdentity{}, err
	}
	gidText := account.Gid
	if groupName != "" {
		group, lookupErr := user.LookupGroup(groupName)
		if lookupErr != nil {
			return effectiveIdentity{}, lookupErr
		}
		gidText = group.Gid
	}
	gidValue, err := strconv.ParseUint(gidText, 10, 32)
	return effectiveIdentity{uid: uint32(uidValue), gid: uint32(gidValue)}, err
}

func exactLoopbackChange(current, candidate []byte) bool {
	var oldValue, newValue map[string]any
	if toml.Unmarshal(current, &oldValue) != nil || toml.Unmarshal(candidate, &newValue) != nil {
		return false
	}
	oldWeb, ok1 := oldValue["webServer"].(map[string]any)
	newWeb, ok2 := newValue["webServer"].(map[string]any)
	if !ok1 || !ok2 || newWeb["addr"] != "127.0.0.1" {
		return false
	}
	oldWeb["addr"] = "127.0.0.1"
	return reflect.DeepEqual(oldValue, newValue)
}

func hash(data []byte) string { value := sha256.Sum256(data); return hex.EncodeToString(value[:]) }

type restrictedVerifier struct{ uid, gid uint32 }

func (v restrictedVerifier) Verify(ctx context.Context, binaryPath, configPath string) error {
	command := exec.CommandContext(ctx, binaryPath, "verify", "-c", configPath)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: v.uid, Gid: v.gid, NoSetGroups: true}}
	if err := command.Run(); err != nil {
		return errors.New("frp verification failed")
	}
	return nil
}
func failure(code agentv1.ErrorCode, diagnostic string) Response {
	return Response{ErrorCode: code, Diagnostic: diagnostic}
}
