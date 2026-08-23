package securitycheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

const maxLogBytes int64 = 1 << 20
const maxConfigBytes int64 = 16 << 20

type Collector interface {
	Collect(context.Context) Result
}

type failover struct{ primary, secondary Collector }

func NewFailover(primary, secondary Collector) Collector {
	return &failover{primary: primary, secondary: secondary}
}

func (f *failover) Collect(ctx context.Context) Result {
	result := f.primary.Collect(ctx)
	if len(result.CompletedKinds) > 0 || result.Complete {
		return result
	}
	return f.secondary.Collect(ctx)
}

type Result struct {
	Findings       []*agentv1.DeploymentRisk
	CompletedKinds []agentv1.DeploymentRiskKind
	Complete       bool
	ErrorCode      string
}

type Local struct {
	role, configPath, serviceName string
	readConfig                    func(string) ([]byte, os.FileMode, error)
	readLog                       func(context.Context, string, string) ([]byte, error)
}

type parsedConfig struct {
	adminAddress string
	adminEnabled bool
	token        bool
	logPath      string
}

func New(role, configPath, serviceName string) *Local {
	return &Local{role: role, configPath: configPath, serviceName: serviceName, readConfig: readConfig, readLog: readRecentLogs}
}

func (l *Local) Collect(ctx context.Context) Result {
	data, mode, err := l.readConfig(l.configPath)
	if err != nil {
		return Result{ErrorCode: "CONFIG_READ_FAILED"}
	}
	config, err := parseConfig(l.configPath, data)
	if err != nil {
		return Result{ErrorCode: "CONFIG_PARSE_FAILED"}
	}
	var risks []*agentv1.DeploymentRisk
	completed := []agentv1.DeploymentRiskKind{agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_CONFIG_TOKEN_PERMISSIONS}
	if l.role == "server" {
		completed = append(completed, agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_ADMIN_API_NON_LOOPBACK)
	}
	if l.role == "server" && config.adminEnabled && !isLoopback(config.adminAddress) {
		kind := agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_ADMIN_API_NON_LOOPBACK
		risks = append(risks, risk(kind, "web_server_addr=non_loopback", resourceFingerprint(kind, data, mode)))
	}
	if config.token && mode.Perm()&0077 != 0 {
		kind := agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_CONFIG_TOKEN_PERMISSIONS
		risks = append(risks, risk(kind, fmt.Sprintf("config_mode=%04o", mode.Perm()), resourceFingerprint(kind, data, mode)))
	}
	logs, err := l.readLog(ctx, l.serviceName, config.logPath)
	if err != nil {
		return Result{Findings: risks, CompletedKinds: completed, ErrorCode: "LOG_READ_FAILED"}
	}
	completed = append(completed, agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_PROXY_NAME_CONFLICT)
	if hasProxyNameConflict(logs) {
		kind := agentv1.DeploymentRiskKind_DEPLOYMENT_RISK_KIND_PROXY_NAME_CONFLICT
		risks = append(risks, risk(kind, "recent_logs=proxy_name_conflict", resourceFingerprint(kind, data, mode)))
	}
	return Result{Findings: risks, CompletedKinds: completed, Complete: true}
}

func risk(kind agentv1.DeploymentRiskKind, evidence, fingerprint string) *agentv1.DeploymentRisk {
	return &agentv1.DeploymentRisk{Kind: kind, Evidence: evidence, Confidence: "high", RuleVersion: "1", ResourceFingerprint: fingerprint}
}

func resourceFingerprint(kind agentv1.DeploymentRiskKind, data []byte, mode os.FileMode) string {
	content := sha256.Sum256(data)
	value := fmt.Sprintf("%d\x00%s\x00%04o", kind, hex.EncodeToString(content[:]), mode.Perm())
	result := sha256.Sum256([]byte(value))
	return hex.EncodeToString(result[:])
}

func readConfig(path string) ([]byte, os.FileMode, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, 0, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, errors.New("frp config is not a regular file")
	}
	if info.Size() > maxConfigBytes {
		return nil, 0, errors.New("frp config exceeds inspection limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxConfigBytes+1))
	if int64(len(data)) > maxConfigBytes {
		return nil, 0, errors.New("frp config exceeds inspection limit")
	}
	return data, info.Mode(), err
}

func parseConfig(path string, data []byte) (parsedConfig, error) {
	if strings.EqualFold(filepath.Ext(path), ".ini") {
		return parseINI(data), nil
	}
	var raw map[string]any
	var err error
	if strings.EqualFold(filepath.Ext(path), ".toml") {
		err = toml.Unmarshal(data, &raw)
	} else {
		err = yaml.Unmarshal(data, &raw)
	}
	if err != nil {
		return parsedConfig{}, err
	}
	return parsedConfig{
		adminAddress: nestedString(raw, "webServer", "addr"),
		adminEnabled: nestedInt(raw, "webServer", "port") > 0,
		token:        nestedString(raw, "auth", "token") != "",
		logPath:      nestedString(raw, "log", "to"),
	}, nil
}

func nestedString(value map[string]any, keys ...string) string {
	var current any = value
	for _, key := range keys {
		object, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = object[key]
		if !ok {
			return ""
		}
	}
	result, _ := current.(string)
	return strings.TrimSpace(result)
}

func nestedInt(value map[string]any, keys ...string) int64 {
	var current any = value
	for _, key := range keys {
		object, ok := current.(map[string]any)
		if !ok {
			return 0
		}
		current, ok = object[key]
		if !ok {
			return 0
		}
	}
	switch result := current.(type) {
	case int:
		return int64(result)
	case int64:
		return result
	case uint64:
		if result <= uint64(^uint64(0)>>1) {
			return int64(result)
		}
	}
	return 0
}

func parseINI(data []byte) parsedConfig {
	var result parsedConfig
	section := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.Trim(strings.TrimSpace(value), "\"'")
		switch {
		case section == "common" && key == "dashboard_addr":
			result.adminAddress = value
		case section == "common" && key == "dashboard_port":
			result.adminEnabled = value != "" && value != "0"
		case section == "common" && (key == "token" || key == "auth_token"):
			result.token = value != ""
		case section == "common" && key == "log_file":
			result.logPath = value
		}
	}
	return result
}

func isLoopback(value string) bool {
	host := strings.TrimSpace(value)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func readRecentLogs(ctx context.Context, serviceName, logPath string) ([]byte, error) {
	var result []byte
	readable := false
	if logPath != "" && logPath != "console" && filepath.IsAbs(logPath) {
		var err error
		if result, err = tailFile(logPath, maxLogBytes); err == nil {
			readable = true
		}
	}
	journal := &tailWriter{limit: int(maxLogBytes)}
	command := exec.CommandContext(ctx, "journalctl", "--no-pager", "-u", serviceName, "-n", "2000", "-o", "cat")
	command.Stdout = journal
	if err := command.Run(); err == nil {
		readable = true
		result = append(result, journal.data...)
	}
	if !readable {
		return nil, errors.New("no readable frp log source")
	}
	if int64(len(result)) > maxLogBytes {
		result = result[len(result)-int(maxLogBytes):]
	}
	return result, nil
}

type tailWriter struct {
	data  []byte
	limit int
}

func (w *tailWriter) Write(p []byte) (int, error) {
	written := len(p)
	if len(p) >= w.limit {
		w.data = append(w.data[:0], p[len(p)-w.limit:]...)
		return written, nil
	}
	overflow := len(w.data) + len(p) - w.limit
	if overflow > 0 {
		copy(w.data, w.data[overflow:])
		w.data = w.data[:len(w.data)-overflow]
	}
	w.data = append(w.data, p...)
	return written, nil
}

func tailFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, err
	}
	start := max(int64(0), info.Size()-limit)
	if _, err = file.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	return io.ReadAll(io.LimitReader(file, limit))
}

func hasProxyNameConflict(log []byte) bool {
	for _, raw := range bytes.Split(bytes.ToLower(log), []byte{'\n'}) {
		line := string(raw)
		if !strings.Contains(line, "proxy") {
			continue
		}
		if strings.Contains(line, "duplicate") || strings.Contains(line, "already exist") || strings.Contains(line, "already in use") {
			return true
		}
	}
	return false
}
